package verify

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/dario-mr/open-trust/internal/adapters"
	"github.com/dario-mr/open-trust/internal/policy"
	"github.com/dario-mr/open-trust/internal/subject"
	scb "github.com/dario-mr/open-trust/profiles/supply-chain-baseline/v1"
)

// Recheck is the buyer's own re-run of the image-based checks (SBOM, vulnerabilities) on the image
// they received, with the profile's pinned scanners and today's vulnerability database. It needs no
// trust in the vendor's pipeline, on any CI.
type Recheck struct {
	Result   string   // today's result over the sbom and vulns checks
	Findings []string // today's sbom and vulns findings (vendor exceptions still applied while valid)
	DB       string   // buyer's trivy DB update time
	VendorDB string   // vendor's trivy DB update time, from the certificate

	// Failing today and absent from the certificate, split by when the vulnerability was published.
	Unreported []string // published well before the vendor's scan: the vendor's scan should have seen it
	New        []string // published after (or just before) the vendor's scan: the certificate went stale

	PackagesCompared bool     // only with --evidence: the vendor's SBOM is then authenticated
	PackagesMissing  []string // in the image, not in the vendor's SBOM
	PackagesExtra    []string // in the vendor's SBOM, not in the image
}

// shortcut: a CVE published less than this before the vendor's DB update counts as new, because
// severities are often re-rated in the first weeks; tune once we have real-world false positives.
const reratingGrace = 30 * 24 * time.Hour

// scanImage runs the pinned image scanners; tests replace it to stay hermetic.
var scanImage = func(ctx context.Context, layout string, s *subject.Subject, local bool) (*adapters.Evidence, error) {
	tools, err := scb.LoadTools()
	if err != nil {
		return nil, err
	}
	var l *adapters.Local
	if local { // the re-check needs no source, so no Semgrep: every tool is pinned by digest
		if l, err = adapters.PrepareLocal(ctx, tools, false); err != nil {
			return nil, err
		}
	}
	work, err := dockerVisibleTemp("", "otrust-recheck-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(work)
	abs, err := filepath.Abs(layout)
	if err != nil {
		return nil, err
	}
	r := &adapters.Runner{Tools: tools, SourceDir: work, WorkDir: work, Subject: abs, CacheVol: "otrust-cache", Local: l}
	return r.ScanImage(ctx, s.SyftSource())
}

// dockerVisibleTemp makes a temp dir under the user cache dir: Docker Desktop and Colima share the
// home directory with the daemon, but not always the system temp dir.
func dockerVisibleTemp(_, pattern string) (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return os.MkdirTemp("", pattern)
	}
	base = filepath.Join(base, "otrust")
	if err := os.MkdirAll(base, 0o755); err != nil {
		return "", err
	}
	return os.MkdirTemp(base, pattern)
}

// compareRecheck evaluates the fresh evidence under the certificate's own exceptions and compares it
// with what the certificate claims. vendorSBOM is nil unless the vendor's evidence was verified.
func compareRecheck(ctx context.Context, p *Predicate, subjectDigest string, fresh *adapters.Evidence, vendorSBOM []byte, now time.Time) (*Recheck, error) {
	in := &policy.Input{
		Now:        now.UTC().Format(time.RFC3339),
		Subject:    policy.SubjectIn{Digest: subjectDigest, AssessedDigest: subjectDigest},
		Evidence:   policy.EvidenceIn{SBOM: fresh.SBOM, Vulns: fresh.Vulns},
		Exceptions: p.Ext.Exceptions,
	}
	if in.Exceptions == nil {
		in.Exceptions = []policy.Exception{}
	}
	dec, err := policy.Evaluate(ctx, in)
	if err != nil {
		return nil, err
	}
	rc := &Recheck{Result: "PASSED", Findings: []string{}, DB: trivyDBTime(fresh.TrivyDB), VendorDB: vendorDBTime(p)}
	rank := map[string]int{"PASSED": 0, "WARN": 1, "FAILED": 2}
	for _, c := range dec.Checks {
		if c.ID != "sbom" && c.ID != "vulns" {
			continue
		}
		if rank[c.Result] > rank[rc.Result] {
			rc.Result = c.Result
		}
		for _, f := range c.Findings {
			rc.Findings = append(rc.Findings, c.ID+": "+f)
		}
	}

	cutoff, err := time.Parse(time.RFC3339, rc.VendorDB)
	if err != nil {
		cutoff, _ = time.Parse(time.RFC3339, p.TimeVerified)
	}
	published := publishedDates(fresh.Vulns)
	var claimed []string
	for _, c := range p.Ext.Checks {
		if c.ID == "vulns" {
			claimed = c.Findings
		}
	}
	for _, u := range dec.UnmetRequirements {
		msg, ok := strings.CutPrefix(u, "vulns: ")
		if !ok {
			continue
		}
		id, pkg := vulnKey(msg)
		if id == "" || slices.ContainsFunc(claimed, func(f string) bool { a, b := vulnKey(f); return a == id && b == pkg }) {
			continue // known to the certificate (possibly at a lower severity then): not new
		}
		if pub, ok := published[id]; ok && !cutoff.IsZero() && pub.Before(cutoff.Add(-reratingGrace)) {
			rc.Unreported = append(rc.Unreported, msg+", published "+pub.Format("2006-01-02"))
		} else {
			rc.New = append(rc.New, msg)
		}
	}

	if vendorSBOM != nil {
		rc.PackagesCompared = true
		have, want := packages(fresh.SBOM), packages(vendorSBOM)
		for k := range have {
			if !want[k] {
				rc.PackagesMissing = append(rc.PackagesMissing, k)
			}
		}
		for k := range want {
			if !have[k] {
				rc.PackagesExtra = append(rc.PackagesExtra, k)
			}
		}
		slices.Sort(rc.PackagesMissing)
		slices.Sort(rc.PackagesExtra)
	}
	return rc, nil
}

// mismatch says why the certificate disagrees with the buyer's re-check, or "" if it doesn't.
func (rc *Recheck) mismatch() string {
	var why []string
	if n := len(rc.Unreported); n > 0 {
		why = append(why, fmt.Sprintf("%d failing vulnerabilities were public long before the vendor's scan but are not in the certificate", n))
	}
	if n := len(rc.PackagesMissing); n > 0 {
		why = append(why, fmt.Sprintf("the image has %d packages the vendor's SBOM leaves out", n))
	}
	if n := len(rc.PackagesExtra); n > 0 {
		why = append(why, fmt.Sprintf("the vendor's SBOM lists %d packages the image does not contain", n))
	}
	return strings.Join(why, "; ")
}

// vulnKey reads the vulnerability ID and package@version from a policy finding message,
// "<SEVERITY> <ID> in <pkg>@<version> (fixed in: …)" (policy.rego, findings.vulns).
func vulnKey(msg string) (id, pkg string) {
	f := strings.Fields(msg)
	if len(f) < 4 || f[2] != "in" {
		return "", ""
	}
	return f[1], f[3]
}

func publishedDates(vulns []byte) map[string]time.Time {
	var doc struct {
		Results []struct {
			Vulnerabilities []struct {
				VulnerabilityID string
				PublishedDate   string
			}
		}
	}
	_ = json.Unmarshal(vulns, &doc)
	m := map[string]time.Time{}
	for _, r := range doc.Results {
		for _, v := range r.Vulnerabilities {
			if t, err := time.Parse(time.RFC3339, v.PublishedDate); err == nil {
				m[v.VulnerabilityID] = t
			}
		}
	}
	return m
}

// packages keys an SBOM's components by purl, or name@version when there is none.
func packages(sbom []byte) map[string]bool {
	var doc struct {
		Components []struct {
			Name, Version, Purl string
		}
	}
	_ = json.Unmarshal(sbom, &doc)
	m := map[string]bool{}
	for _, c := range doc.Components {
		k := c.Purl
		if k == "" {
			k = c.Name + "@" + c.Version
		}
		m[k] = true
	}
	return m
}

func trivyDBTime(versionJSON []byte) string {
	var v struct{ VulnerabilityDB struct{ UpdatedAt string } }
	_ = json.Unmarshal(versionJSON, &v)
	return v.VulnerabilityDB.UpdatedAt
}

func vendorDBTime(p *Predicate) string {
	trivy, _ := p.Ext.Tools["trivy"].(map[string]any)
	raw, _ := json.Marshal(trivy["db"])
	return trivyDBTime(raw)
}

// MismatchFree is true when the image agrees with the certificate (it may still fail today).
func (rc *Recheck) MismatchFree() bool { return rc.mismatch() == "" }
