package verify

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/dario-mr/open-trust/internal/adapters"
	"github.com/dario-mr/open-trust/internal/policy"
	"github.com/dario-mr/open-trust/internal/statement"
	"github.com/dario-mr/open-trust/internal/subject"
)

// fakeScan makes the buyer's re-check "find" the SBOM of one fixture and the vulnerabilities of another.
func fakeScan(t *testing.T, sbomFixture, vulnsFixture string) {
	t.Helper()
	load := func(fx string) policy.EvidenceIn {
		raw, err := os.ReadFile(filepath.Join(fixtures, fx, "input.json"))
		if err != nil {
			t.Fatal(err)
		}
		var in policy.Input
		json.Unmarshal(raw, &in)
		return in.Evidence
	}
	ev := &adapters.Evidence{SBOM: load(sbomFixture).SBOM, Vulns: load(vulnsFixture).Vulns,
		TrivyDB: json.RawMessage(`{"VulnerabilityDB":{"UpdatedAt":"2026-11-20T06:00:00Z"}}`)}
	orig := scanImage
	scanImage = func(context.Context, string, *subject.Subject, bool) (*adapters.Evidence, error) { return ev, nil }
	t.Cleanup(func() { scanImage = orig })
}

func vendorDB(at string) func(map[string]any, *statement.Extension) {
	return func(_ map[string]any, ext *statement.Extension) {
		ext.Tools = map[string]any{"trivy": map[string]any{"db": map[string]any{"VulnerabilityDB": map[string]any{"UpdatedAt": at}}}}
	}
}

func TestRecheckAgrees(t *testing.T) {
	fakeScan(t, "clean", "clean")
	c := newCert(t, "clean", vendorDB("2026-11-16T06:00:00Z"))
	c.opts.Recheck = true
	r := run(t, c.opts)
	expect(t, r, OK, "")
	if rc := r.Recheck; rc == nil || rc.Result != "PASSED" || !rc.PackagesCompared || rc.VendorDB != "2026-11-16T06:00:00Z" {
		t.Fatalf("recheck = %+v", r.Recheck)
	}
}

// The vendor signed PASSED, but the image carries Log4Shell, public since 2021: the vendor's scan must have seen it.
func TestRecheckCatchesUnreportedVulnerability(t *testing.T) {
	fakeScan(t, "clean", "vulnerable")
	c := newCert(t, "clean", vendorDB("2026-11-16T06:00:00Z"))
	c.opts.Recheck = true
	r := run(t, c.opts)
	expect(t, r, RecheckMismatch, "public long before the vendor's scan")
	if !slices.ContainsFunc(r.Recheck.Unreported, func(s string) bool { return strings.Contains(s, "CVE-2021-44228") }) {
		t.Fatalf("Log4Shell not reported as unreported: %v", r.Recheck.Unreported)
	}
}

// Same image, but the vendor scanned before Log4Shell was published: honest, just stale.
func TestRecheckOutdated(t *testing.T) {
	fakeScan(t, "clean", "vulnerable")
	c := newCert(t, "clean", vendorDB("2021-12-01T00:00:00Z"))
	c.opts.Recheck = true
	r := run(t, c.opts)
	expect(t, r, Outdated, "today's vulnerability data")
	if len(r.Recheck.Unreported) != 0 || !slices.ContainsFunc(r.Recheck.New, func(s string) bool { return strings.Contains(s, "CVE-2021-44228") }) {
		t.Fatalf("recheck = %+v", r.Recheck)
	}
}

// The vendor's (digest-checked) SBOM leaves out packages that are in the image.
func TestRecheckPackageMismatch(t *testing.T) {
	fakeScan(t, "vulnerable", "clean")
	c := newCert(t, "clean", vendorDB("2026-11-16T06:00:00Z"))
	c.opts.Recheck = true
	r := run(t, c.opts)
	expect(t, r, RecheckMismatch, "packages the vendor's SBOM leaves out")
	if !slices.ContainsFunc(r.Recheck.PackagesMissing, func(s string) bool { return strings.Contains(s, "log4j-core@2.14.1") }) {
		t.Fatalf("missing = %v", r.Recheck.PackagesMissing)
	}
}

func TestRecheckWithoutEvidenceSkipsPackages(t *testing.T) {
	fakeScan(t, "vulnerable", "clean")
	c := newCert(t, "clean", vendorDB("2026-11-16T06:00:00Z"))
	c.opts.Recheck, c.opts.Evidence = true, ""
	r := run(t, c.opts)
	expect(t, r, OK, "")
	if r.Recheck.PackagesCompared || !slices.ContainsFunc(r.Notes, func(s string) bool { return strings.Contains(s, "packages not compared") }) {
		t.Fatalf("recheck = %+v, notes = %v", r.Recheck, r.Notes)
	}
}
