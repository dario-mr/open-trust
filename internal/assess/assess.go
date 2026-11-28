// Package assess orchestrates one assessment: subject → scanners → policy → statement + evidence.
// It knows nothing about the CLI or the CI provider beyond ci.Env.
package assess

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"

	"github.com/dario-mr/open-trust/internal/adapters"
	"github.com/dario-mr/open-trust/internal/ci"
	"github.com/dario-mr/open-trust/internal/policy"
	"github.com/dario-mr/open-trust/internal/provenance"
	"github.com/dario-mr/open-trust/internal/signer"
	"github.com/dario-mr/open-trust/internal/statement"
	"github.com/dario-mr/open-trust/internal/subject"
	"github.com/dario-mr/open-trust/profiles"
	scb "github.com/dario-mr/open-trust/profiles/supply-chain-baseline/v1"
)

const Version = "0.1.18"

type Options struct {
	Image      string // OCI layout dir or tar
	Name       string // subject name, e.g. registry.example.com/acme/svc
	SourceDir  string
	OutDir     string
	Repo       string
	Revision   string
	Exceptions string        // path; default <source>/.otrust/exceptions.yaml
	Signer     signer.Signer // nil: unsigned statement only (local testing)
	// Provenance is a signed SLSA provenance bundle (e.g. GitHub attest-build-provenance); without it,
	// unsigned BuildKit provenance attached to the image is used if present.
	Provenance  string
	TrustedRoot string // Sigstore trusted_root.json for checking Provenance; default: fetch via TUF
	// Attach pushes the signed certificate to the image's registry as an OCI referrer, so buyers
	// verify by image reference alone. Needs Image to be a registry reference and push access.
	Attach bool
	// LocalScanners runs the scanners without docker: Syft and Trivy from their pinned release
	// archives, Semgrep from PATH at the pinned version (adapters.Local).
	LocalScanners bool
}

// Result is one assessment: one scan, one certificate per profile (profiles.All, in that order).
type Result struct {
	Certificates []*Certificate
	Subject      *subject.Subject
	CI           ci.Env
	OutDir       string
}

type Certificate struct {
	Profile   *profiles.Profile
	Statement *statement.Statement
	Decision  *policy.Decision
	Signed    bool
	Attached  string // the certificate's referrer digest in the registry, when attached
}

// Of returns the certificate of one profile.
func (r *Result) Of(p *profiles.Profile) *Certificate {
	for _, c := range r.Certificates {
		if c.Profile == p {
			return c
		}
	}
	return nil
}

func Run(ctx context.Context, o Options) (*Result, error) {
	src, err := filepath.Abs(o.SourceDir)
	if err != nil {
		return nil, err
	}
	out, err := filepath.Abs(o.OutDir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return nil, err
	}
	if o.Attach && (o.Signer == nil || !subject.IsRef(o.Image)) {
		return nil, fmt.Errorf("--attach needs a registry image (name@sha256:…) and a signer")
	}
	name := o.Name
	img := o.Image
	if subject.IsRef(o.Image) {
		// pulled into the out dir (the scanners' containers must see it) and removed afterwards
		img = filepath.Join(out, ".otrust-image")
		os.RemoveAll(img)
		defer os.RemoveAll(img)
		if err := subject.Pull(ctx, o.Image, img); err != nil {
			return nil, fmt.Errorf("subject: %w", err)
		}
		if name == "" {
			name = strings.SplitN(o.Image, "@", 2)[0]
		}
	} else if img, err = filepath.Abs(o.Image); err != nil {
		return nil, err
	}

	subj, err := subject.Resolve(img)
	if err != nil {
		return nil, fmt.Errorf("subject: %w", err)
	}
	env, err := ci.Detect(ctx, src, o.Repo, o.Revision)
	if err != nil {
		return nil, err
	}
	excPath := o.Exceptions
	if excPath == "" {
		excPath = filepath.Join(src, ".otrust", "exceptions.yaml")
	}
	exceptions, err := policy.LoadExceptions(excPath)
	if err != nil {
		return nil, err
	}

	tools, err := scb.LoadTools()
	if err != nil {
		return nil, err
	}
	r := &adapters.Runner{Tools: tools, SourceDir: src, WorkDir: out, Subject: img, CacheVol: "otrust-cache"}
	if o.LocalScanners {
		if r.Local, err = adapters.PrepareLocal(ctx, tools, true); err != nil {
			return nil, fmt.Errorf("scanners: %w", err)
		}
	}
	// the evidence dir and the image are not source, even when they sit inside the source tree
	for _, p := range []string{out, img} {
		if rel, err := filepath.Rel(src, p); err == nil && rel != "." && !strings.HasPrefix(rel, "..") {
			r.Exclude = append(r.Exclude, rel)
		}
	}
	ev, err := r.Run(ctx, subj.SyftSource())
	if err != nil {
		return nil, fmt.Errorf("scanners: %w", err)
	}

	// Evidence stays local; only its digests go into the statement.
	files := map[string][]byte{
		"sbom.cdx.json": ev.SBOM, "vulns.json": ev.Vulns, "secrets.json": ev.Secrets,
		"sast.json": ev.SAST, "trivy-db.json": ev.TrivyDB,
	}
	prov, provBytes, err := checkProvenance(o, subj, env)
	if err != nil {
		return nil, err
	}
	if provBytes != nil {
		files["provenance.json"] = provBytes
	}
	digests := map[string]string{}
	for name, b := range files {
		if err := os.WriteFile(filepath.Join(out, name), b, 0o644); err != nil {
			return nil, err
		}
		digests[name] = sha256hex(b)
	}

	now := time.Now().UTC().Truncate(time.Second)
	pctx := policy.Context{
		Now:          now.Format(time.RFC3339),
		Subject:      policy.SubjectIn{Digest: subj.Digest, AssessedDigest: subj.Digest},
		Provenance:   prov,
		Exceptions:   exceptions,
		SASTCoverage: adapters.SASTCoverage(ev.SAST, ev.SemgrepRuleset.Languages),
	}
	ctxJSON, err := json.MarshalIndent(pctx, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(out, statement.ContextFile), ctxJSON, 0o644); err != nil {
		return nil, err
	}
	trust := "unsigned"
	if o.Signer != nil {
		// keyless: fetch the short-lived token and certificate only now, after the scans
		if p, ok := o.Signer.(interface{ Prepare(context.Context) error }); ok {
			if err := p.Prepare(ctx); err != nil {
				return nil, fmt.Errorf("signer: %w", err)
			}
		}
		trust = o.Signer.TrustLevel()
	}
	agent, err := selfDigest()
	if err != nil {
		return nil, err
	}
	var trivyDB any
	_ = json.Unmarshal(ev.TrivyDB, &trivyDB)
	res := &Result{Subject: subj, CI: env, OutDir: out}
	in := pctx.Input(policy.EvidenceIn{SBOM: ev.SBOM, Vulns: ev.Vulns, Secrets: ev.Secrets, SAST: ev.SAST})
	for _, prof := range profiles.All {
		dec, err := policy.Evaluate(ctx, prof, in)
		if err != nil {
			return nil, err
		}
		st := statement.Build(statement.Params{
			SubjectName:    nameOr(name, img),
			SubjectDigest:  subj.Digest,
			AgentVersion:   Version,
			AgentDigest:    agent,
			Time:           now,
			CI:             env,
			TrustLevel:     trust,
			Tools:          recordedTools(tools, trivyDB, ev, o.LocalScanners),
			Limitations:    toolLimitations(o.LocalScanners, tools),
			Profile:        prof,
			Decision:       dec,
			Evidence:       evidenceDigests(digests),
			ProvenanceHash: digests["provenance.json"],
			ContextDigest:  sha256hex(ctxJSON),
		})
		stJSON, err := json.MarshalIndent(st, "", "  ")
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(out, prof.Statement), stJSON, 0o644); err != nil {
			return nil, err
		}
		c := &Certificate{Profile: prof, Statement: st, Decision: dec}
		res.Certificates = append(res.Certificates, c)
		bundlePath := filepath.Join(out, prof.Bundle)
		os.Remove(bundlePath) // never leave a stale certificate next to new evidence
		if o.Signer == nil {
			continue
		}
		b, err := o.Signer.Sign(ctx, stJSON)
		if err != nil {
			return nil, fmt.Errorf("sign: %w", err)
		}
		if err := os.WriteFile(bundlePath, b, 0o644); err != nil {
			return nil, err
		}
		c.Signed = true
		if o.Attach {
			ann := map[string]string{"dev.open-trust.profile": dec.Profile.ID + "@" + dec.Profile.Version, "dev.open-trust.result": dec.Result}
			if c.Attached, err = subject.Attach(ctx, o.Image, subj.Digest, b, ann); err != nil {
				return nil, err
			}
		}
	}
	return res, nil
}

func evidenceDigests(byFile map[string]string) map[string]string {
	m := map[string]string{}
	for check, f := range statement.EvidenceFiles {
		m[check] = byFile[f]
	}
	return m
}

func nameOr(name, path string) string {
	if name != "" {
		return name
	}
	return "file://" + path
}

func sha256hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func selfDigest() (string, error) {
	p, err := os.Executable()
	if err != nil {
		return "", err
	}
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// checkProvenance prefers a signed provenance bundle; otherwise it falls back to the unsigned BuildKit
// provenance attached to the image, which is bound to it only by the OCI index annotation.
func checkProvenance(o Options, subj *subject.Subject, env ci.Env) (policy.Provenance, []byte, error) {
	if o.Provenance == "" {
		if subj.Provenance == nil {
			return policy.Provenance{}, nil, nil
		}
		return policy.Provenance{Present: true, SubjectMatch: true, Source: "buildkit-unsigned"}, subj.Provenance, nil
	}
	b, err := os.ReadFile(o.Provenance)
	if err != nil {
		return policy.Provenance{}, nil, err
	}
	var tm root.TrustedMaterial
	if o.TrustedRoot != "" {
		tm, err = root.NewTrustedRootFromPath(o.TrustedRoot)
	} else {
		tm, err = root.FetchTrustedRoot()
	}
	if err != nil {
		return policy.Provenance{}, nil, fmt.Errorf("trusted root for provenance: %w", err)
	}
	r, err := provenance.Check(b, subj.Digest, env.Repo, tm)
	if err != nil {
		return policy.Provenance{}, nil, fmt.Errorf("provenance %s: %w", o.Provenance, err)
	}
	return policy.Provenance{Present: true, Signed: true, SignerTrusted: r.SignerTrusted, SubjectMatch: r.SubjectMatch,
		Source: "sigstore-bundle", Signer: r.BuildSigner}, b, nil
}

// recordedTools says in the certificate which tools ran and how: the pinned image, or (local) the
// pinned release archive's sha256, or for Semgrep the host's installation at the pinned version.
func recordedTools(t scb.Tools, trivyDB any, ev *adapters.Evidence, local bool) map[string]any {
	pinned := func(tool scb.Tool) map[string]any {
		if !local {
			return map[string]any{"version": tool.Version, "image": tool.Image}
		}
		a := tool.Release[runtime.GOOS+"/"+runtime.GOARCH]
		return map[string]any{"version": tool.Version, "runner": "local", "release": a}
	}
	syft, trivy, semgrep := pinned(t.Syft), pinned(t.Trivy), pinned(t.Semgrep)
	trivy["db"] = trivyDB
	if local {
		semgrep = map[string]any{"version": t.Semgrep.Version, "runner": "local-path"}
	}
	semgrep["config"], semgrep["ruleset"], semgrep["neutralizedIgnoreFiles"] = t.Semgrep.Config, ev.SemgrepRuleset, nonNil(ev.NeutralizedIgnores)
	return map[string]any{"syft": syft, "trivy": trivy, "semgrep": semgrep}
}

func toolLimitations(local bool, t scb.Tools) []string {
	if !local {
		return nil
	}
	return []string{"Semgrep " + t.Semgrep.Version + " ran from the host's installation: its version was checked, but it is not pinned by digest like the other tools"}
}
