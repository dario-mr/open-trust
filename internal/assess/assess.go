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
	"strings"
	"time"

	"github.com/dario-mr/open-trust/internal/adapters"
	"github.com/dario-mr/open-trust/internal/ci"
	"github.com/dario-mr/open-trust/internal/policy"
	"github.com/dario-mr/open-trust/internal/signer"
	"github.com/dario-mr/open-trust/internal/statement"
	"github.com/dario-mr/open-trust/internal/subject"
	scb "github.com/dario-mr/open-trust/profiles/supply-chain-baseline/v1"
)

const Version = "0.1.0-dev"

type Options struct {
	Image      string // OCI layout dir or tar
	Name       string // subject name, e.g. registry.example.com/acme/svc
	SourceDir  string
	OutDir     string
	Repo       string
	Revision   string
	Exceptions string        // path; default <source>/.otrust/exceptions.yaml
	Signer     signer.Signer // nil: unsigned statement only (local testing)
}

// BundleFile is the signed certificate a vendor hands to customers (with the image).
const BundleFile = "certificate.sigstore.json"

type Result struct {
	Statement *statement.Statement
	Decision  *policy.Decision
	Subject   *subject.Subject
	CI        ci.Env
	OutDir    string
	Signed    bool
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
	img, err := filepath.Abs(o.Image)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
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
	if rel, err := filepath.Rel(src, out); err == nil && rel != "." && !strings.HasPrefix(rel, "..") {
		r.ExcludeRel = rel
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
	if subj.Provenance != nil {
		files["provenance.json"] = subj.Provenance
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
		Now:     now.Format(time.RFC3339),
		Subject: policy.SubjectIn{Digest: subj.Digest, AssessedDigest: subj.Digest},
		Provenance: policy.Provenance{
			Present: subj.Provenance != nil,
			// BuildKit provenance is unsigned and bound to the image only by the index annotation.
			// shortcut: signed/trusted provenance (GitHub attest-build-provenance bundles) is verified in week 4.
			SubjectMatch: subj.Provenance != nil,
		},
		Exceptions: exceptions,
	}
	ctxJSON, err := json.MarshalIndent(pctx, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(out, statement.ContextFile), ctxJSON, 0o644); err != nil {
		return nil, err
	}
	os.Remove(filepath.Join(out, "input.json")) // pre-week-3 layout
	dec, err := policy.Evaluate(ctx, pctx.Input(policy.EvidenceIn{SBOM: ev.SBOM, Vulns: ev.Vulns, Secrets: ev.Secrets, SAST: ev.SAST}))
	if err != nil {
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
	st := statement.Build(statement.Params{
		SubjectName:   nameOr(o.Name, img),
		SubjectDigest: subj.Digest,
		AgentVersion:  Version,
		AgentDigest:   agent,
		Time:          now,
		CI:            env,
		TrustLevel:    trust,
		Tools: map[string]any{
			"syft":  tools.Syft,
			"trivy": map[string]any{"version": tools.Trivy.Version, "image": tools.Trivy.Image, "db": trivyDB},
			"semgrep": map[string]any{"version": tools.Semgrep.Version, "image": tools.Semgrep.Image, "config": tools.Semgrep.Config,
				"neutralizedIgnoreFiles": nonNil(ev.NeutralizedIgnores)},
		},
		Decision:       dec,
		Evidence:       evidenceDigests(digests),
		ProvenanceHash: digests["provenance.json"],
		ContextDigest:  sha256hex(ctxJSON),
	})
	stJSON, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(out, "statement.json"), stJSON, 0o644); err != nil {
		return nil, err
	}
	res := &Result{Statement: st, Decision: dec, Subject: subj, CI: env, OutDir: out}
	bundlePath := filepath.Join(out, BundleFile)
	os.Remove(bundlePath) // never leave a stale certificate next to new evidence
	if o.Signer != nil {
		b, err := o.Signer.Sign(ctx, stJSON)
		if err != nil {
			return nil, fmt.Errorf("sign: %w", err)
		}
		if err := os.WriteFile(bundlePath, b, 0o644); err != nil {
			return nil, err
		}
		res.Signed = true
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
