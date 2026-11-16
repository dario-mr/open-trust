package verify

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dario-mr/open-trust/internal/policy"
	"github.com/dario-mr/open-trust/internal/signer"
	"github.com/dario-mr/open-trust/internal/statement"
	"github.com/dario-mr/open-trust/internal/trustlevel"
	scb "github.com/dario-mr/open-trust/profiles/supply-chain-baseline/v1"
)

// Hermetic certificates: real Week 1 scanner evidence + a synthetic OCI image, signed in-process.

const fixtures = "../../profiles/supply-chain-baseline/v1/fixtures/inputs"

type cert struct {
	dir, bundle, image, trust string
	opts                      Options
}

func writeBlob(t *testing.T, dir string, b []byte) string {
	sum := sha256.Sum256(b)
	h := hex.EncodeToString(sum[:])
	p := filepath.Join(dir, "blobs", "sha256", h)
	os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return "sha256:" + h
}

func writeImage(t *testing.T, content string) (dir, digest string) {
	dir = t.TempDir()
	cfgB, layerB := []byte(`{"os":"linux","rootfs":{"type":"layers","diff_ids":[]}}`), []byte(content)
	cfg, layer := writeBlob(t, dir, cfgB), writeBlob(t, dir, layerB)
	m, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
		"config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": cfg, "size": len(cfgB)},
		"layers": []any{map[string]any{"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": layer, "size": len(layerB)}}})
	digest = writeBlob(t, dir, m)
	idx, _ := json.Marshal(map[string]any{"schemaVersion": 2, "manifests": []any{
		map[string]any{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": digest, "size": len(m)}}})
	os.WriteFile(filepath.Join(dir, "index.json"), idx, 0o644)
	return dir, digest
}

func sha(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// newCert assesses a fixture case (clean|vulnerable) and signs it; mut may lie in the statement before signing.
func newCert(t *testing.T, fixture string, mut func(p map[string]any, ext *statement.Extension)) cert {
	t.Helper()
	ctx := context.Background()
	c := cert{dir: t.TempDir()}
	var digest string
	c.image, digest = writeImage(t, "layer of "+fixture)

	raw, err := os.ReadFile(filepath.Join(fixtures, fixture, "input.json"))
	if err != nil {
		t.Fatal(err)
	}
	var in policy.Input
	json.Unmarshal(raw, &in)
	digests := map[string]string{}
	for id, b := range map[string][]byte{"sbom": in.Evidence.SBOM, "vulns": in.Evidence.Vulns, "secrets": in.Evidence.Secrets, "sast": in.Evidence.SAST} {
		os.WriteFile(filepath.Join(c.dir, statement.EvidenceFiles[id]), b, 0o644)
		digests[id] = sha(b)
	}
	now := time.Now().UTC().Truncate(time.Second)
	pc := policy.Context{Now: now.Format(time.RFC3339), Subject: policy.SubjectIn{Digest: digest, AssessedDigest: digest},
		Provenance: in.Provenance, Exceptions: []policy.Exception{}}
	ctxJSON, _ := json.Marshal(pc)
	os.WriteFile(filepath.Join(c.dir, statement.ContextFile), ctxJSON, 0o644)
	dec, err := policy.Evaluate(ctx, pc.Input(in.Evidence))
	if err != nil {
		t.Fatal(err)
	}
	st := statement.Build(statement.Params{SubjectName: "example.com/" + fixture, SubjectDigest: digest, AgentVersion: "test",
		AgentDigest: "a9e17", Time: now, TrustLevel: trustlevel.L1, Decision: dec, Evidence: digests, ContextDigest: sha(ctxJSON)})
	if mut != nil {
		ext := st.Predicate[statement.ExtensionKey].(statement.Extension)
		mut(st.Predicate, &ext)
		if _, kept := st.Predicate[statement.ExtensionKey]; kept {
			st.Predicate[statement.ExtensionKey] = ext
		}
	}
	stJSON, _ := json.Marshal(st)

	keys := filepath.Join(c.dir, "vendor")
	if _, err := signer.GenerateKey(keys); err != nil {
		t.Fatal(err)
	}
	s, err := signer.LoadKey(keys + ".key")
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.Sign(ctx, stJSON)
	if err != nil {
		t.Fatal(err)
	}
	c.bundle = filepath.Join(c.dir, "certificate.sigstore.json")
	os.WriteFile(c.bundle, b, 0o644)
	c.trust = writeTrust(t, c.dir, "signers:\n  - name: vendor\n    publicKey: vendor.pub\n")
	c.opts = Options{Bundle: c.bundle, Image: c.image, TrustPolicy: c.trust, Evidence: c.dir}
	return c
}

func writeTrust(t *testing.T, dir, yaml string) string {
	p := filepath.Join(dir, "trust-"+sha([]byte(yaml))[:8]+".yaml")
	os.WriteFile(p, []byte(yaml), 0o644)
	return p
}

func run(t *testing.T, o Options) *Report {
	t.Helper()
	r, err := Verify(context.Background(), o)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	return r
}

func expect(t *testing.T, r *Report, want Code, reasonContains string) {
	t.Helper()
	if r.Code != want || !strings.Contains(r.Reason, reasonContains) {
		t.Fatalf("got %s (%s), want %s containing %q", r.Code, r.Reason, want, reasonContains)
	}
}

// ---------------------------------------------------------------- outcomes

func TestVerifiedWithEvidence(t *testing.T) {
	c := newCert(t, "clean", nil)
	r := run(t, c.opts)
	expect(t, r, OK, "")
	if !r.EvidenceChecked || r.TrustLevel != trustlevel.L1 || r.SignerName != "vendor" {
		t.Fatalf("report: %+v", r)
	}
}

func TestInvalidSignatureWhenPayloadEdited(t *testing.T) {
	c := newCert(t, "vulnerable", nil)
	raw, _ := os.ReadFile(c.bundle)
	var b map[string]any
	json.Unmarshal(raw, &b)
	env := b["dsseEnvelope"].(map[string]any)
	payload, _ := base64.StdEncoding.DecodeString(env["payload"].(string))
	edited := strings.Replace(string(payload), `"verificationResult":"FAILED"`, `"verificationResult":"PASSED"`, 1)
	if edited == string(payload) {
		t.Fatal("test setup: nothing replaced")
	}
	env["payload"] = base64.StdEncoding.EncodeToString([]byte(edited))
	out, _ := json.Marshal(b)
	os.WriteFile(c.bundle, out, 0o644)
	expect(t, run(t, c.opts), InvalidSignature, "")
}

func TestUntrustedSigner(t *testing.T) {
	c := newCert(t, "clean", nil)
	other := filepath.Join(t.TempDir(), "other")
	signer.GenerateKey(other)
	c.opts.TrustPolicy = writeTrust(t, filepath.Dir(other), "signers:\n  - name: someone else\n    publicKey: other.pub\n")
	expect(t, run(t, c.opts), UntrustedSigner, "does not list")
}

func TestMalformed(t *testing.T) {
	c := newCert(t, "clean", nil)
	os.WriteFile(c.bundle, []byte(`{"not":"a bundle"}`), 0o644)
	expect(t, run(t, c.opts), Malformed, "")

	c = newCert(t, "clean", func(p map[string]any, _ *statement.Extension) { delete(p, statement.ExtensionKey) })
	expect(t, run(t, c.opts), Malformed, "no Open Trust assessment")
}

func TestPolicyUnknown(t *testing.T) {
	c := newCert(t, "clean", func(p map[string]any, _ *statement.Extension) {
		p["policy"] = map[string]any{"uri": "https://example.com/my-lax-policy", "digest": map[string]string{"sha256": "00"}}
	})
	expect(t, run(t, c.opts), PolicyUnknown, "my-lax-policy")
}

func TestArtifactMismatch(t *testing.T) {
	c := newCert(t, "clean", nil)
	c.opts.Image, _ = writeImage(t, "a different image")
	expect(t, run(t, c.opts), ArtifactMismatch, "certificate is for")

	// same digest, but a layer was swapped in the layout the customer received
	c = newCert(t, "clean", nil)
	filepath.WalkDir(filepath.Join(c.image, "blobs"), func(p string, d os.DirEntry, _ error) error {
		if b, _ := os.ReadFile(p); !d.IsDir() && string(b) == "layer of clean" {
			os.WriteFile(p, []byte("layer of evil"), 0o644)
		}
		return nil
	})
	expect(t, run(t, c.opts), ArtifactMismatch, "does not match its digest")
}

func TestTrustLevelTooLowAndClaimNotTrusted(t *testing.T) {
	// the vendor claims the strongest level, but a key signature only proves L1
	c := newCert(t, "clean", func(_ map[string]any, ext *statement.Extension) { ext.TrustLevel = trustlevel.L1IsolatedAssessor })
	r := run(t, c.opts)
	expect(t, r, OK, "")
	if r.TrustLevel != trustlevel.L1 || len(r.Notes) == 0 || !strings.Contains(r.Notes[0], "claims") {
		t.Fatalf("claimed level must not be trusted: %+v", r)
	}
	c.opts.TrustPolicy = writeTrust(t, c.dir, "minTrustLevel: L1+ci-identity\nsigners:\n  - name: vendor\n    publicKey: vendor.pub\n")
	expect(t, run(t, c.opts), TrustLevelTooLow, "below the required L1+ci-identity")
}

func TestRevoked(t *testing.T) {
	c := newCert(t, "clean", nil)
	r := run(t, c.opts)
	rev := filepath.Join(c.dir, "revocations.json")
	os.WriteFile(rev, []byte(`{"revoked":[{"subject":"`+r.SubjectDigest+`","reason":"recalled build"}]}`), 0o644)
	c.opts.Revocations = rev
	expect(t, run(t, c.opts), Revoked, "recalled build")

	os.WriteFile(rev, []byte(`{"revoked":[{"signer":"`+strings.TrimPrefix(r.SignerIdentity, "key ")+`","reason":"key leaked"}]}`), 0o644)
	expect(t, run(t, c.opts), Revoked, "key leaked")
}

func TestExpired(t *testing.T) {
	c := newCert(t, "clean", nil)
	c.opts.Now = time.Now().Add(statement.Validity + time.Hour)
	expect(t, run(t, c.opts), Expired, "expired at")
}

func TestEvidenceMissing(t *testing.T) {
	c := newCert(t, "clean", nil)
	os.Remove(filepath.Join(c.dir, "sast.json"))
	expect(t, run(t, c.opts), EvidenceMissing, "sast.json")
}

func TestEvidenceMismatchOnEditedFile(t *testing.T) {
	c := newCert(t, "clean", nil)
	os.WriteFile(filepath.Join(c.dir, "vulns.json"), []byte(`{"Results":[]}`), 0o644)
	expect(t, run(t, c.opts), EvidenceMismatch, "vulns.json does not match")
}

// The vendor signs honest evidence digests but a dishonest summary. Only re-evaluation catches it.
func TestEvidenceMismatchOnLyingSummary(t *testing.T) {
	c := newCert(t, "vulnerable", func(p map[string]any, ext *statement.Extension) {
		p["verificationResult"], p["verifiedLevels"] = "PASSED", []string{scb.VSALevel}
		for i := range ext.Checks {
			ext.Checks[i].Result, ext.Checks[i].Findings = "PASSED", nil
		}
		ext.UnmetRequirements = []string{}
	})
	noEvidence := c.opts
	noEvidence.Evidence = ""
	expect(t, run(t, noEvidence), OK, "") // a signature alone cannot reveal the lie
	expect(t, run(t, c.opts), EvidenceMismatch, "evidence gives FAILED")
}

func TestAssessmentFailed(t *testing.T) {
	c := newCert(t, "vulnerable", nil)
	r := run(t, c.opts)
	expect(t, r, AssessmentFailed, "FAILED")
	if !r.EvidenceChecked || len(r.Predicate.Ext.UnmetRequirements) != 5 {
		t.Fatalf("failed assessment must still be fully verified and explained: %+v", r)
	}
}

// ---------------------------------------------------------------- keyless (real GitHub Actions bundle)

const (
	autogovBundle = "testdata/autogov-vsa.sigstore.json"
	publicRoot    = "testdata/public-good-trusted-root.json"
	ghIssuer      = "https://token.actions.githubusercontent.com"
)

func autogovOpts(t *testing.T, trust string) Options {
	return Options{Bundle: autogovBundle, TrustedRoot: publicRoot, TrustPolicy: writeTrust(t, t.TempDir(), trust)}
}

func TestKeylessCertificateIdentityAndTrustLevel(t *testing.T) {
	trust := "signers:\n  - name: autogov\n    issuer: " + ghIssuer + "\n    sourceRepo: https://github.com/liatrio/autogov\n" +
		"    buildSigner: ^https://github\\.com/liatrio/autogov-workflows/\n    requireHostedRunner: true\n"
	r := run(t, autogovOpts(t, trust))
	// signature + identity verify; it then fails as MALFORMED because it is autogov's VSA, not ours
	expect(t, r, Malformed, "no Open Trust assessment")
	if r.SignerName != "autogov" || !strings.Contains(r.SignerIdentity, "rw-verify.yaml") {
		t.Fatalf("identity: %+v", r)
	}
	if r.TrustLevel != trustlevel.L1CIIdentity {
		t.Fatalf("not a known assessor, so ci-identity; got %s", r.TrustLevel)
	}

	// the same certificate from a known isolated assessor (reusable workflow in another repo, hosted runner)
	saved := trustlevel.KnownAssessors
	trustlevel.KnownAssessors = []string{"https://github.com/liatrio/autogov-workflows/.github/workflows/rw-verify.yaml@"}
	t.Cleanup(func() { trustlevel.KnownAssessors = saved })
	if r := run(t, autogovOpts(t, trust)); r.TrustLevel != trustlevel.L1IsolatedAssessor {
		t.Fatalf("got %s", r.TrustLevel)
	}
}

func TestKeylessUntrustedRepoOrSigner(t *testing.T) {
	r := run(t, autogovOpts(t, "signers:\n  - name: acme\n    issuer: "+ghIssuer+"\n    sourceRepo: https://github.com/acme/svc\n"))
	expect(t, r, UntrustedSigner, `source repo "https://github.com/liatrio/autogov"`)

	r = run(t, autogovOpts(t, "signers:\n  - name: pinned\n    issuer: "+ghIssuer+"\n    sourceRepo: https://github.com/liatrio/autogov\n"+
		"    buildSigner: ^https://github\\.com/liatrio/autogov/\n"))
	expect(t, r, UntrustedSigner, "build signer")
}

func TestKeylessTamperedPayload(t *testing.T) {
	raw, _ := os.ReadFile(autogovBundle)
	var b map[string]any
	json.Unmarshal(raw, &b)
	env := b["dsseEnvelope"].(map[string]any)
	p, _ := base64.StdEncoding.DecodeString(env["payload"].(string))
	env["payload"] = base64.StdEncoding.EncodeToString([]byte(strings.Replace(string(p), "PASSED", "FAILED", 1)))
	out, _ := json.Marshal(b)
	o := autogovOpts(t, "signers:\n  - name: autogov\n    issuer: "+ghIssuer+"\n    sourceRepo: https://github.com/liatrio/autogov\n")
	o.Bundle = filepath.Join(t.TempDir(), "tampered.json")
	os.WriteFile(o.Bundle, out, 0o644)
	expect(t, run(t, o), InvalidSignature, "")
}

// ---------------------------------------------------------------- safe defaults

func TestTrustPolicyIsRequiredAndStrict(t *testing.T) {
	c := newCert(t, "clean", nil)
	o := c.opts
	o.TrustPolicy = ""
	if _, err := Verify(context.Background(), o); err == nil {
		t.Fatal("no trust policy must be an error, never 'trust anyone'")
	}
	for name, y := range map[string]string{
		"no signers":           "signers: []\n",
		"typo key":             "signers:\n  - name: x\n    publickey: vendor.pub\n",
		"repo-less CI":         "signers:\n  - name: x\n    issuer: " + ghIssuer + "\n",
		"unknown level":        "minTrustLevel: L3\nsigners:\n  - name: x\n    publicKey: vendor.pub\n",
		"key and issuer mixed": "signers:\n  - name: x\n    publicKey: vendor.pub\n    issuer: " + ghIssuer + "\n",
	} {
		o.TrustPolicy = writeTrust(t, c.dir, y)
		if _, err := Verify(context.Background(), o); err == nil {
			t.Errorf("%s: must be rejected", name)
		}
	}
	o = autogovOpts(t, "signers:\n  - name: a\n    issuer: "+ghIssuer+"\n    sourceRepo: https://github.com/liatrio/autogov\n")
	o.TrustedRoot = ""
	if _, err := Verify(context.Background(), o); err == nil || !strings.Contains(err.Error(), "trusted-root") {
		t.Fatalf("keyless without trusted root: %v", err)
	}
}
