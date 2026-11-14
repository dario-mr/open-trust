package provenance

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/root"
)

// testdata/autogov-slsa-provenance.sigstore.json: real GitHub-signed SLSA v1 provenance
// (first line of autogov.intoto.jsonl, liatrio/autogov v1.4.6) for the autogov binary.
const (
	bundlePath = "testdata/autogov-slsa-provenance.sigstore.json"
	autogovSHA = "sha256:c5947ea28d3efc2a0d4c27580cd3a4c8c42525afdb19527c4a52a6bf5f3790e0"
	repo       = "https://github.com/liatrio/autogov"
)

func trusted(t *testing.T) root.TrustedMaterial {
	tr, err := root.NewTrustedRootFromPath("../verify/testdata/public-good-trusted-root.json")
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

func load(t *testing.T) []byte {
	b, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSignedProvenanceForThisArtifactFromThisRepo(t *testing.T) {
	r, err := Check(load(t), autogovSHA, repo+".git", trusted(t))
	if err != nil {
		t.Fatal(err)
	}
	if !r.SubjectMatch || !r.SignerTrusted || r.PredicateType != "https://slsa.dev/provenance/v1" {
		t.Fatalf("%+v", r)
	}
	if !strings.Contains(r.BuildSigner, "rw-attest-blob.yaml") {
		t.Fatalf("build signer = %s", r.BuildSigner)
	}
}

func TestOtherArtifactOrOtherRepo(t *testing.T) {
	r, err := Check(load(t), "sha256:"+strings.Repeat("0", 64), repo, trusted(t))
	if err != nil || r.SubjectMatch {
		t.Fatalf("other image must not match: %+v %v", r, err)
	}
	r, err = Check(load(t), autogovSHA, "https://github.com/acme/svc", trusted(t))
	if err != nil || r.SignerTrusted {
		t.Fatalf("provenance from another repository must not be trusted: %+v %v", r, err)
	}
}

func TestTamperedProvenanceIsAnError(t *testing.T) {
	var b map[string]any
	json.Unmarshal(load(t), &b)
	env := b["dsseEnvelope"].(map[string]any)
	p, _ := base64.StdEncoding.DecodeString(env["payload"].(string))
	env["payload"] = base64.StdEncoding.EncodeToString([]byte(strings.Replace(string(p), "c5947ea2", "deadbeef", 1)))
	out, _ := json.Marshal(b)
	if _, err := Check(out, autogovSHA, repo, trusted(t)); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("tampered provenance must fail: %v", err)
	}
	if _, err := Check([]byte(`{}`), autogovSHA, repo, trusted(t)); err == nil {
		t.Fatal("garbage must fail")
	}
}
