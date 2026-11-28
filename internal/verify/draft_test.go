package verify

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const realCert, realRoot = "testdata/demo-isolated.sigstore.json", "testdata/public-good-trusted-root.json"

// A real keyless certificate: the draft pins its identity and accepts it (DraftPolicy self-checks).
func TestDraftPolicyFromRealCertificate(t *testing.T) {
	d, err := DraftPolicy(Options{Bundle: realCert, TrustedRoot: realRoot})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"minTrustLevel: L1+isolated-assessor", "sourceRepo: 'https://github.com/dario-mr/open-trust-demo'",
		`assess\.yml@`, "requireHostedRunner: true", "minAgentVersion: "} {
		if !strings.Contains(d, want) {
			t.Errorf("draft lacks %q:\n%s", want, d)
		}
	}
}

// A certificate whose signed payload was edited proves nothing: no draft.
func TestDraftPolicyRefusesTamperedCertificate(t *testing.T) {
	var b map[string]any
	json.Unmarshal(mustRead(t, realCert), &b)
	env := b["dsseEnvelope"].(map[string]any)
	env["payload"] = "e30=" // {}
	out, _ := json.Marshal(b)
	p := filepath.Join(t.TempDir(), "edited.sigstore.json")
	os.WriteFile(p, out, 0o644)
	if _, err := DraftPolicy(Options{Bundle: p, TrustedRoot: realRoot}); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("got %v", err)
	}
}

// A key-signed certificate: the draft names the key file, and with the vendor's key it verifies.
func TestDraftPolicyForKeySigned(t *testing.T) {
	c := newCert(t, "clean", nil)
	d, err := DraftPolicy(Options{Bundle: c.bundle})
	if err != nil || !strings.Contains(d, "publicKey: vendor.pub") {
		t.Fatalf("%v\n%s", err, d)
	}
	c.opts.TrustPolicy = writeTrust(t, c.dir, d) // newCert put vendor.pub in c.dir
	expect(t, run(t, c.opts), OK, "")
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
