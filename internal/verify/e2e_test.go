package verify

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/dario-mr/open-trust/internal/assess"
	"github.com/dario-mr/open-trust/internal/signer"
)

// Real signed assessment (pinned scanners via docker) → verification. Needs fixtures/generate.sh first:
//
//	OTRUST_E2E=1 go test ./internal/verify/ -run E2E
func TestE2EAssessSignVerify(t *testing.T) {
	if os.Getenv("OTRUST_E2E") == "" {
		t.Skip("set OTRUST_E2E=1 (needs docker and fixtures/generate.sh)")
	}
	const fx = "../../profiles/supply-chain-baseline/v1/fixtures"
	out, _ := filepath.Abs("../../otrust-out/e2e/signed") // under $HOME so the docker daemon can mount it
	os.RemoveAll(out)
	os.MkdirAll(out, 0o755)
	if _, err := signer.GenerateKey(filepath.Join(out, "vendor")); err != nil {
		t.Fatal(err)
	}
	s, err := signer.LoadKey(filepath.Join(out, "vendor.key"))
	if err != nil {
		t.Fatal(err)
	}
	for c, want := range map[string]Code{"clean": OK, "vulnerable": AssessmentFailed} {
		ev := filepath.Join(out, c)
		img := filepath.Join(fx, "build", c+".oci.tar")
		if _, err := assess.Run(context.Background(), assess.Options{Image: img, SourceDir: filepath.Join(fx, "src", c, "app"),
			OutDir: ev, Revision: "e2e", Signer: s}); err != nil {
			t.Fatal(err)
		}
		r := run(t, Options{Bundle: filepath.Join(ev, assess.BundleFile), Image: img, Evidence: ev,
			TrustPolicy: writeTrust(t, out, "signers:\n  - name: vendor\n    publicKey: vendor.pub\n")})
		if r.Code != want || !r.EvidenceChecked {
			t.Errorf("%s: got %s (%s), want %s with evidence re-checked", c, r.Code, r.Reason, want)
		}
	}
}
