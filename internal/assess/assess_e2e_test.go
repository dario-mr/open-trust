package assess

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/dario-mr/open-trust/internal/statement"
)

// End-to-end against the real pinned scanners. Needs docker and built fixtures:
//
//	profiles/supply-chain-baseline/v1/fixtures/generate.sh && OTRUST_E2E=1 go test ./internal/assess/
//
// The out dir is under the repo (not t.TempDir) so the docker daemon can mount it (Colima shares $HOME only).
const fx = "../../profiles/supply-chain-baseline/v1/fixtures"

func e2e(t *testing.T) {
	t.Helper()
	if os.Getenv("OTRUST_E2E") == "" {
		t.Skip("set OTRUST_E2E=1 (needs docker and fixtures/generate.sh)")
	}
}

func outDir(t *testing.T, name string) string {
	d, _ := filepath.Abs(filepath.Join("../../otrust-out/e2e", name))
	os.RemoveAll(d)
	return d
}

func assessFixture(t *testing.T, c, out, exceptions string) *Result {
	t.Helper()
	r, err := Run(context.Background(), Options{
		Image: filepath.Join(fx, "build", c+".oci.tar"), Name: "example.com/fixture/" + c,
		SourceDir: filepath.Join(fx, "src", c, "app"), OutDir: out,
		Revision: "e2e", Exceptions: exceptions,
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestE2EClean(t *testing.T) {
	e2e(t)
	out := outDir(t, "clean")
	r := assessFixture(t, "clean", out, "")
	if r.Decision.Result != "PASSED" {
		t.Fatalf("clean: %s %v", r.Decision.Result, r.Decision.UnmetRequirements)
	}
	// every evidence digest in the statement must match the file written next to it
	ext := r.Statement.Predicate[statement.ExtensionKey].(statement.Extension)
	files := map[string]string{"sbom": "sbom.cdx.json", "vulns": "vulns.json", "secrets": "secrets.json", "sast": "sast.json", "provenance": "provenance.json"}
	for _, c := range ext.Checks {
		f, ok := files[c.ID]
		if !ok {
			continue
		}
		b, err := os.ReadFile(filepath.Join(out, f))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(b)
		if c.EvidenceDigest["sha256"] != hex.EncodeToString(sum[:]) {
			t.Errorf("%s: evidence digest does not match %s", c.ID, f)
		}
	}
}

func TestE2EVulnerableFailsThenPassesWithExceptions(t *testing.T) {
	e2e(t)
	r := assessFixture(t, "vulnerable", outDir(t, "vulnerable"), "")
	if r.Decision.Result != "FAILED" || len(r.Decision.UnmetRequirements) != 5 {
		t.Fatalf("vulnerable: %s %v", r.Decision.Result, r.Decision.UnmetRequirements)
	}

	exc := filepath.Join(outDir(t, "exc"), "exceptions.yaml")
	os.MkdirAll(filepath.Dir(exc), 0o755)
	os.WriteFile(exc, []byte(`
- {check: vulns, id: CVE-2021-44228, reason: fixture, expires: "2099-01-01T00:00:00Z"}
- {check: vulns, id: CVE-2021-45046, reason: fixture, expires: "2099-01-01T00:00:00Z"}
- {check: vulns, id: CVE-2021-45105, reason: fixture, expires: "2099-01-01T00:00:00Z"}
- {check: secrets, id: "config/deploy.pem#private-key", reason: fake key, expires: "2099-01-01T00:00:00Z"}
- {check: sast, id: java.lang.security.audit.formatted-sql-string.formatted-sql-string, reason: fixture, expires: "2099-01-01T00:00:00Z"}
`), 0o644)
	r = assessFixture(t, "vulnerable", outDir(t, "vulnerable-exc"), exc)
	if r.Decision.Result != "PASSED" || len(r.Decision.ExceptionsApplied) != 5 {
		t.Fatalf("with exceptions: %s, applied %d, unmet %v", r.Decision.Result, len(r.Decision.ExceptionsApplied), r.Decision.UnmetRequirements)
	}
}

// Evidence written inside the source tree must not be scanned on the next run.
func TestE2EOutDirInsideSourceIsExcluded(t *testing.T) {
	e2e(t)
	src, _ := filepath.Abs(filepath.Join(fx, "src", "vulnerable", "app"))
	out := filepath.Join(src, "otrust-out")
	t.Cleanup(func() { os.RemoveAll(out) })
	// Trivy redacts secrets in its own output, so plant one in the evidence dir to make the exclusion observable.
	os.MkdirAll(out, 0o755)
	os.WriteFile(filepath.Join(out, "planted.pem"), []byte("-----BEGIN RSA PRIVATE KEY-----\n"+
		"MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\nKUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQ==\n"+
		"-----END RSA PRIVATE KEY-----\n"), 0o644)
	for i := range 2 {
		r, err := Run(context.Background(), Options{
			Image: filepath.Join(fx, "build", "vulnerable.oci.tar"), SourceDir: src, OutDir: out, Revision: "e2e",
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range r.Decision.Checks {
			if c.ID == "secrets" && len(c.Findings) != 1 {
				t.Fatalf("run %d: secrets findings = %v (evidence dir was scanned?)", i+1, c.Findings)
			}
		}
	}
}
