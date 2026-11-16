package assess

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	ocilayout "github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/dario-mr/open-trust/internal/adapters"
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

// A vendor .semgrepignore must not be able to blind the SAST check.
func TestE2EVendorSemgrepignoreIsNeutralized(t *testing.T) {
	e2e(t)
	src := t.TempDir()
	vuln := filepath.Join(fx, "src", "vulnerable", "app")
	b, err := os.ReadFile(filepath.Join(vuln, "Main.java"))
	if err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Join(src, "sub"), 0o755)
	os.WriteFile(filepath.Join(src, "sub", "Main.java"), b, 0o644)
	os.WriteFile(filepath.Join(src, ".semgrepignore"), []byte("*\n"), 0o644)
	os.WriteFile(filepath.Join(src, "sub", ".semgrepignore"), []byte("*\n"), 0o644)
	// docker (Colima) can only mount under $HOME, so stage the source there
	staged, _ := filepath.Abs("../../otrust-out/e2e/semgrepignore-src")
	os.RemoveAll(staged)
	if err := os.CopyFS(staged, os.DirFS(src)); err != nil {
		t.Fatal(err)
	}
	r, err := Run(context.Background(), Options{Image: filepath.Join(fx, "build", "vulnerable.oci.tar"),
		SourceDir: staged, OutDir: outDir(t, "semgrepignore"), Revision: "e2e"})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range r.Decision.Checks {
		if c.ID == "sast" && c.Result != "FAILED" {
			t.Fatalf("sast = %s %v: the vendor's .semgrepignore hid the SQL injection", c.Result, c.Findings)
		}
	}
	ext := r.Statement.Predicate[statement.ExtensionKey].(statement.Extension)
	got := ext.Tools["semgrep"].(map[string]any)["neutralizedIgnoreFiles"].([]string)
	if len(got) != 2 {
		t.Fatalf("neutralized ignore files = %v, want both recorded", got)
	}
	// the exact ruleset used is recorded by digest, and the (non-redistributable) file is not kept
	rs := ext.Tools["semgrep"].(map[string]any)["ruleset"].(adapters.Ruleset)
	if len(rs.SHA256) != 64 || rs.Source != "p/java" {
		t.Fatalf("ruleset not recorded: %+v", rs)
	}
	if _, err := os.Stat(filepath.Join(r.OutDir, ".otrust-semgrep-rules.yaml")); !os.IsNotExist(err) {
		t.Fatalf("ruleset file left in the evidence dir: %v", err)
	}
}

// An image pulled from a registry by digest is assessed exactly like its OCI tar: same subject,
// same result, and the pulled copy does not stay in the evidence dir.
func TestE2ERegistryReference(t *testing.T) {
	e2e(t)
	srv := httptest.NewServer(registry.New())
	defer srv.Close()
	dir := t.TempDir()
	if err := exec.Command("tar", "-xf", filepath.Join(fx, "build", "clean.oci.tar"), "-C", dir).Run(); err != nil {
		t.Fatal(err)
	}
	ii, err := ocilayout.ImageIndexFromPath(dir)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := ii.IndexManifest()
	inner, err := ii.ImageIndex(m.Manifests[0].Digest) // buildx --push pushes this BuildKit index
	if err != nil {
		t.Fatal(err)
	}
	repo := strings.TrimPrefix(srv.URL, "http://") + "/fixture/clean"
	tag, _ := name.NewTag(repo + ":e2e")
	if err := remote.WriteIndex(tag, inner); err != nil {
		t.Fatal(err)
	}
	d, _ := inner.Digest()

	out := outDir(t, "registry")
	r, err := Run(context.Background(), Options{Image: repo + "@" + d.String(),
		SourceDir: filepath.Join(fx, "src", "clean", "app"), OutDir: out, Revision: "e2e"})
	if err != nil {
		t.Fatal(err)
	}
	fromTar := assessFixture(t, "clean", outDir(t, "registry-tar"), "")
	if r.Subject.Digest != fromTar.Subject.Digest || r.Decision.Result != "PASSED" {
		t.Fatalf("registry: %s %s; tar: %s", r.Subject.Digest, r.Decision.Result, fromTar.Subject.Digest)
	}
	if got := r.Statement.Subject[0].Name; got != repo {
		t.Fatalf("subject name = %q, want the repository %q", got, repo)
	}
	if _, err := os.Stat(filepath.Join(out, ".otrust-image")); !os.IsNotExist(err) {
		t.Fatalf("pulled image left in the evidence dir: %v", err)
	}
}
