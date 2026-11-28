package policy

import (
	"context"
	"encoding/json"
	"github.com/dario-mr/open-trust/profiles"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func fixture(t *testing.T, name string) *Input {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("../../profiles/supply-chain-baseline/v1/fixtures/inputs", name, "input.json"))
	if err != nil {
		t.Fatal(err)
	}
	var in Input
	if err := json.Unmarshal(b, &in); err != nil {
		t.Fatal(err)
	}
	return &in
}

// The embedded Go evaluation must agree with `opa test` on the same fixtures.
func TestEvaluateFixtures(t *testing.T) {
	ctx := context.Background()
	d, err := Evaluate(ctx, profiles.SupplyChain, fixture(t, "clean"))
	if err != nil {
		t.Fatal(err)
	}
	if d.Result != "PASSED" || len(d.UnmetRequirements) != 0 {
		t.Errorf("clean: %s %v", d.Result, d.UnmetRequirements)
	}
	if d.Profile.ID != "supply-chain-baseline" || d.Profile.Version != "1.3.0" {
		t.Errorf("profile = %+v", d.Profile)
	}

	d, err = Evaluate(ctx, profiles.SupplyChain, fixture(t, "vulnerable"))
	if err != nil {
		t.Fatal(err)
	}
	var failed []string
	for _, c := range d.Checks {
		if c.Result == "FAILED" {
			failed = append(failed, c.ID)
		}
	}
	if d.Result != "FAILED" || !slices.Equal(failed, []string{"vulns", "secrets", "sast"}) {
		t.Errorf("vulnerable: %s, failed checks %v", d.Result, failed)
	}
}

func TestMissingEvidenceIsNotNull(t *testing.T) {
	in := fixture(t, "clean")
	in.Evidence.SAST = nil
	d, err := Evaluate(context.Background(), profiles.SupplyChain, in)
	if err != nil {
		t.Fatal(err)
	}
	if d.Result != "FAILED" || !slices.Contains(d.UnmetRequirements, "sast: missing SAST evidence") {
		t.Fatalf("nil evidence must count as missing: %s %v", d.Result, d.UnmetRequirements)
	}
}

func TestLoadExceptions(t *testing.T) {
	dir := t.TempDir()
	if es, err := LoadExceptions(filepath.Join(dir, "none.yaml")); err != nil || len(es) != 0 {
		t.Fatalf("missing file: %v %v", es, err)
	}
	p := filepath.Join(dir, "e.yaml")
	os.WriteFile(p, []byte("- check: vulns\n  id: CVE-1\n  reason: r\n  expires: 2099-01-01T00:00:00Z\n"), 0o644)
	es, err := LoadExceptions(p)
	if err != nil || len(es) != 1 || es[0].Expires != "2099-01-01T00:00:00Z" {
		t.Fatalf("got %+v %v", es, err)
	}
	os.WriteFile(p, []byte("- check: vulns\n  id: CVE-1\n  reason: r\n  expiry: 2099-01-01\n"), 0o644)
	if _, err := LoadExceptions(p); err == nil {
		t.Fatal("unknown key must be rejected")
	}
}

// An exception for a check no profile has would match nothing and silently except nothing.
func TestLoadExceptionsRefusesUnknownCheck(t *testing.T) {
	p := filepath.Join(t.TempDir(), "exceptions.yaml")
	os.WriteFile(p, []byte("- {check: licences, id: x, reason: typo, expires: \"2099-01-01T00:00:00Z\"}\n"), 0o644)
	if _, err := LoadExceptions(p); err == nil {
		t.Fatal("unknown check accepted")
	}
	os.WriteFile(p, []byte("- {check: licenses, id: x, reason: r, expires: \"2099-01-01T00:00:00Z\"}\n- {check: vulns, id: y, reason: r, expires: \"2099-01-01T00:00:00Z\"}\n"), 0o644)
	if es, err := LoadExceptions(p); err != nil || len(es) != 2 {
		t.Fatalf("%v %v", es, err)
	}
}
