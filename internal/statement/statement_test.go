package statement

import (
	"encoding/json"
	"github.com/dario-mr/open-trust/profiles"
	"testing"
	"time"

	"github.com/dario-mr/open-trust/internal/policy"
)

func build(result string) map[string]any {
	d := &policy.Decision{Result: result, Checks: []policy.Check{{ID: "sbom", Result: result}, {ID: "subject_binding", Result: "PASSED"}}}
	d.Profile.ID, d.Profile.Version = "supply-chain-baseline", "1.0.0"
	st := Build(Params{Profile: profiles.SupplyChain,
		SubjectName: "example.com/x", SubjectDigest: "sha256:abc", Time: time.Unix(0, 0),
		TrustLevel: "unsigned", Decision: d, Evidence: map[string]string{"sbom": "f00", "subject_binding": ""},
	})
	b, _ := json.Marshal(st)
	var m map[string]any
	json.Unmarshal(b, &m)
	return m
}

func TestVSAShape(t *testing.T) {
	m := build("PASSED")
	p := m["predicate"].(map[string]any)
	for _, k := range []string{"verifier", "timeVerified", "resourceUri", "policy", "verificationResult", "verifiedLevels"} {
		if _, ok := p[k]; !ok {
			t.Errorf("VSA predicate missing required field %q", k)
		}
	}
	if got := p["policy"].(map[string]any)["digest"].(map[string]any)["sha256"]; got != profiles.SupplyChain.Digest() {
		t.Errorf("policy digest = %v", got)
	}
	if got := m["subject"].([]any)[0].(map[string]any)["digest"].(map[string]any)["sha256"]; got != "abc" {
		t.Errorf("subject digest must drop the sha256: prefix, got %v", got)
	}
	if lv := p["verifiedLevels"].([]any); len(lv) != 1 || lv[0] != profiles.SupplyChain.VSALevel {
		t.Errorf("verifiedLevels = %v", lv)
	}
	ext := p[ExtensionKey].(map[string]any)
	checks := ext["checks"].([]any)
	if _, ok := checks[0].(map[string]any)["evidenceDigest"]; !ok {
		t.Error("sbom check must carry its evidence digest")
	}
	if _, ok := checks[1].(map[string]any)["evidenceDigest"]; ok {
		t.Error("a check without evidence must not carry an empty digest")
	}
	if ext["validUntil"] != "1970-01-31T00:00:00Z" {
		t.Errorf("validUntil = %v, want +30 days", ext["validUntil"])
	}
}

func TestFailedResultUsesFailedLevel(t *testing.T) {
	p := build("FAILED")["predicate"].(map[string]any)
	if lv := p["verifiedLevels"].([]any); len(lv) != 1 || lv[0] != "FAILED" {
		t.Errorf("verifiedLevels = %v", lv)
	}
}
