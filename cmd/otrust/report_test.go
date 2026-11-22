package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/dario-mr/open-trust/internal/verify"
)

// Scripts (demo/scenarios.sh) read the verdict from the last line.
func TestReportEndsWithVerdict(t *testing.T) {
	for r, want := range map[*verify.Report]string{
		{Code: verify.OK}: "VERIFIED",
		{Code: verify.ArtifactMismatch, Reason: "image is x"}: "ARTIFACT_MISMATCH: image is x",
	} {
		var b bytes.Buffer
		printReport(&b, r)
		lines := strings.Split(strings.TrimSpace(b.String()), "\n")
		if got := lines[len(lines)-1]; got != want {
			t.Errorf("last line %q, want %q", got, want)
		}
		if md := markdownReport(r, "c.json", "img"); !strings.HasPrefix(md, "# Open Trust verification: ") {
			t.Errorf("markdown starts %q", md[:40])
		}
	}
	for c := range verify.ExitCodes {
		if meaning[c] == "" {
			t.Errorf("no plain-language meaning for %s", c)
		}
	}
}

func TestSeverityCounts(t *testing.T) {
	fs := []string{"CRITICAL a", "HIGH b", "HIGH c", "WARNING d"}
	if got := severityCounts(fs); got != " (1 CRITICAL, 2 HIGH, 1 WARNING)" {
		t.Errorf("got %q", got)
	}
	if got := severityCounts(fs[:3]); got != "" {
		t.Errorf("short lists need no summary, got %q", got)
	}
}

func TestCertificateSubject(t *testing.T) {
	payload := `{"subject":[{"name":"x","digest":{"sha256":"abc"}}],"predicate":{"policy":{"uri":"https://open-trust.dev/profiles/supply-chain-baseline/1.1.0"},"verificationResult":"PASSED"}}`
	b, _ := json.Marshal(map[string]any{"dsseEnvelope": map[string]any{"payload": []byte(payload)}})
	d, ann, err := certificateSubject(b)
	if err != nil || d != "sha256:abc" || ann["dev.open-trust.profile"] != "supply-chain-baseline@1.1.0" || ann["dev.open-trust.result"] != "PASSED" {
		t.Fatalf("%s %v %v", d, ann, err)
	}
	if _, _, err := certificateSubject([]byte(`{"mediaType":"x"}`)); err == nil {
		t.Fatal("not a certificate must be refused")
	}
}
