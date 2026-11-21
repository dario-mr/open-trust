package main

import (
	"bytes"
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
