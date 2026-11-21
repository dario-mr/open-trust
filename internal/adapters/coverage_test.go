package adapters

import (
	"reflect"
	"testing"

	"github.com/dario-mr/open-trust/internal/policy"
)

func TestSASTCoverage(t *testing.T) {
	sast := []byte(`{"paths":{"scanned":["/src/main.go","/src/app/Main.kt","/src/lib/x.KTS","/src/README.md",
		"/src/Dockerfile","/src/deploy/api.Dockerfile","/src/native/core.cpp","/src/config.yaml"]}}`)
	rules := map[string]int{}
	for _, l := range []string{"go", "go", "kt", "Kotlin", "dockerfile", "yaml", "generic"} {
		rules[ruleLanguage(l)]++
	}
	got := SASTCoverage(sast, rules)
	want := []policy.LanguageCoverage{
		{Language: "cpp", Files: 1, Rules: 0}, // the uncovered one
		{Language: "dockerfile", Files: 2, Rules: 1},
		{Language: "go", Files: 1, Rules: 2},
		{Language: "kotlin", Files: 2, Rules: 2},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
	if got := SASTCoverage([]byte(`{}`), rules); len(got) != 0 {
		t.Fatalf("no scanned paths: %+v", got)
	}
}
