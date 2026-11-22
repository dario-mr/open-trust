package adapters

import (
	"os"
	"path/filepath"
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

// The local SAST tree links the vendor's files, blanks .semgrepignore without touching the
// vendor's copy, and leaves excluded paths (the evidence dir) out.
func TestLocalSASTDirLeavesVendorTreeAlone(t *testing.T) {
	src, work := t.TempDir(), t.TempDir()
	os.MkdirAll(filepath.Join(src, "app"), 0o755)
	os.WriteFile(filepath.Join(src, "app", "main.go"), []byte("package main\n"), 0o644)
	os.WriteFile(filepath.Join(src, "app", ".semgrepignore"), []byte("*\n"), 0o644)
	os.MkdirAll(filepath.Join(src, "otrust-out"), 0o755)
	os.WriteFile(filepath.Join(src, "otrust-out", "sast.json"), []byte("{}"), 0o644)
	r := &Runner{SourceDir: src, WorkDir: work, Exclude: []string{"otrust-out"}}
	dir, err := r.localSASTDir([]byte("rules: []"), []string{"app/.semgrepignore"})
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(src, "app", ".semgrepignore")); string(b) != "*\n" {
		t.Fatalf("the vendor's .semgrepignore was changed: %q", b)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "src", "app", ".semgrepignore")); err != nil || len(b) != 0 {
		t.Fatalf("not blanked in the scan tree: %q, %v", b, err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "src", "app", "main.go")); string(b) != "package main\n" {
		t.Fatalf("main.go: %q", b)
	}
	if _, err := os.Stat(filepath.Join(dir, "src", "otrust-out")); err == nil {
		t.Fatal("excluded path was copied")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, localRules)); string(b) != "rules: []" {
		t.Fatal("rules file missing")
	}
}
