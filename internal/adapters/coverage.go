package adapters

import (
	"encoding/json"
	"path"
	"sort"
	"strings"

	"github.com/dario-mr/open-trust/internal/policy"
)

// byExtension maps source file extensions to Semgrep language names. Data formats (YAML, JSON) and
// docs are left out: generic rules touch them, but nobody expects code analysis of them.
var byExtension = map[string]string{
	"go": "go", "java": "java", "kt": "kotlin", "kts": "kotlin", "py": "python",
	"js": "javascript", "jsx": "javascript", "mjs": "javascript", "cjs": "javascript",
	"ts": "typescript", "tsx": "typescript", "mts": "typescript", "cts": "typescript",
	"rb": "ruby", "php": "php", "cs": "csharp", "c": "c", "h": "c",
	"cpp": "cpp", "cc": "cpp", "cxx": "cpp", "hpp": "cpp", "hh": "cpp", "hxx": "cpp",
	"rs": "rust", "scala": "scala", "swift": "swift", "ex": "elixir", "exs": "elixir",
	"erl": "erlang", "hrl": "erlang", "clj": "clojure", "cljs": "clojure", "cljc": "clojure",
	"lua": "lua", "sol": "solidity", "tf": "hcl", "hcl": "hcl", "dart": "dart",
	"groovy": "groovy", "gradle": "groovy", "pl": "perl", "pm": "perl", "hs": "haskell",
	"ml": "ocaml", "mli": "ocaml", "sh": "bash", "bash": "bash",
}

// ruleLanguage folds the aliases Semgrep rules use (js, kt, C#, terraform, …) into byExtension's names.
func ruleLanguage(l string) string {
	l = strings.ToLower(l)
	if a, ok := map[string]string{"js": "javascript", "ts": "typescript", "py": "python", "rb": "ruby",
		"kt": "kotlin", "c#": "csharp", "sh": "bash", "terraform": "hcl", "docker": "dockerfile",
		"c++": "cpp", "ex": "elixir", "rs": "rust"}[l]; ok {
		return a
	}
	return l
}

func fileLanguage(p string) string {
	base := path.Base(p)
	if base == "Dockerfile" || strings.HasPrefix(base, "Dockerfile.") || strings.HasSuffix(base, ".Dockerfile") {
		return "dockerfile"
	}
	if i := strings.LastIndexByte(base, '.'); i >= 0 {
		return byExtension[strings.ToLower(base[i+1:])]
	}
	return ""
}

// SASTCoverage counts, per source language among the files Semgrep scanned, the files and the
// ruleset's rules for that language. A language with files and no rules was not analysed.
func SASTCoverage(semgrepJSON []byte, ruleLanguages map[string]int) []policy.LanguageCoverage {
	var out struct {
		Paths struct {
			Scanned []string `json:"scanned"`
		} `json:"paths"`
	}
	_ = json.Unmarshal(semgrepJSON, &out)
	files := map[string]int{}
	for _, p := range out.Paths.Scanned {
		if l := fileLanguage(p); l != "" {
			files[l]++
		}
	}
	cov := []policy.LanguageCoverage{}
	for l, n := range files {
		cov = append(cov, policy.LanguageCoverage{Language: l, Files: n, Rules: ruleLanguages[l]})
	}
	sort.Slice(cov, func(i, j int) bool { return cov[i].Language < cov[j].Language })
	return cov
}
