// Package adapters runs the profile's pinned scanners and returns their raw JSON output.
// Invocations match profiles/supply-chain-baseline/v1/fixtures/generate.sh.
package adapters

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"time"

	"gopkg.in/yaml.v3"

	scb "github.com/dario-mr/open-trust/profiles/supply-chain-baseline/v1"
)

// Runner executes pinned tool images with docker.
// shortcut: docker only; CI runners without docker need a "pinned binary on PATH" mode (week 4).
type Runner struct {
	Tools     scb.Tools
	SourceDir string // mounted read-only at /src
	WorkDir   string // mounted at /work; must be visible to the docker daemon (e.g. under $HOME on Colima)
	Subject   string // OCI layout dir or tar, mounted read-only at /subject
	CacheVol  string // named volume for scanner DBs
	// Exclude lists paths under SourceDir that are not source (the evidence dir, an image tar) and
	// that scanners must skip. Directories and files are both allowed.
	Exclude []string
}

type Evidence struct {
	SBOM     json.RawMessage
	Vulns    json.RawMessage
	Secrets  json.RawMessage
	SAST     json.RawMessage
	TrivyDB  json.RawMessage // `trivy version` output: vuln DB version + update time (not in scan JSON)
	Commands map[string][]string
	// NeutralizedIgnores lists vendor .semgrepignore files that were blanked for the SAST scan.
	NeutralizedIgnores []string
	SemgrepRuleset     Ruleset
}

// SemgrepRegistry serves a ruleset such as p/default as one YAML document.
const SemgrepRegistry = "https://semgrep.dev/c/"

// Ruleset is the SAST ruleset exactly as fetched for this run. Semgrep's registry rules are current
// but may not be redistributed, so the certificate records their digest, not a copy, and the file
// is deleted after the scan.
type Ruleset struct {
	Source  string `json:"source"`
	URL     string `json:"url"`
	SHA256  string `json:"sha256"`
	Fetched string `json:"fetched"`
	Rules   int    `json:"rules"`
	// Languages counts the rules per language (aliases folded, see ruleLanguage); for SAST coverage.
	Languages map[string]int `json:"-"`
}

const rulesFile = ".otrust-semgrep-rules.yaml" // in WorkDir during the scan only

// rulesMount is where semgrep sees the ruleset. Semgrep prefixes rule IDs with the config file's
// directory, so the file must sit at the root: exception keys use the registry rule IDs.
const rulesMount = "/otrust-semgrep-rules.yaml"

func fetchRuleset(ctx context.Context, source string) ([]byte, Ruleset, error) {
	rs := Ruleset{Source: source, URL: SemgrepRegistry + source, Fetched: time.Now().UTC().Format(time.RFC3339)}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rs.URL, nil)
	if err != nil {
		return nil, rs, err
	}
	// the registry's CDN serves JSON to gzip clients and YAML otherwise; the digest must always be
	// over the same bytes, so ask for an uncompressed (YAML) response
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := (&http.Client{Timeout: time.Minute}).Do(req)
	if err != nil {
		return nil, rs, fmt.Errorf("semgrep ruleset: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, rs, fmt.Errorf("semgrep ruleset %s: %s", rs.URL, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, rs, err
	}
	var doc struct {
		Rules []struct {
			Languages []string `yaml:"languages"`
		} `yaml:"rules"`
	}
	if yaml.Unmarshal(b, &doc) != nil || len(doc.Rules) == 0 {
		return nil, rs, fmt.Errorf("semgrep ruleset %s: not a rules document", rs.URL)
	}
	rs.Rules = len(doc.Rules)
	rs.Languages = map[string]int{}
	for _, r := range doc.Rules {
		for _, l := range r.Languages {
			rs.Languages[ruleLanguage(l)]++
		}
	}
	sum := sha256.Sum256(b)
	rs.SHA256 = hex.EncodeToString(sum[:])
	return b, rs, nil
}

func (r *Runner) docker(ctx context.Context, image string, okExit []int, mounts []string, args ...string) ([]byte, []string, error) {
	base := []string{"run", "--rm", "--platform", "linux/" + runtime.GOARCH,
		"-v", r.SourceDir + ":/src:ro",
		"-v", r.WorkDir + ":/work",
		"-v", r.Subject + ":/subject:ro",
		"-v", r.CacheVol + ":/cache",
		"-e", "TRIVY_CACHE_DIR=/cache/trivy",
		"-e", "SEMGREP_SEND_METRICS=off"}
	for _, m := range mounts {
		base = append(base, "-v", m)
	}
	full := append(append(base, image), args...)
	var out, errb bytes.Buffer
	cmd := exec.CommandContext(ctx, "docker", full...)
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		for _, c := range okExit {
			if ee.ExitCode() == c {
				err = nil
			}
		}
	}
	if err != nil {
		return nil, full, fmt.Errorf("%s: %w\n%s", image, err, tail(errb.Bytes(), 2000))
	}
	if !json.Valid(out.Bytes()) {
		return nil, full, fmt.Errorf("%s: output is not JSON\n%s", image, tail(out.Bytes(), 500))
	}
	return out.Bytes(), full, nil
}

func tail(b []byte, n int) []byte {
	if len(b) > n {
		return b[len(b)-n:]
	}
	return b
}

// ScanImage runs only the image-based scanners (SBOM, vulnerabilities, trivy DB version). A buyer
// re-runs exactly these to re-check a certificate: they need the image, not the vendor's source.
// It writes the SBOM into WorkDir because trivy scans that file.
func (r *Runner) ScanImage(ctx context.Context, syftScheme string) (*Evidence, error) {
	ev := &Evidence{Commands: map[string][]string{}}
	var err error
	step := func(name string, out *json.RawMessage, image string, args ...string) {
		if err != nil {
			return
		}
		var cmd []string
		*out, cmd, err = r.docker(ctx, image, nil, nil, args...)
		ev.Commands[name] = cmd
	}
	step("sbom", &ev.SBOM, r.Tools.Syft.Image,
		"scan", syftScheme+":/subject", "-o", "cyclonedx-json", "-q")
	if err == nil {
		err = os.WriteFile(filepath.Join(r.WorkDir, "sbom.cdx.json"), ev.SBOM, 0o644)
	}
	step("vulns", &ev.Vulns, r.Tools.Trivy.Image,
		"sbom", "--quiet", "--format", "json", "/work/sbom.cdx.json")
	step("trivy-db", &ev.TrivyDB, r.Tools.Trivy.Image,
		"version", "--format", "json")
	return ev, err
}

// Run executes all scanners.
func (r *Runner) Run(ctx context.Context, syftScheme string) (*Evidence, error) {
	ev, err := r.ScanImage(ctx, syftScheme)
	if err != nil {
		return ev, err
	}
	var mounts []string // per-step extra mounts; only the SAST step sets them
	step := func(name string, out *json.RawMessage, image string, okExit []int, args ...string) {
		if err != nil {
			return
		}
		var cmd []string
		*out, cmd, err = r.docker(ctx, image, okExit, mounts, args...)
		ev.Commands[name] = cmd
	}

	// --offline-scan: a secrets scan must not resolve dependencies over the network (leaks names; rate limits)
	secretArgs := []string{"fs", "--quiet", "--offline-scan", "--scanners", "secret", "--format", "json"}
	sastArgs := []string{"semgrep", "scan", "--metrics=off", "--quiet", "--json", "--config", rulesMount}
	for _, rel := range r.Exclude {
		flag := "--skip-files"
		if fi, statErr := os.Stat(filepath.Join(r.SourceDir, rel)); statErr == nil && fi.IsDir() {
			flag = "--skip-dirs"
		}
		secretArgs = append(secretArgs, flag, "/src/"+filepath.ToSlash(rel))
		sastArgs = append(sastArgs, "--exclude", filepath.ToSlash(rel))
	}
	step("secrets", &ev.Secrets, r.Tools.Trivy.Image, nil, append(secretArgs, "/src")...)

	// A vendor .semgrepignore (at any depth) can exclude every file from SAST, so the profile's
	// SAST claim would be empty. Blank each one with a read-only empty file over it; the vendor's
	// tree itself is mounted read-only and left untouched.
	if err == nil {
		var empty string
		if ev.NeutralizedIgnores, err = findSemgrepIgnores(r.SourceDir, r.Exclude); err == nil && len(ev.NeutralizedIgnores) > 0 {
			empty = filepath.Join(r.WorkDir, ".otrust-empty-ignore")
			err = os.WriteFile(empty, nil, 0o644)
			for _, rel := range ev.NeutralizedIgnores {
				mounts = append(mounts, empty+":/src/"+filepath.ToSlash(rel)+":ro")
			}
		}
	}
	if err == nil {
		var rules []byte
		if rules, ev.SemgrepRuleset, err = fetchRuleset(ctx, r.Tools.Semgrep.Config); err == nil {
			path := filepath.Join(r.WorkDir, rulesFile)
			err = os.WriteFile(path, rules, 0o644)
			defer os.Remove(path)
			mounts = append(mounts, path+":"+rulesMount+":ro")
		}
	}
	// semgrep exits 1 when it has findings: a result, not an error
	step("sast", &ev.SAST, r.Tools.Semgrep.Image, []int{1}, append(sastArgs, "/src")...)
	return ev, err
}

func findSemgrepIgnores(root string, exclude []string) ([]string, error) {
	var found []string
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		if d.IsDir() && (d.Name() == ".git" || slices.Contains(exclude, rel)) {
			return filepath.SkipDir
		}
		if !d.IsDir() && d.Name() == ".semgrepignore" {
			found = append(found, rel)
		}
		return nil
	})
	return found, err
}
