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

// Runner executes the pinned tools: as docker images, or with Local set as host binaries.
type Runner struct {
	Tools     scb.Tools
	SourceDir string // mounted read-only at /src
	WorkDir   string // mounted at /work; must be visible to the docker daemon (e.g. under $HOME on Colima)
	Subject   string // OCI layout dir or tar, mounted read-only at /subject
	CacheVol  string // named volume for scanner DBs
	// Exclude lists paths under SourceDir that are not source (the evidence dir, an image tar) and
	// that scanners must skip. Directories and files are both allowed.
	Exclude []string
	Local   *Local // nil: docker
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
	if errors.Is(err, exec.ErrNotFound) {
		return nil, full, errors.New("docker not found: install docker, or run the scanners without it with --scanners local")
	}
	if err != nil {
		return nil, full, fmt.Errorf("%s: %w\n%s", image, err, tail(errb.Bytes(), 2000))
	}
	if !json.Valid(out.Bytes()) {
		return nil, full, fmt.Errorf("%s: output is not JSON\n%s", image, tail(out.Bytes(), 500))
	}
	return out.Bytes(), full, nil
}

// local runs a host binary in dir. Each step's dir keeps the host's own paths (home directory)
// out of the evidence: tools see relative names, as they see /src and /work in docker.
func (r *Runner) local(ctx context.Context, bin string, okExit []int, dir string, args ...string) ([]byte, []string, error) {
	full := append([]string{bin}, args...)
	var out, errb bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "TRIVY_CACHE_DIR="+filepath.Join(r.Local.Cache, "trivy"),
		"SEMGREP_SEND_METRICS=off", "SEMGREP_ENABLE_VERSION_CHECK=0")
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) && slices.Contains(okExit, ee.ExitCode()) {
		err = nil
	}
	if err != nil {
		return nil, full, fmt.Errorf("%s: %w\n%s", filepath.Base(bin), err, tail(errb.Bytes(), 2000))
	}
	if !json.Valid(out.Bytes()) {
		return nil, full, fmt.Errorf("%s: output is not JSON\n%s", filepath.Base(bin), tail(out.Bytes(), 500))
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
	// step runs one scanner: as its docker image with container paths, or locally in dir with
	// paths relative to it (local == nil means the same arguments)
	step := func(name string, out *json.RawMessage, image, bin, dir string, docker, local []string) {
		if err != nil {
			return
		}
		var cmd []string
		if r.Local == nil {
			*out, cmd, err = r.docker(ctx, image, nil, nil, docker...)
		} else {
			if local == nil {
				local = docker
			}
			*out, cmd, err = r.local(ctx, bin, nil, dir, local...)
		}
		ev.Commands[name] = cmd
	}
	var syft, trivy string
	if r.Local != nil {
		syft, trivy = r.Local.Syft, r.Local.Trivy
	}
	sbomArgs := func(subject string) []string {
		return []string{"scan", syftScheme + ":" + subject, "-o", "cyclonedx-json", "-q"}
	}
	step("sbom", &ev.SBOM, r.Tools.Syft.Image, syft, filepath.Dir(r.Subject), sbomArgs("/subject"), sbomArgs(filepath.Base(r.Subject)))
	if err == nil {
		err = os.WriteFile(filepath.Join(r.WorkDir, "sbom.cdx.json"), ev.SBOM, 0o644)
	}
	vulnArgs := func(sbom string) []string { return []string{"sbom", "--quiet", "--format", "json", sbom} }
	step("vulns", &ev.Vulns, r.Tools.Trivy.Image, trivy, r.WorkDir, vulnArgs("/work/sbom.cdx.json"), vulnArgs("sbom.cdx.json"))
	step("trivy-db", &ev.TrivyDB, r.Tools.Trivy.Image, trivy, r.WorkDir, []string{"version", "--format", "json"}, nil)
	return ev, err
}

// Run executes all scanners.
func (r *Runner) Run(ctx context.Context, syftScheme string) (*Evidence, error) {
	ev, err := r.ScanImage(ctx, syftScheme)
	if err != nil {
		return ev, err
	}
	var mounts []string // per-step extra mounts; only the SAST step sets them
	step := func(name string, out *json.RawMessage, image, bin, dir string, okExit []int, docker, local []string) {
		if err != nil {
			return
		}
		var cmd []string
		if r.Local == nil {
			*out, cmd, err = r.docker(ctx, image, okExit, mounts, docker...)
		} else {
			*out, cmd, err = r.local(ctx, bin, okExit, dir, local...)
		}
		ev.Commands[name] = cmd
	}
	var trivy, semgrep string
	if r.Local != nil {
		trivy, semgrep = r.Local.Trivy, r.Local.Semgrep
	}

	// --offline-scan: a secrets scan must not resolve dependencies over the network (leaks names; rate limits)
	secretArgs := []string{"fs", "--quiet", "--offline-scan", "--scanners", "secret", "--format", "json"}
	localSecretArgs := slices.Clone(secretArgs)
	sastArgs := []string{"scan", "--metrics=off", "--quiet", "--json", "--config"}
	var excludes []string
	for _, rel := range r.Exclude {
		flag := "--skip-files"
		if fi, statErr := os.Stat(filepath.Join(r.SourceDir, rel)); statErr == nil && fi.IsDir() {
			flag = "--skip-dirs"
		}
		secretArgs = append(secretArgs, flag, "/src/"+filepath.ToSlash(rel))
		localSecretArgs = append(localSecretArgs, flag, filepath.ToSlash(rel))
		excludes = append(excludes, "--exclude", filepath.ToSlash(rel))
	}
	step("secrets", &ev.Secrets, r.Tools.Trivy.Image, trivy, r.SourceDir, nil, append(secretArgs, "/src"), append(localSecretArgs, "."))

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
	var rules []byte
	if err == nil {
		if rules, ev.SemgrepRuleset, err = fetchRuleset(ctx, r.Tools.Semgrep.Config); err == nil && r.Local == nil {
			path := filepath.Join(r.WorkDir, rulesFile)
			err = os.WriteFile(path, rules, 0o644)
			defer os.Remove(path)
			mounts = append(mounts, path+":"+rulesMount+":ro")
		}
	}
	sastDir := ""
	if err == nil && r.Local != nil {
		sastDir, err = r.localSASTDir(rules, ev.NeutralizedIgnores)
		defer os.RemoveAll(sastDir)
	}
	// semgrep exits 1 when it has findings: a result, not an error. Locally the rules file sits in
	// semgrep's working directory, so rule IDs carry no directory prefix, as at the container root.
	step("sast", &ev.SAST, r.Tools.Semgrep.Image, semgrep, sastDir, []int{1},
		append(append(append([]string{"semgrep"}, sastArgs...), rulesMount), append(excludes, "/src")...),
		append(append(sastArgs, localRules), append(excludes, "src")...))
	return ev, err
}

const localRules = "otrust-semgrep-rules.yaml"

// localSASTDir prepares semgrep's working directory: the rules file, and src, the source tree as hard
// links (semgrep refuses a symlinked root, and an absolute path would put the host's home directory
// into the findings), with the vendor's .semgrepignore files replaced by empty ones (docker mode
// overlays an empty file instead; the vendor's tree is never modified).
func (r *Runner) localSASTDir(rules []byte, blank []string) (string, error) {
	dir, err := os.MkdirTemp(r.WorkDir, ".otrust-sast-")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, localRules), rules, 0o644); err != nil {
		return dir, err
	}
	src := filepath.Join(dir, "src")
	if err := linkTree(r.SourceDir, src, r.Exclude); err != nil {
		return dir, err
	}
	for _, rel := range blank {
		p := filepath.Join(src, rel)
		// remove the hard link first: writing through it would empty the vendor's own file
		if err := errors.Join(os.Remove(p), os.WriteFile(p, nil, 0o644)); err != nil {
			return dir, err
		}
	}
	return dir, nil
}

// linkTree recreates a tree with hard links to its regular files (a copy where linking fails, e.g.
// across file systems), directories and symlinks, skipping exclude, which may hold the destination
// itself (an evidence dir inside the source tree).
func linkTree(from, to string, exclude []string) error {
	return filepath.WalkDir(from, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(from, p)
		if rel != "." && slices.Contains(exclude, rel) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		dst := filepath.Join(to, rel)
		switch {
		case d.IsDir():
			return os.MkdirAll(dst, 0o755)
		case d.Type()&os.ModeSymlink != 0:
			t, err := os.Readlink(p)
			if err != nil {
				return err
			}
			return os.Symlink(t, dst)
		case d.Type().IsRegular():
			if os.Link(p, dst) == nil {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			fi, _ := d.Info()
			return os.WriteFile(dst, b, fi.Mode().Perm())
		}
		return nil // sockets, devices: not source
	})
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
