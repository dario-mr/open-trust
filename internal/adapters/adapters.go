// Package adapters runs the profile's pinned scanners and returns their raw JSON output.
// Invocations match profiles/supply-chain-baseline/v1/fixtures/generate.sh.
package adapters

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

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
	// ExcludeRel is a path under SourceDir (e.g. the evidence output dir) that scanners must skip.
	ExcludeRel string
}

type Evidence struct {
	SBOM     json.RawMessage
	Vulns    json.RawMessage
	Secrets  json.RawMessage
	SAST     json.RawMessage
	TrivyDB  json.RawMessage // `trivy version` output: vuln DB version + update time (not in scan JSON)
	Commands map[string][]string
}

func (r *Runner) docker(ctx context.Context, image string, okExit []int, args ...string) ([]byte, []string, error) {
	base := []string{"run", "--rm", "--platform", "linux/" + runtime.GOARCH,
		"-v", r.SourceDir + ":/src:ro",
		"-v", r.WorkDir + ":/work",
		"-v", r.Subject + ":/subject:ro",
		"-v", r.CacheVol + ":/cache",
		"-e", "TRIVY_CACHE_DIR=/cache/trivy",
		"-e", "SEMGREP_SEND_METRICS=off",
		image}
	full := append(base, args...)
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

// Run executes all scanners. It writes the SBOM into WorkDir because trivy scans that file.
func (r *Runner) Run(ctx context.Context, syftScheme string) (*Evidence, error) {
	ev := &Evidence{Commands: map[string][]string{}}
	var err error
	step := func(name string, out *json.RawMessage, image string, okExit []int, args ...string) {
		if err != nil {
			return
		}
		var cmd []string
		*out, cmd, err = r.docker(ctx, image, okExit, args...)
		ev.Commands[name] = cmd
	}

	step("sbom", &ev.SBOM, r.Tools.Syft.Image, nil,
		"scan", syftScheme+":/subject", "-o", "cyclonedx-json", "-q")
	if err == nil {
		err = os.WriteFile(filepath.Join(r.WorkDir, "sbom.cdx.json"), ev.SBOM, 0o644)
	}
	step("vulns", &ev.Vulns, r.Tools.Trivy.Image, nil,
		"sbom", "--quiet", "--format", "json", "/work/sbom.cdx.json")
	step("trivy-db", &ev.TrivyDB, r.Tools.Trivy.Image, nil,
		"version", "--format", "json")
	secretArgs := []string{"fs", "--quiet", "--scanners", "secret", "--format", "json"}
	sastArgs := []string{"semgrep", "scan", "--metrics=off", "--quiet", "--json", "--config", r.Tools.Semgrep.Config}
	if r.ExcludeRel != "" {
		secretArgs = append(secretArgs, "--skip-dirs", "/src/"+filepath.ToSlash(r.ExcludeRel))
		sastArgs = append(sastArgs, "--exclude", filepath.ToSlash(r.ExcludeRel))
	}
	step("secrets", &ev.Secrets, r.Tools.Trivy.Image, nil, append(secretArgs, "/src")...)
	// semgrep exits 1 when it has findings: a result, not an error
	step("sast", &ev.SAST, r.Tools.Semgrep.Image, []int{1}, append(sastArgs, "/src")...)
	return ev, err
}
