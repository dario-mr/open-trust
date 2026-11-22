package adapters

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	scb "github.com/dario-mr/open-trust/profiles/supply-chain-baseline/v1"
)

// Local runs the scanners as host binaries instead of docker images. Syft and Trivy are the pinned
// release archives (tools.json "release", checked by sha256); Semgrep, which ships as a Python
// package rather than a binary, must be on PATH at exactly the pinned version.
type Local struct {
	Syft, Trivy string // extracted from the pinned archives
	Semgrep     string // from PATH; "" when not needed (verify --recheck)
	Cache       string // scanner DBs
}

// PrepareLocal fetches (or reuses from the cache) the pinned Syft and Trivy for this platform,
// and, with needSemgrep, finds Semgrep on PATH and checks its version.
func PrepareLocal(ctx context.Context, tools scb.Tools, needSemgrep bool) (*Local, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return nil, err
	}
	base = filepath.Join(base, "otrust")
	l := &Local{Cache: filepath.Join(base, "scanner-cache")}
	if l.Syft, err = fetchBinary(ctx, base, "syft", tools.Syft); err != nil {
		return nil, err
	}
	if l.Trivy, err = fetchBinary(ctx, base, "trivy", tools.Trivy); err != nil {
		return nil, err
	}
	if needSemgrep {
		if l.Semgrep, err = semgrepOnPath(ctx, tools.Semgrep.Version); err != nil {
			return nil, err
		}
	}
	return l, os.MkdirAll(l.Cache, 0o755)
}

func semgrepOnPath(ctx context.Context, want string) (string, error) {
	p, err := exec.LookPath("semgrep")
	if err != nil {
		return "", fmt.Errorf("--scanners local needs semgrep %s on PATH (e.g. `pipx install semgrep==%s` or `uv tool install semgrep==%s`)", want, want, want)
	}
	cmd := exec.CommandContext(ctx, p, "--version")
	cmd.Env = append(os.Environ(), "SEMGREP_ENABLE_VERSION_CHECK=0")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("semgrep --version: %w", err)
	}
	if got := strings.TrimSpace(string(out)); got != want {
		return "", fmt.Errorf("semgrep on PATH is %s, the profile pins %s (e.g. `pipx install --force semgrep==%s`)", got, want, want)
	}
	return p, nil
}

// fetchBinary returns the tool's binary from its pinned release archive for this platform. The
// archive is cached by its sha256 and re-hashed on every use, and the binary re-extracted from it,
// so a tampered cache fails instead of running.
func fetchBinary(ctx context.Context, base, name string, t scb.Tool) (string, error) {
	platform := runtime.GOOS + "/" + runtime.GOARCH
	a, ok := t.Release[platform]
	if !ok {
		return "", fmt.Errorf("no pinned %s %s release for %s: use --scanners docker", name, t.Version, platform)
	}
	archive := filepath.Join(base, "archives", a.SHA256+".tar.gz")
	b, err := os.ReadFile(archive)
	if err != nil || sha256hex(b) != a.SHA256 {
		if b, err = download(ctx, a.URL); err != nil {
			return "", fmt.Errorf("%s %s: %w", name, t.Version, err)
		}
		if got := sha256hex(b); got != a.SHA256 {
			return "", fmt.Errorf("%s: sha256 %s, pinned %s", a.URL, got, a.SHA256)
		}
		if err := os.MkdirAll(filepath.Dir(archive), 0o755); err != nil {
			return "", err
		}
		if err := os.WriteFile(archive, b, 0o644); err != nil {
			return "", err
		}
	}
	dir := filepath.Join(base, "bin", a.SHA256)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	bin := filepath.Join(dir, name)
	return bin, extract(b, name, bin)
}

func download(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := (&http.Client{Timeout: 5 * time.Minute}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 512<<20))
}

// extract writes the regular file called name at the archive's top level to dest.
func extract(archive []byte, name, dest string) error {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("archive has no %s", name)
		}
		if err != nil {
			return err
		}
		if h.Typeflag != tar.TypeReg || strings.TrimPrefix(h.Name, "./") != name {
			continue
		}
		tmp := dest + ".tmp"
		f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
		if err != nil {
			return err
		}
		_, err = io.Copy(f, io.LimitReader(tr, 1<<30))
		if err := errors.Join(err, f.Close()); err != nil {
			return err
		}
		return os.Rename(tmp, dest)
	}
}

func sha256hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
