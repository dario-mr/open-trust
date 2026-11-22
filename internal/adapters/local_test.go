package adapters

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	scb "github.com/dario-mr/open-trust/profiles/supply-chain-baseline/v1"
)

// Real download of the pinned archives: OTRUST_E2E=1 go test ./internal/adapters -run Fetch
func TestFetchPinnedBinaries(t *testing.T) {
	if os.Getenv("OTRUST_E2E") == "" {
		t.Skip("set OTRUST_E2E=1 (downloads the pinned Syft and Trivy releases)")
	}
	tools, _ := scb.LoadTools()
	base := t.TempDir()
	for name, tool := range map[string]scb.Tool{"syft": tools.Syft, "trivy": tools.Trivy} {
		bin, err := fetchBinary(context.Background(), base, name, tool)
		if err != nil {
			t.Fatal(err)
		}
		if fi, err := os.Stat(bin); err != nil || fi.Mode()&0o111 == 0 {
			t.Fatalf("%s: %v", bin, err)
		}
		// a tampered cached archive is re-downloaded, never run
		a := tool.Release[runtime.GOOS+"/"+runtime.GOARCH]
		os.WriteFile(filepath.Join(base, "archives", a.SHA256+".tar.gz"), []byte("tampered"), 0o644)
		if _, err := fetchBinary(context.Background(), base, name, tool); err != nil {
			t.Fatalf("%s after tampering: %v", name, err)
		}
	}
	bad := tools.Syft
	bad.Release = map[string]scb.Asset{runtime.GOOS + "/" + runtime.GOARCH: {URL: bad.Release[runtime.GOOS+"/"+runtime.GOARCH].URL, SHA256: "00"}}
	if _, err := fetchBinary(context.Background(), t.TempDir(), "syft", bad); err == nil {
		t.Fatal("a download that doesn't match its pin must be refused")
	}
}

func TestEveryPinnedPlatform(t *testing.T) {
	tools, err := scb.LoadTools()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"linux/amd64", "linux/arm64", "darwin/amd64", "darwin/arm64"} {
		for name, tool := range map[string]scb.Tool{"syft": tools.Syft, "trivy": tools.Trivy} {
			if a := tool.Release[p]; a.URL == "" || len(a.SHA256) != 64 {
				t.Errorf("%s has no pinned release for %s", name, p)
			}
		}
	}
}
