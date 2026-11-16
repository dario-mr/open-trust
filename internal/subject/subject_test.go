package subject

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type layout struct {
	t     *testing.T
	files map[string][]byte
}

func (l *layout) blob(v any) string {
	b, ok := v.([]byte)
	if !ok {
		b, _ = json.Marshal(v)
	}
	sum := sha256.Sum256(b)
	h := hex.EncodeToString(sum[:])
	l.files["blobs/sha256/"+h] = b
	return "sha256:" + h
}

func (l *layout) writeDir() string {
	dir := l.t.TempDir()
	for name, b := range l.files {
		p := filepath.Join(dir, name)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, b, 0o644); err != nil {
			l.t.Fatal(err)
		}
	}
	return dir
}

func (l *layout) writeTar() string {
	p := filepath.Join(l.t.TempDir(), "img.tar")
	f, _ := os.Create(p)
	tw := tar.NewWriter(f)
	for name, b := range l.files {
		tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(b))})
		tw.Write(b)
	}
	tw.Close()
	f.Close()
	return p
}

func (l *layout) size(d string) int {
	return len(l.files["blobs/sha256/"+strings.TrimPrefix(d, "sha256:")])
}

// d is a complete descriptor (registries need mediaType and size, not only the digest).
func (l *layout) d(mt, digest string, extra map[string]any) map[string]any {
	m := map[string]any{"mediaType": mt, "digest": digest, "size": l.size(digest)}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

// buildkitLike mirrors what `buildx --output type=oci --provenance=mode=min` produced in practice.
func buildkitLike(t *testing.T) (*layout, string) {
	l := &layout{t: t, files: map[string][]byte{}}
	cfg := l.blob([]byte(`{"architecture":"arm64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}`))
	layer := l.blob([]byte("pretend this is a gzipped layer"))
	img := l.blob(map[string]any{"schemaVersion": 2, "mediaType": mtManifest,
		"config": l.d("application/vnd.oci.image.config.v1+json", cfg, nil),
		"layers": []any{l.d("application/vnd.oci.image.layer.v1.tar+gzip", layer, nil)},
	})
	prov := l.blob([]byte(`{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"https://slsa.dev/provenance/v0.2","subject":[]}`))
	attCfg := l.blob([]byte(`{"architecture":"unknown","os":"unknown","rootfs":{"type":"layers","diff_ids":[]}}`))
	att := l.blob(map[string]any{"schemaVersion": 2, "mediaType": mtManifest,
		"config": l.d("application/vnd.oci.image.config.v1+json", attCfg, nil),
		"layers": []any{l.d(mtInToto, prov, map[string]any{"annotations": map[string]string{annPredicate: "https://slsa.dev/provenance/v0.2"}})},
	})
	inner := l.blob(map[string]any{"schemaVersion": 2, "mediaType": mtIndex, "manifests": []any{
		l.d(mtManifest, img, map[string]any{"platform": map[string]string{"os": "linux", "architecture": "arm64"}}),
		l.d(mtManifest, att, map[string]any{"annotations": map[string]string{annRefType: "attestation-manifest", annRefDigest: img}}),
	}})
	l.files["index.json"], _ = json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": mtIndex, "manifests": []any{
		l.d(mtIndex, inner, nil),
	}})
	return l, img
}

func TestResolveDirAndTarWithProvenance(t *testing.T) {
	l, img := buildkitLike(t)
	for _, p := range []string{l.writeDir(), l.writeTar()} {
		s, err := Resolve(p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if s.Digest != img {
			t.Errorf("digest = %s, want %s", s.Digest, img)
		}
		if s.ProvenancePredicate != "https://slsa.dev/provenance/v0.2" || len(s.Provenance) == 0 {
			t.Errorf("provenance not found: %q", s.ProvenancePredicate)
		}
	}
}

func TestResolvePlainManifestNoProvenance(t *testing.T) {
	l := &layout{t: t, files: map[string][]byte{}}
	img := l.blob(map[string]any{"schemaVersion": 2})
	l.files["index.json"], _ = json.Marshal(map[string]any{"manifests": []any{map[string]any{"mediaType": mtManifest, "digest": img}}})
	s, err := Resolve(l.writeDir())
	if err != nil || s.Digest != img || s.Provenance != nil {
		t.Fatalf("got %+v, %v", s, err)
	}
}

func TestResolveRejectsEveryTamperedBlob(t *testing.T) {
	base, _ := buildkitLike(t)
	n := 0
	for name := range base.files {
		if name == "index.json" {
			continue
		}
		n++
		for _, tarred := range []bool{false, true} {
			l := &layout{t: t, files: map[string][]byte{}}
			for k, v := range base.files {
				l.files[k] = v
			}
			l.files[name] = append(append([]byte{}, l.files[name]...), ' ')
			p := l.writeDir()
			if tarred {
				p = l.writeTar()
			}
			if _, err := Resolve(p); err == nil || !strings.Contains(err.Error(), "does not match") {
				t.Errorf("tampered %s (tar=%v): want digest mismatch, got %v", name, tarred, err)
			}
		}
	}
	if n != 7 { // config, layer, image manifest, provenance, attestation config + manifest, inner index
		t.Fatalf("expected 7 blobs, got %d", n)
	}
}

func TestResolveRejectsMultiPlatform(t *testing.T) {
	l := &layout{t: t, files: map[string][]byte{}}
	a := l.blob(map[string]any{"schemaVersion": 2, "a": 1})
	b := l.blob(map[string]any{"schemaVersion": 2, "b": 1})
	l.files["index.json"], _ = json.Marshal(map[string]any{"manifests": []any{
		map[string]any{"mediaType": mtManifest, "digest": a, "platform": map[string]string{"os": "linux", "architecture": "amd64"}},
		map[string]any{"mediaType": mtManifest, "digest": b, "platform": map[string]string{"os": "linux", "architecture": "arm64"}},
	}})
	if _, err := Resolve(l.writeDir()); err == nil || !strings.Contains(err.Error(), "expected one") {
		t.Fatalf("want multi-platform error, got %v", err)
	}
}
