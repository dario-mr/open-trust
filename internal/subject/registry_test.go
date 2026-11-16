package subject

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	ocilayout "github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// push writes the BuildKit-like layout to an in-process registry and returns the repository and
// the pushed index digest.
func push(t *testing.T) (repo, indexDigest, img string) {
	t.Helper()
	srv := httptest.NewServer(registry.New())
	t.Cleanup(srv.Close)
	l, img := buildkitLike(t)
	ii, err := ocilayout.ImageIndexFromPath(l.writeDir())
	if err != nil {
		t.Fatal(err)
	}
	// index.json wraps the BuildKit index; push that inner index, as buildx --push would
	m, _ := ii.IndexManifest()
	inner, err := ii.ImageIndex(m.Manifests[0].Digest)
	if err != nil {
		t.Fatal(err)
	}
	repo = strings.TrimPrefix(srv.URL, "http://") + "/acme/svc"
	tag, _ := name.NewTag(repo + ":v1")
	if err := remote.WriteIndex(tag, inner); err != nil {
		t.Fatal(err)
	}
	d, _ := inner.Digest()
	return repo, d.String(), img
}

func TestPullByIndexDigestKeepsProvenance(t *testing.T) {
	repo, idx, img := push(t)
	ref := repo + "@" + idx
	if !IsRef(ref) {
		t.Fatalf("%s should be a registry reference", ref)
	}
	dir := t.TempDir()
	if err := Pull(context.Background(), ref, dir); err != nil {
		t.Fatal(err)
	}
	s, err := Resolve(dir)
	if err != nil {
		t.Fatal(err)
	}
	// the subject is the image manifest, as for an OCI tar of the same build
	if s.Digest != img || s.ProvenancePredicate == "" {
		t.Fatalf("digest %s (want %s), provenance %q", s.Digest, img, s.ProvenancePredicate)
	}
}

func TestPullByManifestDigest(t *testing.T) {
	repo, _, img := push(t)
	dir := t.TempDir()
	if err := Pull(context.Background(), repo+"@"+img, dir); err != nil {
		t.Fatal(err)
	}
	if s, err := Resolve(dir); err != nil || s.Digest != img {
		t.Fatalf("got %+v, %v", s, err)
	}
}

func TestPullRefusesTags(t *testing.T) {
	repo, _, _ := push(t)
	err := Pull(context.Background(), repo+":v1", t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "pinned by digest") {
		t.Fatalf("a tag can move; want refusal, got %v", err)
	}
}

func TestIsRef(t *testing.T) {
	for in, want := range map[string]bool{
		"ghcr.io/acme/svc@sha256:" + strings.Repeat("a", 64): true,
		"ghcr.io/acme/svc:v1":                                true,  // refused later by Pull, with a clear reason
		"image.oci.tar":                                      false, // a missing file stays a file error
		".":                                                  false, // an existing path
	} {
		if got := IsRef(in); got != want {
			t.Errorf("IsRef(%q) = %v, want %v", in, got, want)
		}
	}
}
