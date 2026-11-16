package verify

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	ocilayout "github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// pushLayout pushes the single image of an OCI layout dir and returns its digest reference.
func pushLayout(t *testing.T, srv *httptest.Server, dir, repo string) string {
	t.Helper()
	ii, err := ocilayout.ImageIndexFromPath(dir)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := ii.IndexManifest()
	img, err := ii.Image(m.Manifests[0].Digest)
	if err != nil {
		t.Fatal(err)
	}
	ref := strings.TrimPrefix(srv.URL, "http://") + "/" + repo
	tag, _ := name.NewTag(ref + ":latest")
	if err := remote.Write(tag, img); err != nil {
		t.Fatal(err)
	}
	var d v1.Hash
	if d, err = img.Digest(); err != nil {
		t.Fatal(err)
	}
	return ref + "@" + d.String()
}

func TestVerifyRegistryReference(t *testing.T) {
	srv := httptest.NewServer(registry.New())
	defer srv.Close()
	c := newCert(t, "clean", nil)
	c.opts.Image = pushLayout(t, srv, c.image, "acme/svc")
	expect(t, run(t, c.opts), OK, "")

	other, _ := writeImage(t, "a different image")
	c.opts.Image = pushLayout(t, srv, other, "acme/other")
	expect(t, run(t, c.opts), ArtifactMismatch, "certificate is for")

	c.opts.Image = strings.TrimPrefix(srv.URL, "http://") + "/acme/svc:latest"
	expect(t, run(t, c.opts), ArtifactMismatch, "pinned by digest")
}
