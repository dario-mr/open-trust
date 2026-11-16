package subject

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	ocilayout "github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// IsRef reports whether image names a registry image rather than a local OCI layout: not an
// existing path, has a tag or digest separator (so a mistyped file name stays a file error), and parses.
func IsRef(image string) bool {
	if _, err := os.Stat(image); err == nil || !strings.ContainsAny(image, "@:") {
		return false
	}
	_, err := name.ParseReference(image)
	return err == nil
}

// Pull copies a registry image, pinned by digest, into an OCI layout at dir, which Resolve then
// checks like any other layout (every blob against its digest). A digest of an index (e.g. BuildKit
// image + attestation manifest) keeps the attached provenance; a multi-platform index is refused by
// Resolve, so name the platform's manifest digest instead. Credentials come from the docker config.
func Pull(ctx context.Context, ref, dir string) error {
	// a tag can move; the certificate binds a digest, so the reference must be one
	d, err := name.NewDigest(ref)
	if err != nil {
		return fmt.Errorf("%q: a registry image must be pinned by digest (name@sha256:…): %w", ref, err)
	}
	opts := []remote.Option{remote.WithContext(ctx), remote.WithAuthFromKeychain(authn.DefaultKeychain)}
	desc, err := remote.Get(d, opts...)
	if err != nil {
		return fmt.Errorf("pull %s: %w", ref, err)
	}
	p, err := ocilayout.Write(dir, empty.Index)
	if err != nil {
		return err
	}
	if desc.MediaType.IsIndex() {
		idx, err := desc.ImageIndex()
		if err != nil {
			return err
		}
		err = p.AppendIndex(idx)
		if err != nil {
			return fmt.Errorf("pull %s: %w", ref, err)
		}
		return nil
	}
	img, err := desc.Image()
	if err != nil {
		return err
	}
	if err := p.AppendImage(img); err != nil {
		return fmt.Errorf("pull %s: %w", ref, err)
	}
	return nil
}
