package subject

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// CertificateArtifactType marks an Open Trust certificate attached to an image as an OCI referrer.
// Its single layer is the Sigstore bundle.
const CertificateArtifactType = "application/vnd.dev.open-trust.certificate.v1+json"

const bundleMediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"

// Attached is a certificate found on a registry image.
type Attached struct {
	Digest  string // the referrer manifest's digest
	Created string
	Bundle  []byte
}

func remoteOpts(ctx context.Context) []remote.Option {
	return []remote.Option{remote.WithContext(ctx), remote.WithAuthFromKeychain(authn.DefaultKeychain)}
}

// Attach pushes a certificate bundle to the repository of ref, as a referrer of the image manifest
// manifestDigest (the certificate's subject). Registries without the referrers API get the
// standard fallback tag. It returns the referrer's digest.
func Attach(ctx context.Context, ref, manifestDigest string, bundle []byte, annotations map[string]string) (string, error) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return "", err
	}
	target := r.Context().Digest(manifestDigest)
	head, err := remote.Head(target, remoteOpts(ctx)...)
	if err != nil {
		return "", fmt.Errorf("attach: %s: %w", target, err)
	}
	a := map[string]string{"org.opencontainers.image.created": time.Now().UTC().Format(time.RFC3339)}
	for k, v := range annotations {
		a[k] = v
	}
	img, err := newArtifact(bundle, a, v1.Descriptor{MediaType: head.MediaType, Size: head.Size, Digest: head.Digest})
	if err != nil {
		return "", err
	}
	d, err := img.Digest()
	if err != nil {
		return "", err
	}
	if err := remote.Write(r.Context().Digest(d.String()), img, remoteOpts(ctx)...); err != nil {
		return "", fmt.Errorf("attach: push to %s: %w", r.Context(), err)
	}
	return d.String(), nil
}

// FindCertificates returns the Open Trust certificates attached to a registry image pinned by
// digest, newest first. A digest of an index (BuildKit image + attestation manifest) is searched
// together with its image manifests, which certificates name as their subject.
func FindCertificates(ctx context.Context, ref string) ([]Attached, error) {
	d, err := name.NewDigest(ref)
	if err != nil {
		return nil, fmt.Errorf("%q: a registry image must be pinned by digest (name@sha256:…): %w", ref, err)
	}
	opts := remoteOpts(ctx)
	digests := []string{d.DigestStr()}
	desc, err := remote.Get(d, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ref, err)
	}
	if desc.MediaType.IsIndex() {
		idx, err := desc.ImageIndex()
		if err != nil {
			return nil, err
		}
		m, err := idx.IndexManifest()
		if err != nil {
			return nil, err
		}
		for _, c := range m.Manifests {
			if c.MediaType.IsImage() && c.Annotations["vnd.docker.reference.type"] != "attestation-manifest" {
				digests = append(digests, c.Digest.String())
			}
		}
	}
	var found []Attached
	for _, dg := range digests {
		idx, err := remote.Referrers(d.Context().Digest(dg), opts...)
		if err != nil {
			return nil, fmt.Errorf("referrers of %s: %w", dg, err)
		}
		m, err := idx.IndexManifest()
		if err != nil {
			return nil, err
		}
		for _, c := range m.Manifests {
			if c.ArtifactType != CertificateArtifactType {
				continue
			}
			img, err := remote.Image(d.Context().Digest(c.Digest.String()), opts...)
			if err != nil {
				return nil, err
			}
			layers, err := img.Layers()
			if err != nil || len(layers) != 1 {
				return nil, fmt.Errorf("certificate %s: want one layer", c.Digest)
			}
			rc, err := layers[0].Uncompressed()
			if err != nil {
				return nil, err
			}
			b, err := io.ReadAll(io.LimitReader(rc, 4<<20))
			rc.Close()
			if err != nil {
				return nil, err
			}
			found = append(found, Attached{Digest: c.Digest.String(), Created: c.Annotations["org.opencontainers.image.created"], Bundle: b})
		}
	}
	sort.SliceStable(found, func(i, j int) bool { return found[i].Created > found[j].Created })
	return found, nil
}

// artifact is an OCI 1.1 artifact manifest: artifactType set, an empty "{}" config, the bundle as its
// one layer, and a subject. Registries that check config media types (GitLab) accept this form.
type artifact struct {
	v1.Image // the bundle layer
	raw      []byte
	manifest *v1.Manifest
}

var emptyConfig = []byte("{}")

func newArtifact(bundle []byte, annotations map[string]string, subject v1.Descriptor) (*artifact, error) {
	base, err := mutate.Append(empty.Image, mutate.Addendum{Layer: static.NewLayer(bundle, bundleMediaType)})
	if err != nil {
		return nil, err
	}
	layers, err := base.Layers()
	if err != nil {
		return nil, err
	}
	ld, err := partial.Descriptor(layers[0])
	if err != nil {
		return nil, err
	}
	ch, _, err := v1.SHA256(bytes.NewReader(emptyConfig))
	if err != nil {
		return nil, err
	}
	m := &v1.Manifest{
		SchemaVersion: 2, MediaType: types.OCIManifestSchema1, ArtifactType: CertificateArtifactType,
		Config:      v1.Descriptor{MediaType: types.OCIEmptyJSON, Size: int64(len(emptyConfig)), Digest: ch},
		Layers:      []v1.Descriptor{*ld},
		Annotations: annotations, Subject: &subject,
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return &artifact{Image: base, raw: raw, manifest: m}, nil
}

func (a *artifact) MediaType() (types.MediaType, error) { return types.OCIManifestSchema1, nil }
func (a *artifact) RawManifest() ([]byte, error)        { return a.raw, nil }
func (a *artifact) Manifest() (*v1.Manifest, error)     { return a.manifest, nil }
func (a *artifact) Size() (int64, error)                { return int64(len(a.raw)), nil }
func (a *artifact) ArtifactType() (string, error)       { return CertificateArtifactType, nil }
func (a *artifact) RawConfigFile() ([]byte, error)      { return emptyConfig, nil }
func (a *artifact) ConfigName() (v1.Hash, error)        { return a.manifest.Config.Digest, nil }
func (a *artifact) Digest() (v1.Hash, error) {
	h, _, err := v1.SHA256(bytes.NewReader(a.raw))
	return h, err
}

// ConfigLayer makes remote.Write upload the "{}" config blob under its own media type.
func (a *artifact) ConfigLayer() (v1.Layer, error) {
	return static.NewLayer(emptyConfig, types.OCIEmptyJSON), nil
}
