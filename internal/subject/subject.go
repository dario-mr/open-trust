// Package subject resolves the assessed artifact: an OCI image layout (directory or tar) →
// the image manifest digest the certificate binds to, plus any BuildKit provenance attached to it.
package subject

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	mtIndex       = "application/vnd.oci.image.index.v1+json"
	mtManifest    = "application/vnd.oci.image.manifest.v1+json"
	mtDockerList  = "application/vnd.docker.distribution.manifest.list.v2+json"
	mtDockerImage = "application/vnd.docker.distribution.manifest.v2+json"
	mtInToto      = "application/vnd.in-toto+json"
	annRefType    = "vnd.docker.reference.type"
	annRefDigest  = "vnd.docker.reference.digest"
	annPredicate  = "in-toto.io/predicate-type"
)

type Subject struct {
	Path   string // OCI layout dir or tar
	IsTar  bool
	Digest string // "sha256:…" of the image manifest

	// Provenance found attached to the image (BuildKit attestation manifest); nil if none.
	Provenance          []byte
	ProvenancePredicate string
}

// SyftSource is the syft source scheme for this layout.
func (s *Subject) SyftSource() string {
	if s.IsTar {
		return "oci-archive"
	}
	return "oci-dir"
}

type descriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Platform    *platform         `json:"platform,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

type platform struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
}

type manifestList struct {
	MediaType string       `json:"mediaType"`
	Manifests []descriptor `json:"manifests"`
}

type imageManifest struct {
	Config descriptor   `json:"config"`
	Layers []descriptor `json:"layers"`
}

// Resolve reads an OCI layout. It requires exactly one (non-attestation) image manifest.
func Resolve(path string) (*Subject, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	s := &Subject{Path: path, IsTar: !fi.IsDir()}
	open := s.opener()
	read := func(name string) ([]byte, error) {
		rc, size, err := open(name)
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		if size > maxMetaBlob {
			return nil, fmt.Errorf("%s is too large (%d bytes)", name, size)
		}
		return io.ReadAll(rc)
	}

	raw, err := read("index.json")
	if err != nil {
		return nil, fmt.Errorf("not an OCI layout (%s): %w", path, err)
	}
	images, attestations, err := walk(read, raw, 0)
	if err != nil {
		return nil, err
	}
	switch len(images) {
	case 0:
		return nil, errors.New("OCI layout contains no image manifest")
	case 1:
	default:
		// shortcut: multi-platform layouts need a --platform selector; add when a real build needs it
		var ps []string
		for _, d := range images {
			ps = append(ps, fmt.Sprintf("%s (%s/%s)", d.Digest, d.Platform.OS, d.Platform.Architecture))
		}
		return nil, fmt.Errorf("OCI layout has %d image manifests, expected one: %s", len(images), strings.Join(ps, ", "))
	}
	s.Digest = images[0].Digest

	// The scanners read this layout, so every blob of the image must match the digest we bind to.
	mraw, err := readBlob(read, s.Digest)
	if err != nil {
		return nil, err
	}
	var m imageManifest
	if err := json.Unmarshal(mraw, &m); err != nil {
		return nil, fmt.Errorf("image manifest %s: %w", s.Digest, err)
	}
	for _, d := range append([]descriptor{m.Config}, m.Layers...) {
		if d.Digest == "" {
			continue
		}
		if err := verifyBlob(open, d.Digest); err != nil {
			return nil, err
		}
	}

	for _, a := range attestations {
		if a.Annotations[annRefDigest] != s.Digest {
			continue
		}
		mraw, err := readBlob(read, a.Digest)
		if err != nil {
			return nil, err
		}
		var m imageManifest
		if err := json.Unmarshal(mraw, &m); err != nil {
			return nil, fmt.Errorf("attestation manifest %s: %w", a.Digest, err)
		}
		if m.Config.Digest != "" {
			if err := verifyBlob(open, m.Config.Digest); err != nil {
				return nil, err
			}
		}
		for _, l := range m.Layers {
			pt := l.Annotations[annPredicate]
			if l.MediaType == mtInToto && strings.HasPrefix(pt, "https://slsa.dev/provenance/") {
				if s.Provenance, err = readBlob(read, l.Digest); err != nil {
					return nil, err
				}
				s.ProvenancePredicate = pt
			}
		}
	}
	return s, nil
}

// walk flattens nested indexes into image manifests and attestation manifests.
func walk(read func(string) ([]byte, error), raw []byte, depth int) (images, attestations []descriptor, err error) {
	if depth > 4 {
		return nil, nil, errors.New("OCI index nesting too deep")
	}
	var idx manifestList
	if err := json.Unmarshal(raw, &idx); err != nil {
		return nil, nil, fmt.Errorf("parse index: %w", err)
	}
	for _, d := range idx.Manifests {
		switch d.MediaType {
		case mtIndex, mtDockerList:
			child, err := readBlob(read, d.Digest)
			if err != nil {
				return nil, nil, err
			}
			i, a, err := walk(read, child, depth+1)
			if err != nil {
				return nil, nil, err
			}
			images, attestations = append(images, i...), append(attestations, a...)
		case mtManifest, mtDockerImage:
			if d.Annotations[annRefType] == "attestation-manifest" {
				attestations = append(attestations, d)
			} else {
				images = append(images, d)
			}
		}
	}
	return images, attestations, nil
}

func blobPath(digest string) (path, hexd string, err error) {
	hexd, ok := strings.CutPrefix(digest, "sha256:")
	if !ok || len(hexd) != 64 {
		return "", "", fmt.Errorf("unsupported digest %q", digest)
	}
	return "blobs/sha256/" + hexd, hexd, nil
}

// readBlob reads a small content-addressed blob and verifies its digest (trust nothing in the layout).
func readBlob(read func(string) ([]byte, error), digest string) ([]byte, error) {
	p, hexd, err := blobPath(digest)
	if err != nil {
		return nil, err
	}
	b, err := read(p)
	if err != nil {
		return nil, err
	}
	if sum := sha256.Sum256(b); hex.EncodeToString(sum[:]) != hexd {
		return nil, fmt.Errorf("blob %s does not match its digest", digest)
	}
	return b, nil
}

// verifyBlob streams a blob of any size through sha256.
func verifyBlob(open opener, digest string) error {
	p, hexd, err := blobPath(digest)
	if err != nil {
		return err
	}
	rc, _, err := open(p)
	if err != nil {
		return err
	}
	defer rc.Close()
	h := sha256.New()
	if _, err := io.Copy(h, rc); err != nil {
		return err
	}
	if hex.EncodeToString(h.Sum(nil)) != hexd {
		return fmt.Errorf("blob %s does not match its digest", digest)
	}
	return nil
}

const maxMetaBlob = 64 << 20 // cap for JSON blobs (index, manifest, attestation) read into memory

type opener func(name string) (io.ReadCloser, int64, error)

type tarEntry struct {
	io.Reader
	f *os.File
}

func (t tarEntry) Close() error { return t.f.Close() }

func (s *Subject) opener() opener {
	if !s.IsTar {
		return func(name string) (io.ReadCloser, int64, error) {
			f, err := os.Open(filepath.Join(s.Path, filepath.FromSlash(name)))
			if err != nil {
				return nil, 0, err
			}
			fi, err := f.Stat()
			if err != nil {
				f.Close()
				return nil, 0, err
			}
			return f, fi.Size(), nil
		}
	}
	// shortcut: rescans the tar per lookup (a handful of lookups per image); index entries if it gets slow
	return func(name string) (io.ReadCloser, int64, error) {
		f, err := os.Open(s.Path)
		if err != nil {
			return nil, 0, err
		}
		tr := tar.NewReader(f)
		for {
			h, err := tr.Next()
			if err != nil {
				f.Close()
				if err == io.EOF {
					return nil, 0, fmt.Errorf("%s not found in %s", name, s.Path)
				}
				return nil, 0, err
			}
			if strings.TrimPrefix(h.Name, "./") == name {
				return tarEntry{tr, f}, h.Size, nil
			}
		}
	}
}
