package signer

import (
	"bytes"
	"context"
	"crypto"
	"fmt"
	"strings"

	"github.com/sigstore/sigstore/pkg/signature/kms"
	_ "github.com/sigstore/sigstore/pkg/signature/kms/aws"        // awskms://
	_ "github.com/sigstore/sigstore/pkg/signature/kms/azure"      // azurekms://
	_ "github.com/sigstore/sigstore/pkg/signature/kms/gcp"        // gcpkms://
	_ "github.com/sigstore/sigstore/pkg/signature/kms/hashivault" // hashivault://
	"github.com/sigstore/sigstore/pkg/signature/options"
)

// IsKMS reports whether ref is a KMS key URI rather than a key file path.
func IsKMS(ref string) bool {
	for _, p := range kms.SupportedProviders() {
		if strings.HasPrefix(ref, p) {
			return true
		}
	}
	return false
}

// LoadSigner opens a key file, or a KMS key by URI (awskms://, gcpkms://, azurekms://, hashivault://;
// the same URIs and credentials as cosign). A KMS key must be ECDSA P-256 with SHA-256.
func LoadSigner(ctx context.Context, ref string) (*KeySigner, error) {
	if !IsKMS(ref) {
		return LoadKey(ref)
	}
	sv, err := kms.Get(ctx, ref, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ref, err)
	}
	pub, err := sv.PublicKey(options.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("%s: public key: %w", ref, err)
	}
	s, err := newKeySigner(pub, func(ctx context.Context, data []byte) ([]byte, error) {
		return sv.SignMessage(bytes.NewReader(data), options.WithContext(ctx))
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ref, err)
	}
	return s, nil
}
