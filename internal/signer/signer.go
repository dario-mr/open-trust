// Package signer wraps a statement in DSSE and signs it into a Sigstore bundle (v0.3).
// Week 3: key file (trust level L1). Keyless (Fulcio + Rekor with a CI OIDC token) is added in
// week 4, where real CI tokens exist to test it.
package signer

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"google.golang.org/protobuf/encoding/protojson"
)

const InTotoPayloadType = "application/vnd.in-toto+json"

type Signer interface {
	// Sign returns a Sigstore bundle (JSON) over the DSSE-wrapped in-toto statement.
	Sign(ctx context.Context, statement []byte) ([]byte, error)
	// TrustLevel is the most this signature can prove (recomputed by the verifier; never trusted from the statement).
	TrustLevel() string
}

// KeyHint identifies a public key in bundles and trust policies: base64(sha256(PKIX DER)),
// the same convention sigstore-go uses for its keypairs.
func KeyHint(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return base64.StdEncoding.EncodeToString(sum[:]), nil
}

// KeySigner signs with a long-lived ECDSA P-256 key held by the vendor: a PEM file, or a KMS key
// (LoadSigner) that never leaves the KMS. Key-signed bundles carry no transparency-log entry, so
// nothing about the vendor's repository is published.
type KeySigner struct {
	pub  crypto.PublicKey
	hint []byte
	// sign returns an ASN.1 ECDSA signature over sha256(data)
	sign func(ctx context.Context, data []byte) ([]byte, error)
}

func newKeySigner(pub crypto.PublicKey, sign func(context.Context, []byte) ([]byte, error)) (*KeySigner, error) {
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, errors.New("want an ECDSA P-256 key")
	}
	h, err := KeyHint(pub)
	if err != nil {
		return nil, err
	}
	return &KeySigner{pub: pub, hint: []byte(h), sign: sign}, nil
}

func LoadKey(path string) (*KeySigner, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("%s: no PEM block", path)
	}
	var k any
	switch blk.Type {
	case "PRIVATE KEY":
		k, err = x509.ParsePKCS8PrivateKey(blk.Bytes)
	case "EC PRIVATE KEY":
		k, err = x509.ParseECPrivateKey(blk.Bytes)
	default:
		return nil, fmt.Errorf("%s: unsupported PEM type %q (want an unencrypted ECDSA P-256 private key)", path, blk.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: want an ECDSA P-256 key", path)
	}
	s, err := newKeySigner(ec.Public(), func(_ context.Context, data []byte) ([]byte, error) {
		digest := sha256.Sum256(data)
		return ecdsa.SignASN1(rand.Reader, ec, digest[:])
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

// GenerateKey writes a new P-256 key pair: <prefix>.key (0600) and <prefix>.pub.
func GenerateKey(prefix string) (string, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return "", err
	}
	pub, err := cryptoutils.MarshalPublicKeyToPEM(k.Public())
	if err != nil {
		return "", err
	}
	// O_EXCL: never overwrite an existing signing key
	f, err := os.OpenFile(prefix+".key", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	if err := errors.Join(pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der}), f.Close()); err != nil {
		return "", err
	}
	if err := os.WriteFile(prefix+".pub", pub, 0o644); err != nil {
		return "", err
	}
	return KeyHint(k.Public())
}

func (s *KeySigner) TrustLevel() string { return "L1" }

func (s *KeySigner) Sign(_ context.Context, statement []byte) ([]byte, error) {
	b, err := sign.Bundle(&sign.DSSEData{Data: statement, PayloadType: InTotoPayloadType}, s, sign.BundleOptions{})
	if err != nil {
		return nil, err
	}
	// round-trip through the bundle type so we only ever emit bundles sigstore-go can load
	if _, err := bundle.NewBundle(b); err != nil {
		return nil, err
	}
	return protojson.Marshal(b)
}

// sign.Keypair implementation.

func (s *KeySigner) GetHashAlgorithm() protocommon.HashAlgorithm {
	return protocommon.HashAlgorithm_SHA2_256
}
func (s *KeySigner) GetSigningAlgorithm() protocommon.PublicKeyDetails {
	return protocommon.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256
}
func (s *KeySigner) GetHint() []byte                { return s.hint }
func (s *KeySigner) GetKeyAlgorithm() string        { return "ECDSA" }
func (s *KeySigner) GetPublicKey() crypto.PublicKey { return s.pub }
func (s *KeySigner) GetPublicKeyPem() (string, error) {
	b, err := cryptoutils.MarshalPublicKeyToPEM(s.pub)
	return string(b), err
}
func (s *KeySigner) SignData(ctx context.Context, data []byte) ([]byte, []byte, error) {
	digest := sha256.Sum256(data)
	sig, err := s.sign(ctx, data)
	return sig, digest[:], err
}
