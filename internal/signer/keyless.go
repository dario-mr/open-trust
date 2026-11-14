package signer

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/dario-mr/open-trust/internal/trustlevel"
)

const (
	PublicGoodFulcio = "https://fulcio.sigstore.dev"
	PublicGoodRekor  = "https://rekor.sigstore.dev"
)

// KeylessSigner signs with an ephemeral key certified by Fulcio for the CI's OIDC identity,
// and logs the signature in Rekor. Fulcio certificates live ~10 minutes and CI tokens are short-lived,
// so both are fetched in Prepare, after the scans, right before the statement is built and signed.
type KeylessSigner struct {
	token     func(context.Context) (string, error)
	fulcioURL string
	rekorURL  string

	kp       *sign.EphemeralKeypair
	cert     []byte // DER
	level    string
	Identity certificate.Summary
}

func NewKeyless(token func(context.Context) (string, error), fulcioURL, rekorURL string) *KeylessSigner {
	return &KeylessSigner{token: token, fulcioURL: fulcioURL, rekorURL: rekorURL}
}

// Prepare obtains the identity token and the Fulcio certificate; TrustLevel is valid afterwards.
func (s *KeylessSigner) Prepare(ctx context.Context) error {
	tok, err := s.token(ctx)
	if err != nil {
		return err
	}
	if s.kp, err = sign.NewEphemeralKeypair(nil); err != nil {
		return err
	}
	f := sign.NewFulcio(&sign.FulcioOptions{BaseURL: s.fulcioURL, Timeout: 30 * time.Second, Retries: 2})
	if s.cert, err = f.GetCertificate(ctx, s.kp, &sign.CertificateProviderOptions{IDToken: tok}); err != nil {
		return fmt.Errorf("fulcio: %w", err)
	}
	x, err := x509.ParseCertificate(s.cert)
	if err != nil {
		return fmt.Errorf("fulcio certificate: %w", err)
	}
	if s.Identity, err = certificate.SummarizeCertificate(x); err != nil {
		return err
	}
	s.level = trustlevel.FromCertificate(s.Identity)
	return nil
}

func (s *KeylessSigner) TrustLevel() string { return s.level }

func (s *KeylessSigner) Sign(ctx context.Context, statement []byte) ([]byte, error) {
	if s.cert == nil {
		return nil, fmt.Errorf("keyless signer: Prepare was not called")
	}
	b, err := sign.Bundle(&sign.DSSEData{Data: statement, PayloadType: InTotoPayloadType}, s.kp, sign.BundleOptions{
		CertificateProvider: fixedCert(s.cert),
		TransparencyLogs:    []sign.Transparency{sign.NewRekor(&sign.RekorOptions{BaseURL: s.rekorURL, Timeout: 30 * time.Second, Retries: 2})},
		Context:             ctx,
	})
	if err != nil {
		return nil, err
	}
	if _, err := bundle.NewBundle(b); err != nil {
		return nil, err
	}
	return protojson.Marshal(b)
}

// fixedCert hands sign.Bundle the certificate already obtained, for the same ephemeral key.
type fixedCert []byte

func (c fixedCert) GetCertificate(context.Context, sign.Keypair, *sign.CertificateProviderOptions) ([]byte, error) {
	return c, nil
}
