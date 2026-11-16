package verify

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	sgverify "github.com/sigstore/sigstore-go/pkg/verify"
	"google.golang.org/protobuf/encoding/protojson"
)

// The published revocation list: trust/revocations.json, signed keyless by revocations.yml on main
// (re-signed weekly, valid 14 days) and served as a release asset.
const (
	RevocationsURL       = "https://github.com/dario-mr/open-trust/releases/download/revocations/revocations.sigstore.json"
	RevocationsSigner    = "https://github.com/dario-mr/open-trust/.github/workflows/revocations.yml@refs/heads/main"
	RevocationsIssuer    = "https://token.actions.githubusercontent.com"
	RevocationsPredicate = "https://open-trust.dev/revocations/v0.1"
)

// revocationList is the plain list (trust/revocations.json, or a customer's own file) and, with
// ValidUntil, the predicate of the signed one.
type revocationList struct {
	ValidUntil string `json:"validUntil,omitempty"`
	Revoked    []struct {
		Subject     string `json:"subject"`
		AgentDigest string `json:"agentDigest"` // hex, as in the certificate
		Signer      string `json:"signer"`      // key hint or certificate SAN
		Reason      string `json:"reason"`
	} `json:"revoked"`
}

func fetchRevocations(url string) ([]byte, error) {
	c := &http.Client{Timeout: 30 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		return nil, fmt.Errorf("revocation list: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("revocation list %s: %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 4<<20))
}

// loadRevocations reads a local list: a Sigstore bundle is checked like the published list; a plain
// JSON file is the customer's own decision and needs no signature.
func loadRevocations(path string, tm func() (root.TrustedMaterial, error), now time.Time) (*revocationList, string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	var probe struct {
		MediaType string `json:"mediaType"`
	}
	_ = json.Unmarshal(b, &probe)
	if strings.HasPrefix(probe.MediaType, "application/vnd.dev.sigstore.bundle") {
		return signedRevocations(b, tm, now)
	}
	var rl revocationList
	if err := decodeStrict(b, &rl); err != nil {
		return nil, "", fmt.Errorf("%s: %w", path, err)
	}
	return &rl, fmt.Sprintf("revocations checked against your list %s (%d entries)", path, len(rl.Revoked)), nil
}

// signedRevocations accepts only the list signed by RevocationsSigner and not yet stale, so an old
// copy cannot be replayed to hide a later revocation for longer than its validity.
func signedRevocations(b []byte, tm func() (root.TrustedMaterial, error), now time.Time) (*revocationList, string, error) {
	var bun bundle.Bundle
	if err := bun.UnmarshalJSON(b); err != nil {
		return nil, "", fmt.Errorf("revocation list is not a Sigstore bundle: %w", err)
	}
	m, err := tm()
	if err != nil {
		return nil, "", err
	}
	v, err := sgverify.NewVerifier(m, sgverify.WithSignedCertificateTimestamps(1),
		sgverify.WithTransparencyLog(1), sgverify.WithObserverTimestamps(1))
	if err != nil {
		return nil, "", err
	}
	id, err := sgverify.NewShortCertificateIdentity(RevocationsIssuer, "", RevocationsSigner, "")
	if err != nil {
		return nil, "", err
	}
	res, err := v.Verify(&bun, sgverify.NewPolicy(sgverify.WithoutArtifactUnsafe(), sgverify.WithCertificateIdentity(id)))
	if err != nil {
		return nil, "", fmt.Errorf("revocation list signature: %w", err)
	}
	if res.Statement == nil || res.Statement.GetPredicateType() != RevocationsPredicate {
		return nil, "", errors.New("signed bundle is not an Open Trust revocation list")
	}
	pj, err := protojson.Marshal(res.Statement.GetPredicate())
	if err != nil {
		return nil, "", err
	}
	var rl revocationList
	if err := decodeStrict(pj, &rl); err != nil {
		return nil, "", fmt.Errorf("revocation list: %w", err)
	}
	until, err := time.Parse(time.RFC3339, rl.ValidUntil)
	if err != nil {
		return nil, "", fmt.Errorf("revocation list validUntil: %w", err)
	}
	if now.After(until) {
		return nil, "", fmt.Errorf("revocation list expired at %s; fetch a fresh one (--online)", rl.ValidUntil)
	}
	return &rl, fmt.Sprintf("revocations checked against the signed Open Trust list (%d entries, valid until %s)", len(rl.Revoked), rl.ValidUntil), nil
}

func (rl *revocationList) match(subjectDigest, agentDigest, signerID string) string {
	for _, e := range rl.Revoked {
		switch {
		case e.Subject != "" && e.Subject == subjectDigest:
			return "artifact " + subjectDigest + " revoked: " + e.Reason
		case e.AgentDigest != "" && e.AgentDigest == agentDigest:
			return "assessment agent sha256:" + agentDigest + " revoked: " + e.Reason
		case e.Signer != "" && e.Signer == strings.TrimPrefix(signerID, "key "):
			return "signer " + signerID + " revoked: " + e.Reason
		}
	}
	return ""
}

func decodeStrict(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}
