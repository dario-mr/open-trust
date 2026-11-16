// Package verify checks a certificate (Sigstore bundle) on the buyer's side, offline, without
// trusting anything the vendor claims beyond what the signature and the trust policy establish.
package verify

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	sgverify "github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/signature"

	"github.com/dario-mr/open-trust/internal/policy"
	"github.com/dario-mr/open-trust/internal/signer"
	"github.com/dario-mr/open-trust/internal/statement"
	"github.com/dario-mr/open-trust/internal/subject"
	"github.com/dario-mr/open-trust/internal/trustlevel"
	scb "github.com/dario-mr/open-trust/profiles/supply-chain-baseline/v1"
)

type Code string

// Codes in the order they are checked; the first failure wins.
const (
	OK               Code = "OK"
	InvalidSignature Code = "INVALID_SIGNATURE"
	UntrustedSigner  Code = "UNTRUSTED_SIGNER"
	Malformed        Code = "MALFORMED"
	PolicyUnknown    Code = "POLICY_UNKNOWN"
	ArtifactMismatch Code = "ARTIFACT_MISMATCH"
	TrustLevelTooLow Code = "TRUST_LEVEL_TOO_LOW"
	Revoked          Code = "REVOKED"
	Expired          Code = "EXPIRED"
	EvidenceMissing  Code = "EVIDENCE_MISSING"
	EvidenceMismatch Code = "EVIDENCE_MISMATCH"
	AssessmentFailed Code = "ASSESSMENT_FAILED"
)

// ExitCodes are stable for scripting. 2 is reserved for usage errors.
var ExitCodes = map[Code]int{
	OK: 0, AssessmentFailed: 10, InvalidSignature: 11, UntrustedSigner: 12, TrustLevelTooLow: 13,
	ArtifactMismatch: 14, EvidenceMismatch: 15, EvidenceMissing: 16, Expired: 17, Revoked: 18,
	PolicyUnknown: 19, Malformed: 20,
}

type Options struct {
	Bundle      string
	Image       string // OCI layout the customer received
	TrustPolicy string // required: who the customer trusts
	Evidence    string // optional: evidence dir shared by the vendor
	TrustedRoot string // Sigstore trusted_root.json; required for certificate-signed bundles
	Revocations string // optional: your own revocations.json, or a downloaded signed list
	Online      bool   // fetch the signed Open Trust revocation list (RevocationsURL)
	Now         time.Time
}

type Report struct {
	Code   Code
	Reason string

	SignerName        string // from the trust policy
	SignerIdentity    string // key hint or certificate SAN
	TrustLevel        string // recomputed from the signature
	ClaimedTrustLevel string // what the statement says
	SubjectDigest     string
	Predicate         *Predicate
	EvidenceChecked   bool
	Notes             []string
}

type Predicate struct {
	Verifier struct {
		ID      string            `json:"id"`
		Version map[string]string `json:"version"`
	} `json:"verifier"`
	TimeVerified string `json:"timeVerified"`
	ResourceURI  string `json:"resourceUri"`
	Policy       struct {
		URI    string            `json:"uri"`
		Digest map[string]string `json:"digest"`
	} `json:"policy"`
	VerificationResult string               `json:"verificationResult"`
	VerifiedLevels     []string             `json:"verifiedLevels"`
	Ext                *statement.Extension `json:"https://open-trust.dev/assessment/v0.1"`
}

type inTotoStatement struct {
	Type          string                         `json:"_type"`
	Subject       []statement.ResourceDescriptor `json:"subject"`
	PredicateType string                         `json:"predicateType"`
	Predicate     *Predicate                     `json:"predicate"`
}

func (r *Report) fail(c Code, format string, a ...any) *Report {
	r.Code, r.Reason = c, fmt.Sprintf(format, a...)
	return r
}

// Verify returns a Report for every verification outcome; an error means the inputs were unusable.
func Verify(ctx context.Context, o Options) (*Report, error) {
	if o.TrustPolicy == "" {
		return nil, errors.New("a trust policy is required: there is no safe default for whom to trust")
	}
	tp, err := LoadTrustPolicy(o.TrustPolicy)
	if err != nil {
		return nil, err
	}
	now := o.Now
	if now.IsZero() {
		now = time.Now()
	}
	r := &Report{}

	// 1. signature and signer
	b, err := bundle.LoadJSONFromPath(o.Bundle)
	if err != nil {
		return r.fail(Malformed, "not a Sigstore bundle: %v", err), nil
	}
	vc, err := b.VerificationContent()
	if err != nil {
		return r.fail(Malformed, "bundle has no verification material: %v", err), nil
	}
	var sp *SignerPolicy
	if pk := vc.PublicKey(); pk != nil {
		r.SignerIdentity = "key " + pk.Hint()
		if sp = tp.keyByHint(pk.Hint()); sp == nil {
			return r.fail(UntrustedSigner, "signed with key %s, which the trust policy does not list", pk.Hint()), nil
		}
		ver, err := signature.LoadVerifier(sp.pub, crypto.SHA256)
		if err != nil {
			return nil, err
		}
		v, err := sgverify.NewVerifier(root.NewTrustedPublicKeyMaterialFromMapping(
			map[string]*root.ExpiringKey{pk.Hint(): root.NewExpiringKey(ver, time.Time{}, time.Time{})}),
			sgverify.WithNoObserverTimestamps())
		if err != nil {
			return nil, err
		}
		if _, err := v.Verify(b, sgverify.NewPolicy(sgverify.WithoutArtifactUnsafe(), sgverify.WithKey())); err != nil {
			return r.fail(InvalidSignature, "%v", err), nil
		}
		r.TrustLevel = trustlevel.L1
	} else {
		if o.TrustedRoot == "" {
			return nil, errors.New("certificate-signed bundle: --trusted-root is required (e.g. `gh attestation trusted-root`)")
		}
		tr, err := root.NewTrustedRootFromPath(o.TrustedRoot)
		if err != nil {
			return nil, fmt.Errorf("trusted root: %w", err)
		}
		v, err := sgverify.NewVerifier(tr, sgverify.WithSignedCertificateTimestamps(1),
			sgverify.WithTransparencyLog(1), sgverify.WithObserverTimestamps(1))
		if err != nil {
			return nil, err
		}
		// Identity is matched below against the trust policy, with a reason per signer.
		res, err := v.Verify(b, sgverify.NewPolicy(sgverify.WithoutArtifactUnsafe(), sgverify.WithoutIdentitiesUnsafe()))
		if err != nil {
			return r.fail(InvalidSignature, "%v", err), nil
		}
		c := res.Signature.Certificate
		r.SignerIdentity = c.SubjectAlternativeName
		if sp, err = tp.matchCert(*c); err != nil {
			return r.fail(UntrustedSigner, "certificate identity not in trust policy (%v)", err), nil
		}
		r.TrustLevel = trustlevel.FromCertificate(*c)
	}
	r.SignerName = sp.Name

	// 2. statement shape (the payload is now authenticated)
	env := b.GetDsseEnvelope()
	if env == nil || env.GetPayloadType() != signer.InTotoPayloadType {
		return r.fail(Malformed, "bundle does not carry an in-toto DSSE envelope"), nil
	}
	var st inTotoStatement
	if err := json.Unmarshal(env.GetPayload(), &st); err != nil {
		return r.fail(Malformed, "statement: %v", err), nil
	}
	switch {
	case st.Type != statement.StatementType, st.PredicateType != statement.VSAType:
		return r.fail(Malformed, "unexpected statement type %q / predicate %q", st.Type, st.PredicateType), nil
	case st.Predicate == nil || st.Predicate.Ext == nil:
		return r.fail(Malformed, "statement has no Open Trust assessment"), nil
	case len(st.Subject) != 1 || st.Subject[0].Digest["sha256"] == "":
		return r.fail(Malformed, "statement must have exactly one sha256 subject"), nil
	}
	p := st.Predicate
	r.Predicate, r.ClaimedTrustLevel = p, p.Ext.TrustLevel
	r.SubjectDigest = "sha256:" + st.Subject[0].Digest["sha256"]
	if p.Policy.Digest["sha256"] != scb.PolicyDigest() {
		return r.fail(PolicyUnknown, "policy %s (sha256:%s) is not the profile this verifier knows", p.Policy.URI, p.Policy.Digest["sha256"]), nil
	}

	// 3. artifact binding
	img, err := subject.Resolve(o.Image)
	if err != nil {
		return r.fail(ArtifactMismatch, "image: %v", err), nil
	}
	if img.Digest != r.SubjectDigest {
		return r.fail(ArtifactMismatch, "image is %s, certificate is for %s", img.Digest, r.SubjectDigest), nil
	}

	// 4. trust level (never more than the signature proves)
	if r.ClaimedTrustLevel != r.TrustLevel {
		r.Notes = append(r.Notes, fmt.Sprintf("statement claims trust level %q; the signature proves %q", r.ClaimedTrustLevel, r.TrustLevel))
	}
	if min := tp.minFor(sp); !trustlevel.AtLeast(r.TrustLevel, min) {
		return r.fail(TrustLevelTooLow, "trust level %s is below the required %s", r.TrustLevel, min), nil
	}

	// 5. revocation and expiry
	if o.Revocations == "" && !o.Online {
		r.Notes = append(r.Notes, "no revocation list given: revocation not checked (use --online)")
	}
	tm := func() (root.TrustedMaterial, error) {
		if o.TrustedRoot != "" {
			return root.NewTrustedRootFromPath(o.TrustedRoot)
		}
		if o.Online {
			return root.FetchTrustedRoot()
		}
		return nil, errors.New("a signed revocation list needs --trusted-root (or --online)")
	}
	var lists []*revocationList
	if o.Revocations != "" {
		rl, note, err := loadRevocations(o.Revocations, tm, now)
		if err != nil {
			return nil, err
		}
		lists, r.Notes = append(lists, rl), append(r.Notes, note)
	}
	if o.Online {
		b, err := fetchRevocations(RevocationsURL)
		if err != nil {
			return nil, err
		}
		rl, note, err := signedRevocations(b, tm, now)
		if err != nil {
			return nil, err
		}
		lists, r.Notes = append(lists, rl), append(r.Notes, note)
	}
	for _, rl := range lists {
		if why := rl.match(r.SubjectDigest, p.Ext.AgentDigest["sha256"], r.SignerIdentity); why != "" {
			return r.fail(Revoked, "%s", why), nil
		}
	}
	until, err := time.Parse(time.RFC3339, p.Ext.ValidUntil)
	if err != nil {
		return r.fail(Malformed, "validUntil: %v", err), nil
	}
	if now.After(until) {
		return r.fail(Expired, "certificate expired at %s", p.Ext.ValidUntil), nil
	}

	// 6. evidence (optional): digests, then re-evaluate the policy and compare with the claimed results
	if o.Evidence != "" {
		code, why, err := checkEvidence(ctx, o.Evidence, r.SubjectDigest, p)
		if err != nil {
			return nil, err
		}
		if code != OK {
			return r.fail(code, "%s", why), nil
		}
		r.EvidenceChecked = true
	}

	// 7. the assessment itself
	if p.VerificationResult != "PASSED" {
		return r.fail(AssessmentFailed, "assessment result is %s", p.VerificationResult), nil
	}
	if !slices.Contains(p.VerifiedLevels, scb.VSALevel) {
		return r.fail(Malformed, "PASSED without verified level %s", scb.VSALevel), nil
	}
	r.Code = OK
	return r, nil
}

func checkEvidence(ctx context.Context, dir, subjectDigest string, p *Predicate) (Code, string, error) {
	read := func(name, wantHex string) ([]byte, Code, string) {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, EvidenceMissing, fmt.Sprintf("%s: %v", name, err)
		}
		if sum := sha256.Sum256(b); hex.EncodeToString(sum[:]) != wantHex {
			return nil, EvidenceMismatch, name + " does not match its digest in the certificate"
		}
		return b, OK, ""
	}
	ctxb, code, why := read(statement.ContextFile, p.Ext.ContextDigest["sha256"])
	if code != OK {
		return code, why, nil
	}
	var pc policy.Context
	if err := json.Unmarshal(ctxb, &pc); err != nil {
		return EvidenceMismatch, "context.json: " + err.Error(), nil
	}
	if pc.Subject.Digest != subjectDigest {
		return EvidenceMismatch, "evidence is for " + pc.Subject.Digest, nil
	}
	ev := map[string]json.RawMessage{}
	for _, c := range p.Ext.Checks {
		if c.EvidenceDigest["sha256"] == "" {
			continue
		}
		b, code, why := read(statement.EvidenceFiles[c.ID], c.EvidenceDigest["sha256"])
		if code != OK {
			return code, why, nil
		}
		ev[c.ID] = b
	}
	dec, err := policy.Evaluate(ctx, pc.Input(policy.EvidenceIn{SBOM: ev["sbom"], Vulns: ev["vulns"], Secrets: ev["secrets"], SAST: ev["sast"]}))
	if err != nil {
		return "", "", err
	}
	var diffs []string
	if dec.Result != p.VerificationResult {
		diffs = append(diffs, fmt.Sprintf("result: certificate says %s, evidence gives %s", p.VerificationResult, dec.Result))
	}
	claimed := map[string]string{}
	for _, c := range p.Ext.Checks {
		claimed[c.ID] = c.Result
	}
	for _, c := range dec.Checks {
		if claimed[c.ID] != c.Result {
			diffs = append(diffs, fmt.Sprintf("%s: certificate says %q, evidence gives %s", c.ID, claimed[c.ID], c.Result))
		}
	}
	if len(diffs) > 0 {
		return EvidenceMismatch, "re-evaluating the evidence disagrees with the certificate: " + strings.Join(diffs, "; "), nil
	}
	return OK, "", nil
}
