// Package provenance checks a signed SLSA provenance bundle (e.g. GitHub attest-build-provenance)
// for the assessed image: valid signature, SLSA predicate, subject = image digest, and a signer
// from the same source repository that was scanned.
package provenance

import (
	"errors"
	"fmt"
	"strings"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	sgverify "github.com/sigstore/sigstore-go/pkg/verify"
)

type Result struct {
	PredicateType string `json:"predicateType"`
	SubjectMatch  bool   `json:"subjectMatch"`
	// SignerTrusted: the provenance was signed by CI of the assessed source repository, so the
	// artifact was built from the same repository whose source was scanned.
	SignerTrusted bool   `json:"signerTrusted"`
	BuildSigner   string `json:"buildSigner"`
	SourceRepo    string `json:"sourceRepo"`
	SourceDigest  string `json:"sourceDigest"`
}

// Check verifies b (Sigstore bundle JSON). A bundle that does not verify is an error, not a
// "present but unsigned" provenance: broken evidence must stop the assessment.
func Check(b []byte, imageDigest, assessedRepo string, tm root.TrustedMaterial) (*Result, error) {
	var bun bundle.Bundle
	if err := bun.UnmarshalJSON(b); err != nil {
		return nil, fmt.Errorf("provenance is not a Sigstore bundle: %w", err)
	}
	vc, err := bun.VerificationContent()
	if err != nil {
		return nil, err
	}
	if vc.Certificate() == nil {
		return nil, errors.New("provenance must be signed with a CI identity certificate, not a bare key")
	}
	v, err := sgverify.NewVerifier(tm, sgverify.WithSignedCertificateTimestamps(1),
		sgverify.WithTransparencyLog(1), sgverify.WithObserverTimestamps(1))
	if err != nil {
		return nil, err
	}
	res, err := v.Verify(&bun, sgverify.NewPolicy(sgverify.WithoutArtifactUnsafe(), sgverify.WithoutIdentitiesUnsafe()))
	if err != nil {
		return nil, fmt.Errorf("provenance signature: %w", err)
	}
	st := res.Statement
	if st == nil || !strings.HasPrefix(st.GetPredicateType(), "https://slsa.dev/provenance/") {
		return nil, fmt.Errorf("not SLSA provenance (predicate %q)", st.GetPredicateType())
	}
	want := strings.TrimPrefix(imageDigest, "sha256:")
	r := &Result{PredicateType: st.GetPredicateType()}
	for _, s := range st.GetSubject() {
		if s.GetDigest()["sha256"] == want {
			r.SubjectMatch = true
		}
	}
	c := res.Signature.Certificate
	r.BuildSigner, r.SourceRepo, r.SourceDigest = c.BuildSignerURI, c.SourceRepositoryURI, c.SourceRepositoryDigest
	r.SignerTrusted = assessedRepo != "" && normalize(c.SourceRepositoryURI) == normalize(assessedRepo)
	return r, nil
}

func normalize(repo string) string {
	return strings.TrimSuffix(strings.TrimSuffix(repo, "/"), ".git")
}
