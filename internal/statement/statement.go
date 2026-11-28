// Package statement builds the in-toto Statement v1 carrying a SLSA VSA v1 predicate
// with the Open Trust assessment extension (poc-plan.md §4).
package statement

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/dario-mr/open-trust/internal/ci"
	"github.com/dario-mr/open-trust/internal/policy"
	"github.com/dario-mr/open-trust/profiles"
)

const (
	StatementType = "https://in-toto.io/Statement/v1"
	VSAType       = "https://slsa.dev/verification_summary/v1"
	ExtensionKey  = "https://open-trust.dev/assessment/v0.1"
	VerifierID    = "https://open-trust.dev/otrust"
	Validity      = 30 * 24 * time.Hour
)

type Digest map[string]string // {"sha256": "<hex>"}

type ResourceDescriptor struct {
	Name   string `json:"name,omitempty"`
	URI    string `json:"uri,omitempty"`
	Digest Digest `json:"digest"`
}

type Statement struct {
	Type          string               `json:"_type"`
	Subject       []ResourceDescriptor `json:"subject"`
	PredicateType string               `json:"predicateType"`
	Predicate     map[string]any       `json:"predicate"`
}

type Check struct {
	ID             string   `json:"id"`
	Result         string   `json:"result"`
	Findings       []string `json:"findings"`
	EvidenceDigest Digest   `json:"evidenceDigest,omitempty"`
}

// EvidenceFiles maps a check to the evidence file it was evaluated on (written next to the statement).
var EvidenceFiles = map[string]string{
	"sbom": "sbom.cdx.json", "vulns": "vulns.json", "secrets": "secrets.json",
	"sast": "sast.json", "provenance": "provenance.json",
	"licenses": "sbom.cdx.json", "sbom_completeness": "sbom.cdx.json", "os_support": "vulns.json",
}

// ContextFile holds the non-scanner policy input (time, subject, provenance status, exceptions);
// with the evidence files it reconstructs the exact policy input, so a verifier can re-evaluate.
const ContextFile = "context.json"

type Extension struct {
	AgentDigest       Digest             `json:"agentDigest"`
	ContextDigest     Digest             `json:"contextDigest"`
	CI                ci.Env             `json:"ci"`
	ValidUntil        string             `json:"validUntil"`
	TrustLevel        string             `json:"trustLevel"`
	Tools             map[string]any     `json:"tools"`
	Checks            []Check            `json:"checks"`
	Exceptions        []policy.Exception `json:"exceptions"`
	ExceptionsIgnored []json.RawMessage  `json:"exceptionsIgnored"`
	UnmetRequirements []string           `json:"unmetRequirements"`
	Limitations       []string           `json:"limitations"`
}

type Params struct {
	SubjectName    string
	SubjectDigest  string // "sha256:<hex>"
	AgentVersion   string
	AgentDigest    string // hex
	Time           time.Time
	CI             ci.Env
	TrustLevel     string
	Tools          map[string]any
	Profile        *profiles.Profile
	Decision       *policy.Decision
	Evidence       map[string]string // check id → sha256 hex of its evidence file
	ProvenanceHash string            // sha256 hex of the provenance attestation used, if any
	ContextDigest  string            // sha256 hex of ContextFile
	Limitations    []string          // beyond the profile's and the trust level's, e.g. how the tools ran
}

// limitations every certificate carries (profile.md §2); trust-level specific ones are appended.
var baseLimitations = []string{
	"Vendor-attested (Level 1): the vendor controls the environment the assessment ran in",
}

func Build(p Params) *Statement {
	d := p.Decision
	checks := make([]Check, 0, len(d.Checks))
	for _, c := range d.Checks {
		ck := Check{ID: c.ID, Result: c.Result, Findings: c.Findings}
		if h := p.Evidence[c.ID]; h != "" {
			ck.EvidenceDigest = Digest{"sha256": h}
		}
		checks = append(checks, ck)
	}
	lim := append(append([]string{}, p.Profile.Limitations...), baseLimitations...)
	switch p.TrustLevel {
	case "unsigned":
		lim = append(lim, "Unsigned: origin and integrity of this statement cannot be verified")
	case "L1":
		lim = append(lim, "Signed with a vendor-held key: proves who signed, not which pipeline ran the assessment")
	case "L1+ci-identity":
		lim = append(lim, "The vendor's own CI pipeline ran and signed the assessment; it was not an isolated assessor")
	}

	lim = append(lim, p.Limitations...)

	levels := []string{p.Profile.VSALevel}
	if d.Result != "PASSED" {
		levels = []string{"FAILED"}
	}
	var inputs []ResourceDescriptor
	if p.ProvenanceHash != "" {
		inputs = append(inputs, ResourceDescriptor{URI: "urn:otrust:provenance", Digest: Digest{"sha256": p.ProvenanceHash}})
	}
	// VSA v1 requires the predicate's top-level fields; the assessment rides in a URI-named extension.
	pred := map[string]any{
		"verifier": map[string]any{
			"id":      VerifierID,
			"version": map[string]string{"otrust": p.AgentVersion},
		},
		"timeVerified": p.Time.UTC().Format(time.RFC3339),
		"resourceUri":  p.SubjectName,
		"policy": map[string]any{
			"uri":    "https://open-trust.dev/profiles/" + d.Profile.ID + "/" + d.Profile.Version,
			"digest": Digest{"sha256": p.Profile.Digest()},
		},
		"verificationResult": d.Result,
		"verifiedLevels":     levels,
		ExtensionKey: Extension{
			AgentDigest:       Digest{"sha256": p.AgentDigest},
			ContextDigest:     Digest{"sha256": p.ContextDigest},
			CI:                p.CI,
			ValidUntil:        p.Time.Add(Validity).UTC().Format(time.RFC3339),
			TrustLevel:        p.TrustLevel,
			Tools:             p.Tools,
			Checks:            checks,
			Exceptions:        nonNil(d.ExceptionsApplied),
			ExceptionsIgnored: nonNil(d.ExceptionsIgnored),
			UnmetRequirements: nonNil(d.UnmetRequirements),
			Limitations:       lim,
		},
	}
	if inputs != nil {
		pred["inputAttestations"] = inputs
	}
	return &Statement{
		Type:          StatementType,
		Subject:       []ResourceDescriptor{{Name: p.SubjectName, Digest: Digest{"sha256": strings.TrimPrefix(p.SubjectDigest, "sha256:")}}},
		PredicateType: VSAType,
		Predicate:     pred,
	}
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
