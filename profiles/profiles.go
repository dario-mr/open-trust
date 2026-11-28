// Package profiles embeds the assurance profiles otrust evaluates: their policies, so the policy
// that runs is exactly the one whose digest goes into a certificate. One assessment scans once and
// produces one certificate per profile.
package profiles

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"slices"
)

//go:embed supply-chain-baseline/v1/policy.rego
var scbPolicy []byte

//go:embed quality-baseline/v1/policy.rego
var qualityPolicy []byte

type Profile struct {
	ID        string
	Policy    []byte
	Query     string   // the Rego rule that yields the decision document
	VSALevel  string   // the custom verifiedLevels value of a PASSED certificate
	Checks    []string // the policy's required checks; exceptions name one of them
	Bundle    string   // the certificate file assess writes
	Statement string   // the unsigned statement file assess writes
	// Limitations every certificate of this profile carries (profile.md §2)
	Limitations []string
}

var (
	SupplyChain = &Profile{ID: "supply-chain-baseline", Policy: scbPolicy, Query: "data.otrust.scb.v1.decision",
		VSALevel: "OPENTRUST_SCB_V1", Checks: []string{"sbom", "vulns", "secrets", "sast", "provenance", "subject_binding"},
		Bundle: "certificate.sigstore.json", Statement: "statement.json",
		Limitations: []string{
			"Scanners detect known vulnerabilities and pattern-matched code flaws only",
			"Does not prove the scanned source is the complete source of the artifact",
		}}
	Quality = &Profile{ID: "quality-baseline", Policy: qualityPolicy, Query: "data.otrust.quality.v1.decision",
		VSALevel: "OPENTRUST_QUALITY_V1", Checks: []string{"licenses", "sbom_completeness", "os_support"},
		Bundle: "certificate.quality-baseline.sigstore.json", Statement: "statement.quality-baseline.json",
		Limitations: []string{
			"Licences are the ones the SBOM tool detected in package metadata: this is not a legal review",
			"Only application dependencies are checked for licences, not OS packages, and none for licence compatibility",
		}}
	All = []*Profile{SupplyChain, Quality}
)

func (p *Profile) Digest() string {
	sum := sha256.Sum256(p.Policy)
	return hex.EncodeToString(sum[:])
}

// ByDigest returns the profile whose policy has this sha256 (hex), or nil.
func ByDigest(d string) *Profile {
	for _, p := range All {
		if p.Digest() == d {
			return p
		}
	}
	return nil
}

// ByID returns the profile with this id, or nil.
func ByID(id string) *Profile {
	for _, p := range All {
		if p.ID == id {
			return p
		}
	}
	return nil
}

// HasCheck reports whether any profile has this check: exceptions must name one.
func HasCheck(check string) bool {
	for _, p := range All {
		if slices.Contains(p.Checks, check) {
			return true
		}
	}
	return false
}
