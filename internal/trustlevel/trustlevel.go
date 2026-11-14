// Package trustlevel derives what a signature can prove (poc-plan.md §3). Assess and verify share it,
// and the verifier always recomputes the level from the verified signature, never trusting the claim.
package trustlevel

import (
	"strings"

	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
)

const (
	L1                 = "L1"                   // vendor-held key: proves who signed
	L1CIIdentity       = "L1+ci-identity"       // CI OIDC identity: proves which pipeline and commit
	L1IsolatedAssessor = "L1+isolated-assessor" // our isolated workflow ran and signed; vendor steps could not alter it
)

var rank = map[string]int{L1: 1, L1CIIdentity: 2, L1IsolatedAssessor: 3}

// Valid reports whether s is a known level.
func Valid(s string) bool { return rank[s] > 0 }

// AtLeast reports whether level meets min. Unknown levels never meet anything.
func AtLeast(level, min string) bool { return rank[level] > 0 && rank[level] >= rank[min] }

// KnownAssessors are Build Signer URI prefixes of Open Trust's isolated assessment workflows.
// shortcut: placeholder until the reusable workflow is published in week 4 (then pin to its real repo).
var KnownAssessors = []string{
	"https://github.com/open-trust/assess/.github/workflows/assess.yml@",
}

// FromCertificate classifies a verified Fulcio certificate.
func FromCertificate(c certificate.Summary) string {
	if isKnownAssessor(c.BuildSignerURI) &&
		// a reusable workflow: the signer is not the vendor's own (top-level) workflow
		c.BuildSignerURI != c.BuildConfigURI &&
		!strings.HasPrefix(c.BuildSignerURI, c.SourceRepositoryURI+"/") &&
		// a self-hosted runner is vendor-controlled, so isolation would not hold
		c.RunnerEnvironment == "github-hosted" {
		return L1IsolatedAssessor
	}
	return L1CIIdentity
}

func isKnownAssessor(uri string) bool {
	for _, p := range KnownAssessors {
		if strings.HasPrefix(uri, p) {
			return true
		}
	}
	return false
}
