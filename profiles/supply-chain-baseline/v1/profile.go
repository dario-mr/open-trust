// Package scb embeds the Supply-Chain Baseline v1 profile (policy + tool pins) into otrust,
// so the policy that runs is exactly the one whose digest goes into the certificate.
package scb

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
)

//go:embed policy.rego
var Policy []byte

// policy100 is profile 1.0.0's policy, frozen byte for byte: certificates name their policy by
// digest, so the verifier keeps every released version to verify and re-evaluate older certificates.
//
//go:embed policy-1.0.0.rego
var policy100 []byte

//go:embed tools.json
var toolsJSON []byte

// Query is the Rego rule that yields the decision document.
const Query = "data.otrust.scb.v1.decision"

// VSALevel is the custom verifiedLevels value for a PASSED result.
const VSALevel = "OPENTRUST_SCB_V1"

type Tool struct {
	Version string `json:"version"`
	Image   string `json:"image"`
	Config  string `json:"config,omitempty"`
	// Release pins the tool's own release archive per "os/arch", for running without docker.
	Release map[string]Asset `json:"release,omitempty"`
}

// Asset is a release archive pinned by sha256; the tool's binary sits at its top level.
type Asset struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
}

type Tools struct {
	Syft    Tool `json:"syft"`
	Trivy   Tool `json:"trivy"`
	Semgrep Tool `json:"semgrep"`
	OPA     Tool `json:"opa"`
}

func LoadTools() (Tools, error) {
	var t Tools
	err := json.Unmarshal(toolsJSON, &t)
	return t, err
}

func PolicyDigest() string { return digest(Policy) }

// PolicyByDigest returns the policy with this sha256 (hex), current or released earlier, or nil.
func PolicyByDigest(d string) []byte {
	for _, p := range [][]byte{Policy, policy100} {
		if digest(p) == d {
			return p
		}
	}
	return nil
}

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
