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

func PolicyDigest() string {
	sum := sha256.Sum256(Policy)
	return hex.EncodeToString(sum[:])
}
