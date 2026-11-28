// Package scb embeds the scanner pins (tools.json) every profile's evidence comes from; the
// policies are in package profiles.
package scb

import (
	_ "embed"
	"encoding/json"
)

//go:embed tools.json
var toolsJSON []byte

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
