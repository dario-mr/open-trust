// Package policy builds the profile input document and evaluates the embedded Rego policy.
package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/open-policy-agent/opa/v1/rego"
	"gopkg.in/yaml.v3"

	scb "github.com/dario-mr/open-trust/profiles/supply-chain-baseline/v1"
)

// Context is the policy input minus scanner evidence. It is written to context.json and bound
// to the statement by digest, so a verifier can rebuild the exact Input from it plus the evidence files.
type Context struct {
	Now        string      `json:"now"`
	Subject    SubjectIn   `json:"subject"`
	Provenance Provenance  `json:"provenance"`
	Exceptions []Exception `json:"exceptions"`
}

func (c Context) Input(ev EvidenceIn) *Input {
	return &Input{Now: c.Now, Subject: c.Subject, Provenance: c.Provenance, Evidence: ev, Exceptions: c.Exceptions}
}

// Input is the document described in profile.md §4.
type Input struct {
	Now        string      `json:"now"`
	Subject    SubjectIn   `json:"subject"`
	Provenance Provenance  `json:"provenance"`
	Evidence   EvidenceIn  `json:"evidence"`
	Exceptions []Exception `json:"exceptions"`
}

type SubjectIn struct {
	Digest         string `json:"digest"`
	AssessedDigest string `json:"assessed_digest"`
}

type Provenance struct {
	Present       bool `json:"present"`
	Signed        bool `json:"signed"`
	SignerTrusted bool `json:"signer_trusted"`
	SubjectMatch  bool `json:"subject_match"`
}

// omitempty matters: a nil RawMessage would marshal as null, which Rego treats as present.
type EvidenceIn struct {
	SBOM    json.RawMessage `json:"sbom,omitempty"`
	Vulns   json.RawMessage `json:"vulns,omitempty"`
	Secrets json.RawMessage `json:"secrets,omitempty"`
	SAST    json.RawMessage `json:"sast,omitempty"`
}

type Exception struct {
	Check   string `json:"check" yaml:"check"`
	ID      string `json:"id" yaml:"id"`
	Reason  string `json:"reason" yaml:"reason"`
	Expires string `json:"expires" yaml:"expires"`
}

type Check struct {
	ID       string   `json:"id"`
	Result   string   `json:"result"`
	Findings []string `json:"findings"`
}

type Decision struct {
	Profile struct {
		ID      string `json:"id"`
		Version string `json:"version"`
	} `json:"profile"`
	Result            string            `json:"result"`
	Checks            []Check           `json:"checks"`
	UnmetRequirements []string          `json:"unmet_requirements"`
	ExceptionsApplied []Exception       `json:"exceptions_applied"`
	ExceptionsIgnored []json.RawMessage `json:"exceptions_ignored"`
}

// LoadExceptions reads .otrust/exceptions.yaml; a missing file means no exceptions.
func LoadExceptions(path string) ([]Exception, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return []Exception{}, nil
	}
	if err != nil {
		return nil, err
	}
	var es []Exception
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true) // a typo'd key must not silently produce an exception without e.g. an expiry
	if err := dec.Decode(&es); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if es == nil {
		es = []Exception{}
	}
	return es, nil
}

func NowRFC3339() string { return time.Now().UTC().Format(time.RFC3339) }

// Evaluate runs the embedded policy over the input exactly as the verifier will.
func Evaluate(ctx context.Context, in *Input) (*Decision, error) {
	raw, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}
	var doc any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}
	rs, err := rego.New(
		rego.Query(scb.Query),
		rego.Module("policy.rego", string(scb.Policy)),
		rego.Input(doc),
		rego.StrictBuiltinErrors(true),
	).Eval(ctx)
	if err != nil {
		return nil, fmt.Errorf("policy evaluation: %w", err)
	}
	if len(rs) != 1 || len(rs[0].Expressions) != 1 {
		return nil, errors.New("policy produced no decision")
	}
	out, err := json.Marshal(rs[0].Expressions[0].Value)
	if err != nil {
		return nil, err
	}
	var d Decision
	if err := json.Unmarshal(out, &d); err != nil {
		return nil, fmt.Errorf("decode decision: %w", err)
	}
	return &d, nil
}
