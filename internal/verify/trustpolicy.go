package verify

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"golang.org/x/mod/semver"
	"strings"

	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"gopkg.in/yaml.v3"

	"github.com/dario-mr/open-trust/internal/signer"
	"github.com/dario-mr/open-trust/internal/trustlevel"
)

// TrustPolicy is the buyer's statement of which signers they accept (trust.yaml).
type TrustPolicy struct {
	MinTrustLevel string `yaml:"minTrustLevel"`
	// MinAgentVersion rejects certificates from older otrust assessors (e.g. "0.1.8"). The version is
	// the one the assessor signed into the statement: at L1+isolated-assessor the vendor cannot alter it.
	MinAgentVersion string         `yaml:"minAgentVersion"`
	Signers         []SignerPolicy `yaml:"signers"`
}

// SignerPolicy is either a public key, or a CI identity (issuer + source repo, optionally narrowed).
type SignerPolicy struct {
	Name            string `yaml:"name"`
	MinTrustLevel   string `yaml:"minTrustLevel"`   // overrides the global minimum for this signer
	MinAgentVersion string `yaml:"minAgentVersion"` // overrides the global minimum for this signer

	PublicKey string `yaml:"publicKey"` // PEM path, relative to the trust policy file

	Issuer              string `yaml:"issuer"`
	SourceRepo          string `yaml:"sourceRepo"`
	SourceRef           string `yaml:"sourceRef"`
	BuildSigner         string `yaml:"buildSigner"` // regexp over the Build Signer URI
	RequireHostedRunner bool   `yaml:"requireHostedRunner"`

	pub         crypto.PublicKey
	hint        string
	buildSigner *regexp.Regexp
}

func (s *SignerPolicy) isKey() bool { return s.PublicKey != "" }

func LoadTrustPolicy(path string) (*TrustPolicy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p TrustPolicy
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true) // a typo must not silently widen trust
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if p.MinTrustLevel == "" {
		p.MinTrustLevel = trustlevel.L1
	}
	if !trustlevel.Valid(p.MinTrustLevel) {
		return nil, fmt.Errorf("%s: unknown minTrustLevel %q", path, p.MinTrustLevel)
	}
	if v := p.MinAgentVersion; v != "" && !semver.IsValid("v"+v) {
		return nil, fmt.Errorf("%s: minAgentVersion %q is not a version like 0.1.8", path, v)
	}
	if len(p.Signers) == 0 {
		return nil, fmt.Errorf("%s: no signers: a trust policy must name who you trust", path)
	}
	for i := range p.Signers {
		s := &p.Signers[i]
		if s.Name == "" {
			s.Name = fmt.Sprintf("signer #%d", i+1)
		}
		if s.MinTrustLevel != "" && !trustlevel.Valid(s.MinTrustLevel) {
			return nil, fmt.Errorf("%s: %s: unknown minTrustLevel %q", path, s.Name, s.MinTrustLevel)
		}
		if v := s.MinAgentVersion; v != "" && !semver.IsValid("v"+v) {
			return nil, fmt.Errorf("%s: %s: minAgentVersion %q is not a version like 0.1.8", path, s.Name, v)
		}
		switch {
		case s.isKey() && s.Issuer != "":
			return nil, fmt.Errorf("%s: %s: use either publicKey or issuer, not both", path, s.Name)
		case s.isKey():
			kp := s.PublicKey
			if !filepath.IsAbs(kp) {
				kp = filepath.Join(filepath.Dir(path), kp)
			}
			pemb, err := os.ReadFile(kp)
			if err != nil {
				return nil, fmt.Errorf("%s: %s: %w", path, s.Name, err)
			}
			if s.pub, err = cryptoutils.UnmarshalPEMToPublicKey(pemb); err != nil {
				return nil, fmt.Errorf("%s: %s: %w", path, s.Name, err)
			}
			if s.hint, err = signer.KeyHint(s.pub); err != nil {
				return nil, err
			}
		case s.Issuer != "":
			// without a source repo, any repository on that CI could sign
			if s.SourceRepo == "" {
				return nil, fmt.Errorf("%s: %s: sourceRepo is required for CI identities", path, s.Name)
			}
			if s.BuildSigner != "" {
				if s.buildSigner, err = regexp.Compile(s.BuildSigner); err != nil {
					return nil, fmt.Errorf("%s: %s: buildSigner: %w", path, s.Name, err)
				}
			}
		default:
			return nil, fmt.Errorf("%s: %s: needs publicKey or issuer", path, s.Name)
		}
	}
	return &p, nil
}

func (p *TrustPolicy) minFor(s *SignerPolicy) string {
	if s.MinTrustLevel != "" {
		return s.MinTrustLevel
	}
	return p.MinTrustLevel
}

func (p *TrustPolicy) minAgentFor(s *SignerPolicy) string {
	if s.MinAgentVersion != "" {
		return s.MinAgentVersion
	}
	return p.MinAgentVersion
}

// agentTooOld says why version is below min, or "" if it is not (or no minimum is set).
func agentTooOld(version, min string) string {
	if min == "" {
		return ""
	}
	if !semver.IsValid("v"+version) || semver.Compare("v"+version, "v"+min) < 0 {
		return fmt.Sprintf("assessed by otrust %q, older than the minimum %s in your trust policy", version, min)
	}
	return ""
}

func (p *TrustPolicy) keyByHint(hint string) *SignerPolicy {
	for i := range p.Signers {
		if p.Signers[i].isKey() && p.Signers[i].hint == hint {
			return &p.Signers[i]
		}
	}
	return nil
}

// matchCert returns the first CI-identity signer the verified certificate satisfies, or why none did.
func (p *TrustPolicy) matchCert(c certificate.Summary) (*SignerPolicy, error) {
	var reasons []string
	for i := range p.Signers {
		s := &p.Signers[i]
		if s.isKey() {
			continue
		}
		var why string
		switch {
		case c.Issuer != s.Issuer:
			why = fmt.Sprintf("issuer %q", c.Issuer)
		case c.SourceRepositoryURI != s.SourceRepo:
			why = fmt.Sprintf("source repo %q", c.SourceRepositoryURI)
		case s.SourceRef != "" && c.SourceRepositoryRef != s.SourceRef:
			why = fmt.Sprintf("source ref %q", c.SourceRepositoryRef)
		case s.buildSigner != nil && !s.buildSigner.MatchString(c.BuildSignerURI):
			why = fmt.Sprintf("build signer %q", c.BuildSignerURI)
		case s.RequireHostedRunner && (c.RunnerEnvironment == "" || c.RunnerEnvironment == "self-hosted"):
			why = fmt.Sprintf("runner %q", orUnknown(c.RunnerEnvironment))
		default:
			return s, nil
		}
		reasons = append(reasons, s.Name+": "+why)
	}
	if len(reasons) == 0 {
		return nil, errors.New("trust policy lists no CI identities")
	}
	return nil, errors.New(strings.Join(reasons, "; "))
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}
