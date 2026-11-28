package verify

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/sigstore/sigstore-go/pkg/bundle"

	"github.com/dario-mr/open-trust/internal/trustlevel"
)

// DraftPolicy writes a trust policy that accepts exactly what this certificate's signature proves:
// its issuer, repository, ref and build signer (pinned), hosted runners if it ran on one, and its
// trust level and assessor version as minimums. The signature is verified first, so a forged
// certificate cannot dictate a policy; the draft is checked to accept the certificate. It is a
// starting point for the buyer to review, never a substitute for deciding whom to trust.
func DraftPolicy(o Options) (string, error) {
	b, err := bundle.LoadJSONFromPath(o.Bundle)
	if err != nil {
		return "", fmt.Errorf("not a Sigstore bundle: %w", err)
	}
	vc, err := b.VerificationContent()
	if err != nil {
		return "", err
	}
	if pk := vc.PublicKey(); pk != nil {
		// without the vendor's public key the signature can't be checked: nothing to pin but the key
		return fmt.Sprintf(`# Key-signed certificate (trust level L1), with key hint %s.
# Get the vendor's public key from the vendor through a channel you trust (not with the certificate)
# and save it as vendor.pub next to this file; verify then refuses certificates signed with any other key.
# A key proves who signed, not how the assessment ran: use verify --recheck.
signers:
  - name: the vendor's signing key
    publicKey: vendor.pub
`, pk.Hint()), nil
	}
	loadRoot := trustedRootLoader(o)
	c, invalid, err := signingCertificate(b, loadRoot)
	if err != nil {
		return "", err
	}
	if invalid != nil {
		return "", fmt.Errorf("the signature does not verify, so it proves nothing to draft from: %w", invalid)
	}
	var st inTotoStatement
	if env := b.GetDsseEnvelope(); env == nil || json.Unmarshal(env.GetPayload(), &st) != nil || st.Predicate == nil {
		return "", errors.New("not an Open Trust certificate")
	}
	level := trustlevel.FromCertificate(*c)
	hosted := c.RunnerEnvironment != "" && c.RunnerEnvironment != "self-hosted"

	var w strings.Builder
	fmt.Fprintf(&w, "# Trust policy drafted by otrust from a certificate for %s.\n", st.Predicate.ResourceURI)
	fmt.Fprintf(&w, "# It accepts certificates signed exactly as that one was. Review each line: it is your decision whom to trust.\n")
	fmt.Fprintf(&w, "minTrustLevel: %s  # %s\n", level, trustMeaning(level))
	if v := st.Predicate.Verifier.Version["otrust"]; v != "" {
		fmt.Fprintf(&w, "minAgentVersion: %s  # refuse certificates from older assessors\n", v)
	}
	signer, release := "^"+regexp.QuoteMeta(c.BuildSignerURI)+"$", false
	if o.AnyRelease {
		signer, release = anyRelease(c.BuildSignerURI)
	}
	fmt.Fprintf(&w, "signers:\n  - name: %s\n", yq(c.SourceRepositoryURI+" via "+c.BuildSignerURI))
	fmt.Fprintf(&w, "    issuer: %s  # who vouches for the CI identity\n", yq(c.Issuer))
	fmt.Fprintf(&w, "    sourceRepo: %s\n", yq(c.SourceRepositoryURI))
	if release && strings.HasPrefix(c.SourceRepositoryRef, "refs/tags/") {
		fmt.Fprintf(&w, "    # no sourceRef: each release builds from its own tag; buildSigner admits release tags only\n")
	} else {
		fmt.Fprintf(&w, "    sourceRef: %s  # only builds of this branch or tag\n", yq(c.SourceRepositoryRef))
	}
	if release {
		fmt.Fprintf(&w, "    # this workflow at any commit pin or release tag (not a branch); minAgentVersion is the floor\n")
	} else {
		fmt.Fprintf(&w, "    # pinned to this exact workflow and revision; when the vendor upgrades, update the pin\n")
	}
	fmt.Fprintf(&w, "    buildSigner: %s\n", yq(signer))
	if hosted {
		fmt.Fprintf(&w, "    requireHostedRunner: true  # refuse runs on machines the vendor controls\n")
	} else {
		fmt.Fprintf(&w, "    # WARNING: this certificate was signed on a runner the CI calls %q, which the vendor may control.\n", orUnknown(c.RunnerEnvironment))
	}
	draft := w.String()

	// self-check: the draft must accept the certificate it was drafted from
	dir, err := os.MkdirTemp("", "otrust-draft-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	p := filepath.Join(dir, "trust.yaml")
	if err := os.WriteFile(p, []byte(draft), 0o600); err != nil {
		return "", err
	}
	tp, err := LoadTrustPolicy(p)
	if err != nil {
		return "", fmt.Errorf("drafted policy does not load: %w", err)
	}
	r, _, err := authenticate(o.Bundle, loadRoot, tp)
	if err != nil {
		return "", err
	}
	if r.Code != "" {
		return "", fmt.Errorf("drafted policy refuses its own certificate: %s: %s", r.Code, r.Reason)
	}
	return draft, nil
}

// releasePin matches what a release pins a workflow to: a full commit, or a release tag v<digits.dots>
// (a look-alike such as v1.0-evil is not one)
const releasePin = `([0-9a-f]{40}|refs/tags/v[0-9.]+)`

// anyRelease generalises a build signer URI pinned to a commit or release tag to any commit or release
// tag of the same workflow. A branch ref is left as it is: it already spans releases.
func anyRelease(uri string) (signer string, release bool) {
	i := strings.LastIndex(uri, "@")
	if i < 0 || !regexp.MustCompile("^"+releasePin+"$").MatchString(uri[i+1:]) {
		return "^" + regexp.QuoteMeta(uri) + "$", false
	}
	return "^" + regexp.QuoteMeta(uri[:i+1]) + releasePin + "$", true
}

func trustMeaning(level string) string {
	switch level {
	case trustlevel.L1IsolatedAssessor:
		return "the published assessor ran; the vendor could not change it"
	case trustlevel.L1CIIdentity:
		return "the vendor's own pipeline signed: use verify --recheck"
	}
	return level
}

// yq quotes a YAML scalar (single quotes: backslashes in regular expressions stay literal).
func yq(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
