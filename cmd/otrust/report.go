package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/dario-mr/open-trust/internal/trustlevel"
	"github.com/dario-mr/open-trust/internal/verify"
)

// meaning says, for someone who is not a supply-chain expert, what a result means and what to do.
var meaning = map[verify.Code]string{
	verify.OK:               "You can rely on this certificate, within the limits listed under \"What this does not prove\".",
	verify.AssessmentFailed: "The certificate is genuine, but the image failed the assessment. Review the failed checks before you deploy it.",
	verify.InvalidSignature: "The certificate was altered or is not properly signed. Do not rely on it.",
	verify.UntrustedSigner:  "It is signed by someone your trust policy does not accept.",
	verify.TrustLevelTooLow: "The certificate is genuine, but it proves less than your trust policy requires.",
	verify.ArtifactMismatch: "This certificate is for a different image than the one you have.",
	verify.EvidenceMismatch: "The vendor's evidence does not match the certificate. Ask the vendor to explain.",
	verify.EvidenceMissing:  "Part of the vendor's evidence is missing.",
	verify.Expired:          "The certificate is older than 30 days. Ask the vendor for a fresh assessment.",
	verify.Revoked:          "The certificate, the assessor or the signer was revoked. Do not deploy.",
	verify.PolicyUnknown:    "It was assessed with a profile this verifier does not know. Update otrust.",
	verify.Malformed:        "This is not a valid Open Trust certificate.",
	verify.AgentOutdated:    "The certificate is genuine, but an older assessor made it than your trust policy accepts. Ask the vendor to re-assess with a current one.",
	verify.RecheckMismatch:  "Your own scan of the image contradicts the certificate: the vendor's results are not reliable for this image.",
	verify.Outdated:         "The certificate was honest, but vulnerabilities published since then make the image fail today. Ask the vendor for a fixed release.",
}

// trustMeaning: what each level proves and does not prove (docs/consumer-guide.md, trust levels).
var trustMeaning = map[string][2]string{
	// the certificate's own limitations already cover what the isolated level does not prove
	trustlevel.L1IsolatedAssessor: {"the published Open Trust assessor ran unmodified on a hosted runner; the vendor could not add steps to it", ""},
	trustlevel.L1CIIdentity: {"the vendor's own CI pipeline, for this project and commit, ran and signed the assessment",
		"That the vendor did not change the assessment: their own pipeline signs, so it could sign made-up results (use --recheck)"},
	trustlevel.L1: {"whoever holds the vendor's key signed it",
		"Anything about how or where the assessment ran: the key holder can sign any result (use --recheck)"},
}

type item struct {
	mark, text string
	sub        []string
}

type section struct {
	title string
	items []item
}

// order mirrors the sequence of checks in verify.Verify, for the ✔/✘ marks.
var order = map[verify.Code]int{
	verify.InvalidSignature: 1, verify.UntrustedSigner: 2, verify.Malformed: 3, verify.PolicyUnknown: 4,
	verify.ArtifactMismatch: 5, verify.TrustLevelTooLow: 6, verify.AgentOutdated: 6, verify.Revoked: 7, verify.Expired: 8,
	verify.EvidenceMissing: 9, verify.EvidenceMismatch: 9, verify.AssessmentFailed: 10,
	verify.RecheckMismatch: 11, verify.Outdated: 12,
}

func buildReport(r *verify.Report) []section {
	passed := func(c verify.Code) bool { return r.Code == verify.OK || order[r.Code] > order[c] }
	mark := func(c verify.Code) string {
		if passed(c) {
			return "✔"
		}
		return "✘"
	}
	var proves section
	proves.title = "What this proves"
	add := func(s *section, mark, text string, sub ...string) {
		s.items = append(s.items, item{mark, text, sub})
	}
	if r.SignerIdentity != "" {
		text := "Signature by " + r.SignerIdentity
		if r.SignerName != "" && passed(verify.UntrustedSigner) {
			text = fmt.Sprintf("Signed by %q from your trust policy (%s)", r.SignerName, r.SignerIdentity)
		}
		add(&proves, mark(verify.UntrustedSigner), text)
	}
	p := r.Predicate
	if p == nil {
		return []section{proves}
	}
	e := p.Ext
	add(&proves, mark(verify.ArtifactMismatch), "For exactly this image: "+r.SubjectDigest)
	add(&proves, "✔", fmt.Sprintf("Built from %s @ %s (%s)", orDash(e.CI.Repo), orDash(e.CI.Revision), orDash(e.CI.Provider)))
	add(&proves, mark(verify.Expired), fmt.Sprintf("Assessed %s with %s, valid until %s", p.TimeVerified, p.Policy.URI, e.ValidUntil))
	if r.TrustLevel != "" {
		add(&proves, mark(verify.TrustLevelTooLow), fmt.Sprintf("Trust level %s: %s", r.TrustLevel, trustMeaning[r.TrustLevel][0]))
	}
	if r.EvidenceChecked {
		add(&proves, "✔", "The vendor's evidence matches its digests and re-evaluates to the same results")
	}
	if rc := r.Recheck; rc != nil {
		text := "Your own scan of the image agrees with the certificate"
		if rc.PackagesCompared {
			text += ", and its packages match the vendor's SBOM"
		}
		if !rc.MismatchFree() {
			text = "Your own scan of the image contradicts the certificate"
		}
		add(&proves, map[bool]string{true: "✔", false: "✘"}[rc.MismatchFree()], text)
	}

	checks := section{title: "Checks, as the vendor's assessment reports them"}
	marks := map[string]string{"PASSED": "✔", "WARN": "⚠", "FAILED": "✘"}
	for _, c := range e.Checks {
		add(&checks, marks[c.Result], fmt.Sprintf("%-16s %s%s", c.ID, c.Result, severityCounts(c.Findings)), c.Findings...)
	}
	if sg, ok := e.Tools["semgrep"].(map[string]any); ok {
		if rs, ok := sg["ruleset"].(map[string]any); ok {
			add(&checks, "ℹ", fmt.Sprintf("SAST rules %v sha256:%v (%v rules, fetched %v)", rs["source"], rs["sha256"], rs["rules"], rs["fetched"]))
		}
	}

	risks := section{title: "Risks the vendor accepted"}
	for _, x := range e.Exceptions {
		add(&risks, "⚠", fmt.Sprintf("Exception %s %s%s (expires %s): %s", x.Check, x.ID, inFile(x.Path), x.Expires, x.Reason))
	}
	for _, u := range e.UnmetRequirements {
		add(&risks, "✘", "Unmet "+u)
	}

	var recheck section
	if rc := r.Recheck; rc != nil {
		recheck.title = fmt.Sprintf("Your re-check today: %s (your vulnerability DB %s, the vendor's %s)", rc.Result, orDash(rc.DB), orDash(rc.VendorDB))
		for _, x := range rc.Unreported {
			add(&recheck, "✘", "Unreported, though public before the vendor's scan: "+x)
		}
		for _, x := range rc.PackagesMissing {
			add(&recheck, "✘", "In the image but not in the vendor's SBOM: "+x)
		}
		for _, x := range rc.PackagesExtra {
			add(&recheck, "✘", "In the vendor's SBOM but not in the image: "+x)
		}
		for _, x := range rc.New {
			add(&recheck, "⚠", "New since the certificate: "+x)
		}
		if len(recheck.items) == 0 {
			add(&recheck, "✔", "Nothing new, nothing missing")
		}
	}

	var changes section
	if ch := r.Changes; ch != nil {
		changes.title = "Changes since the previous certificate (assessed " + ch.Assessed + ")"
		for _, l := range ch.Lines {
			add(&changes, "•", l)
		}
		if len(ch.Lines) == 0 {
			add(&changes, "✔", "None")
		}
	}

	limits := section{title: "What this does not prove"}
	for _, l := range e.Limitations {
		add(&limits, "-", l)
	}
	if t, ok := trustMeaning[r.TrustLevel]; ok && t[1] != "" {
		add(&limits, "-", t[1])
	}
	if r.Recheck == nil {
		add(&limits, "-", "That the image's packages and vulnerabilities are as the vendor reports: run with --recheck to scan it yourself")
	}

	notes := section{title: "Notes"}
	for _, n := range r.Notes {
		add(&notes, "ℹ", n)
	}
	return []section{proves, checks, risks, recheck, changes, limits, notes}
}

// severityCounts summarises a long finding list, e.g. " (5 CRITICAL, 33 HIGH)": findings start with
// their severity (policy.rego).
func severityCounts(findings []string) string {
	if len(findings) <= 3 {
		return ""
	}
	n := map[string]int{}
	for _, f := range findings {
		sev, _, _ := strings.Cut(f, " ")
		n[sev]++
	}
	var parts []string
	for _, sev := range []string{"CRITICAL", "HIGH", "ERROR", "MEDIUM", "WARNING", "LOW"} {
		if n[sev] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n[sev], sev))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, ", ") + ")"
}

func inFile(path string) string {
	if path == "" {
		return ""
	}
	return " in " + path
}

func headline(r *verify.Report) string {
	if r.Code == verify.OK {
		return "VERIFIED"
	}
	return string(r.Code)
}

func verdict(r *verify.Report) string {
	if r.Code == verify.OK {
		return "VERIFIED"
	}
	return string(r.Code) + ": " + r.Reason
}

// printReport writes the report for a terminal. The last line is the verdict, for scripts.
func printReport(w io.Writer, r *verify.Report) {
	fmt.Fprintf(w, "%s\n%s\n", headline(r), meaning[r.Code])
	for _, s := range buildReport(r) {
		if len(s.items) == 0 {
			continue
		}
		fmt.Fprintf(w, "\n%s\n", s.title)
		for _, it := range s.items {
			fmt.Fprintf(w, "  %s %s\n", it.mark, it.text)
			for _, x := range it.sub {
				fmt.Fprintf(w, "      - %s\n", x)
			}
		}
	}
	fmt.Fprintf(w, "\n%s\n", verdict(r))
}

// markdownReport is the same report as a file to pass on, e.g. to a security team.
func markdownReport(r *verify.Report, certificate, image string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Open Trust verification: %s\n\n%s\n\n", headline(r), meaning[r.Code])
	fmt.Fprintf(&b, "Certificate `%s`, image `%s`.\n", certificate, image)
	if r.Code != verify.OK {
		fmt.Fprintf(&b, "\n> %s\n", verdict(r))
	}
	for _, s := range buildReport(r) {
		if len(s.items) == 0 {
			continue
		}
		fmt.Fprintf(&b, "\n## %s\n\n", s.title)
		for _, it := range s.items {
			text := strings.Join(strings.Fields(it.text), " ")
			if it.mark == "-" { // a plain list item: the bullet is the mark
				fmt.Fprintf(&b, "- %s\n", text)
			} else {
				fmt.Fprintf(&b, "- %s %s\n", it.mark, text)
			}
			for _, x := range it.sub {
				fmt.Fprintf(&b, "  - %s\n", x)
			}
		}
	}
	return b.String()
}
