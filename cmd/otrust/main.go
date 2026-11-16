// otrust: assess an artifact against an assurance profile and (week 3) verify the certificate.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"

	"github.com/dario-mr/open-trust/internal/assess"
	"github.com/dario-mr/open-trust/internal/ci"
	"github.com/dario-mr/open-trust/internal/signer"
	"github.com/dario-mr/open-trust/internal/statement"
	"github.com/dario-mr/open-trust/internal/verify"
)

// Exit codes: 0 PASSED, 1 assessment FAILED, 2 usage or runtime error.
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, `usage:
  otrust keygen --out <prefix>
  otrust assess --image <oci-layout> (--key <file> | --no-sign) [flags]
  otrust verify <certificate.sigstore.json> --image <oci-layout> --trust-policy <trust.yaml> [flags]`)
		return 2
	}
	switch args[0] {
	case "assess":
		return cmdAssess(ctx, args[1:], stdout, stderr)
	case "verify":
		return cmdVerify(ctx, args[1:], stdout, stderr)
	case "keygen":
		return cmdKeygen(args[1:], stdout, stderr)
	case "version":
		fmt.Fprintln(stdout, assess.Version)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q (commands: assess, verify, keygen, version)\n", args[0])
		return 2
	}
}

func cmdKeygen(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "otrust", "writes <out>.key (private, 0600) and <out>.pub")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	hint, err := signer.GenerateKey(*out)
	if err != nil {
		fmt.Fprintln(stderr, "otrust:", err)
		return 2
	}
	fmt.Fprintf(stdout, "wrote %s.key and %s.pub (key hint %s)\n", *out, *out, hint)
	fmt.Fprintf(stdout, "give %s.pub to customers for their trust policy; keep %s.key secret\n", *out, *out)
	return 0
}

func cmdAssess(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("assess", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var o assess.Options
	fs.StringVar(&o.Image, "image", "", "OCI image layout (directory or tar) to assess (required)")
	fs.StringVar(&o.Name, "name", "", "subject name recorded in the certificate, e.g. registry.example.com/acme/svc")
	fs.StringVar(&o.SourceDir, "source", ".", "source tree at the assessed revision (secrets + SAST)")
	fs.StringVar(&o.OutDir, "out", "otrust-out", "directory for evidence and statement.json")
	fs.StringVar(&o.Repo, "source-repo", "", "source repository URI (default: git remote origin)")
	fs.StringVar(&o.Revision, "source-revision", "", "source revision (default: git HEAD)")
	fs.StringVar(&o.Exceptions, "exceptions", "", "exceptions file (default: <source>/.otrust/exceptions.yaml)")
	fs.StringVar(&o.Provenance, "provenance", "", "signed SLSA provenance bundle for the image (e.g. from actions/attest-build-provenance)")
	fs.StringVar(&o.TrustedRoot, "trusted-root", "", "Sigstore trusted_root.json to check --provenance (default: fetch via TUF)")
	noSign := fs.Bool("no-sign", false, "write an unsigned statement only (local testing)")
	keyPath := fs.String("key", "", "sign with this ECDSA P-256 private key (trust level L1); see `otrust keygen`")
	keyless := fs.Bool("keyless", false, "sign with the CI's OIDC identity via Sigstore (Fulcio + Rekor)")
	fulcioURL := fs.String("fulcio-url", signer.PublicGoodFulcio, "Fulcio URL for --keyless")
	rekorURL := fs.String("rekor-url", signer.PublicGoodRekor, "Rekor URL for --keyless")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if o.Image == "" {
		fmt.Fprintln(stderr, "--image is required")
		return 2
	}
	// an explicit choice: never emit an unsigned statement by accident
	chosen := 0
	for _, b := range []bool{*keyPath != "", *keyless, *noSign} {
		if b {
			chosen++
		}
	}
	if chosen != 1 {
		fmt.Fprintln(stderr, "choose exactly one of --key <file>, --keyless, or --no-sign")
		return 2
	}
	switch {
	case *keyPath != "":
		s, err := signer.LoadKey(*keyPath)
		if err != nil {
			fmt.Fprintln(stderr, "otrust:", err)
			return 2
		}
		o.Signer = s
	case *keyless:
		// fail fast if there is no identity at all; the token actually used is fetched after the scans
		if _, err := ci.IDToken(ctx, "sigstore"); err != nil {
			fmt.Fprintln(stderr, "otrust:", err)
			return 2
		}
		o.Signer = signer.NewKeyless(func(ctx context.Context) (string, error) { return ci.IDToken(ctx, "sigstore") }, *fulcioURL, *rekorURL)
	}

	res, err := assess.Run(ctx, o)
	if err != nil {
		fmt.Fprintln(stderr, "otrust:", err)
		if errors.Is(err, context.Canceled) {
			return 130
		}
		return 2
	}
	printSummary(stdout, res)
	if res.Decision.Result != "PASSED" {
		return 1
	}
	return 0
}

func printSummary(w io.Writer, r *assess.Result) {
	d := r.Decision
	mark := map[string]string{"PASSED": "✔", "WARN": "⚠", "FAILED": "✘"}
	fmt.Fprintf(w, "Subject   %s\n", r.Subject.Digest)
	fmt.Fprintf(w, "Source    %s @ %s (%s)\n", orDash(r.CI.Repo), r.CI.Revision, r.CI.Provider)
	fmt.Fprintf(w, "Profile   %s %s\n\n", d.Profile.ID, d.Profile.Version)
	for _, c := range d.Checks {
		fmt.Fprintf(w, "%s %-16s %s\n", mark[c.Result], c.ID, c.Result)
		for _, f := range c.Findings {
			fmt.Fprintf(w, "    - %s\n", f)
		}
	}
	if n := len(d.ExceptionsApplied); n > 0 {
		fmt.Fprintf(w, "\nExceptions applied: %d\n", n)
		for _, e := range d.ExceptionsApplied {
			fmt.Fprintf(w, "    - %s %s (expires %s): %s\n", e.Check, e.ID, e.Expires, e.Reason)
		}
	}
	if n := len(d.ExceptionsIgnored); n > 0 {
		fmt.Fprintf(w, "Exceptions ignored (invalid or expired): %d\n", n)
	}
	fmt.Fprintf(w, "\nResult    %s\n", d.Result)
	if r.Signed {
		ext := r.Statement.Predicate[statement.ExtensionKey].(statement.Extension)
		fmt.Fprintf(w, "Trust     %s\n", ext.TrustLevel)
		fmt.Fprintf(w, "Output    %s  (give this and the image to customers)\n", filepath.Join(r.OutDir, assess.BundleFile))
	} else {
		fmt.Fprintln(w, "Trust     unsigned (no signature; for local testing only)")
		fmt.Fprintf(w, "Output    %s\n", filepath.Join(r.OutDir, "statement.json"))
	}
	fmt.Fprintf(w, "Evidence  %s  (stays with you; share only if you choose)\n", r.OutDir)
}

func cmdVerify(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var o verify.Options
	fs.StringVar(&o.Image, "image", "", "the OCI image layout (directory or tar) you received (required)")
	fs.StringVar(&o.TrustPolicy, "trust-policy", "", "trust.yaml listing the signers you accept (required)")
	fs.StringVar(&o.Evidence, "evidence", "", "evidence directory shared by the vendor: re-checks digests and re-runs the policy")
	fs.StringVar(&o.TrustedRoot, "trusted-root", "", "Sigstore trusted_root.json (needed for keyless/CI-signed certificates)")
	fs.StringVar(&o.Revocations, "revocations", "", "revocations.json: your own list, or a downloaded signed Open Trust list")
	fs.BoolVar(&o.Online, "online", false, "fetch the signed Open Trust revocation list (the only network access)")
	// flags may follow the positional certificate path
	var pos []string
	for len(args) > 0 {
		if err := fs.Parse(args); err != nil {
			return 2
		}
		if fs.NArg() == 0 {
			break
		}
		pos, args = append(pos, fs.Arg(0)), fs.Args()[1:]
	}
	if len(pos) != 1 || o.Image == "" {
		fmt.Fprintln(stderr, "usage: otrust verify <certificate.sigstore.json> --image <oci-layout> --trust-policy <trust.yaml> [flags]")
		return 2
	}
	o.Bundle = pos[0]
	r, err := verify.Verify(ctx, o)
	if err != nil {
		fmt.Fprintln(stderr, "otrust:", err)
		return 2
	}
	printReport(stdout, r)
	return verify.ExitCodes[r.Code]
}

func printReport(w io.Writer, r *verify.Report) {
	ok := func(cond bool) string {
		if cond {
			return "✔"
		}
		return "✘"
	}
	reached := func(c verify.Code) bool { return r.Code == verify.OK || order[r.Code] > order[c] }
	if r.SignerIdentity != "" {
		fmt.Fprintf(w, "%s Signature   %s\n", ok(reached(verify.InvalidSignature)), r.SignerIdentity)
	}
	if reached(verify.UntrustedSigner) {
		fmt.Fprintf(w, "✔ Signer      %q in your trust policy\n", r.SignerName)
	}
	if p := r.Predicate; p != nil {
		e := p.Ext
		fmt.Fprintf(w, "%s Artifact    %s\n", ok(reached(verify.ArtifactMismatch)), r.SubjectDigest)
		fmt.Fprintf(w, "  Source      %s @ %s (%s)\n", orDash(e.CI.Repo), e.CI.Revision, e.CI.Provider)
		fmt.Fprintf(w, "  Profile     %s\n", p.Policy.URI)
		fmt.Fprintf(w, "  Assessed    %s, valid until %s\n", p.TimeVerified, e.ValidUntil)
		fmt.Fprintf(w, "  Trust level %s\n", r.TrustLevel)
		fmt.Fprintln(w, "  Checks:")
		for _, c := range e.Checks {
			fmt.Fprintf(w, "    %-16s %s\n", c.ID, c.Result)
			for _, f := range c.Findings {
				fmt.Fprintf(w, "      - %s\n", f)
			}
		}
		// always shown, even on PASSED
		for _, x := range e.Exceptions {
			fmt.Fprintf(w, "  Exception   %s %s (expires %s): %s\n", x.Check, x.ID, x.Expires, x.Reason)
		}
		for _, u := range e.UnmetRequirements {
			fmt.Fprintf(w, "  Unmet       %s\n", u)
		}
		for _, l := range e.Limitations {
			fmt.Fprintf(w, "  Limitation  %s\n", l)
		}
		if r.EvidenceChecked {
			fmt.Fprintln(w, "✔ Evidence    digests match and the policy re-evaluates to the same results")
		}
	}
	for _, n := range r.Notes {
		fmt.Fprintf(w, "ℹ %s\n", n)
	}
	if r.Code == verify.OK {
		fmt.Fprintln(w, "\nVERIFIED")
	} else {
		fmt.Fprintf(w, "\n%s: %s\n", r.Code, r.Reason)
	}
}

// order mirrors the sequence of checks in verify.Verify, for the ✔/✘ marks.
var order = map[verify.Code]int{
	verify.InvalidSignature: 1, verify.UntrustedSigner: 2, verify.Malformed: 3, verify.PolicyUnknown: 4,
	verify.ArtifactMismatch: 5, verify.TrustLevelTooLow: 6, verify.Revoked: 7, verify.Expired: 8,
	verify.EvidenceMissing: 9, verify.EvidenceMismatch: 9, verify.AssessmentFailed: 10,
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
