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
	fs.StringVar(&o.Image, "image", "", "image to assess (required): an OCI layout (directory or tar), or a registry reference name@sha256:…")
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
	fs.StringVar(&o.Image, "image", "", "the image you received (required): an OCI layout (directory or tar), or name@sha256:… pulled from its registry")
	fs.StringVar(&o.TrustPolicy, "trust-policy", "", "trust.yaml listing the signers you accept (required)")
	fs.StringVar(&o.Evidence, "evidence", "", "evidence directory shared by the vendor: re-checks digests and re-runs the policy")
	fs.StringVar(&o.TrustedRoot, "trusted-root", "", "Sigstore trusted_root.json for keyless/CI-signed certificates, to verify offline (without it, --online fetches it)")
	fs.StringVar(&o.Revocations, "revocations", "", "revocations.json: your own list, or a downloaded signed Open Trust list")
	fs.BoolVar(&o.Online, "online", false, "fetch the signed Open Trust revocation list and, without --trusted-root, Sigstore's trusted root")
	fs.StringVar(&o.Previous, "previous", "", "an earlier certificate for the same product: lists what changed (checked against the same trust policy)")
	report := fs.String("report", "", "also write the report as Markdown to this file, to pass on")
	fs.BoolVar(&o.Recheck, "recheck", false, "re-run the image scanners yourself (needs docker; downloads the vulnerability DB) and compare with the certificate")
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
	if *report != "" {
		if err := os.WriteFile(*report, []byte(markdownReport(r, o.Bundle, o.Image)), 0o644); err != nil {
			fmt.Fprintln(stderr, "otrust:", err)
			return 2
		}
	}
	return verify.ExitCodes[r.Code]
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
