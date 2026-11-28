// otrust: assess an artifact against an assurance profile and (week 3) verify the certificate.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"

	"github.com/dario-mr/open-trust/internal/assess"
	"github.com/dario-mr/open-trust/internal/ci"
	"github.com/dario-mr/open-trust/internal/signer"
	"github.com/dario-mr/open-trust/internal/statement"
	"github.com/dario-mr/open-trust/internal/subject"
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
  otrust pubkey --key <file|kms-uri>
  otrust attach <certificate.sigstore.json> --image <name>@sha256:…
  otrust policy [<certificate.sigstore.json>] [--image <name>@sha256:…] (--online | --trusted-root <file>)
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
	case "pubkey":
		return cmdPubkey(ctx, args[1:], stdout, stderr)
	case "attach":
		return cmdAttach(ctx, args[1:], stdout, stderr)
	case "policy":
		return cmdPolicy(ctx, args[1:], stdout, stderr)
	case "version":
		fmt.Fprintln(stdout, assess.Version)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q (commands: assess, verify, policy, attach, keygen, pubkey, version)\n", args[0])
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

// cmdPubkey prints the public key (PEM) of a signing key, e.g. one held in a KMS, for buyers' trust policies.
func cmdPubkey(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("pubkey", flag.ContinueOnError)
	fs.SetOutput(stderr)
	key := fs.String("key", "", "key file, or KMS key URI (awskms://, gcpkms://, azurekms://, hashivault://)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *key == "" {
		fmt.Fprintln(stderr, "--key is required")
		return 2
	}
	s, err := signer.LoadSigner(ctx, *key)
	if err != nil {
		fmt.Fprintln(stderr, "otrust:", err)
		return 2
	}
	pem, err := s.GetPublicKeyPem()
	if err != nil {
		fmt.Fprintln(stderr, "otrust:", err)
		return 2
	}
	fmt.Fprint(stdout, pem)
	fmt.Fprintf(stderr, "key hint %s\n", s.GetHint())
	return 0
}

// cmdPolicy drafts a trust policy from a certificate (a file, or the one attached to --image).
func cmdPolicy(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("policy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var o verify.Options
	fs.StringVar(&o.Image, "image", "", "registry image (name@sha256:…) whose attached certificate to draft from")
	fs.StringVar(&o.TrustedRoot, "trusted-root", "", "Sigstore trusted_root.json (offline)")
	fs.BoolVar(&o.Online, "online", false, "fetch Sigstore's trusted root")
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
	switch {
	case len(pos) == 1:
		o.Bundle = pos[0]
	case len(pos) == 0 && subject.IsRef(o.Image):
		found, err := subject.FindCertificates(ctx, o.Image)
		if err != nil || len(found) == 0 {
			fmt.Fprintln(stderr, "otrust: no Open Trust certificate attached to", o.Image, err)
			return 2
		}
		f, err := os.CreateTemp("", "otrust-attached-*.sigstore.json")
		if err != nil {
			fmt.Fprintln(stderr, "otrust:", err)
			return 2
		}
		defer os.Remove(f.Name())
		if _, err := f.Write(found[0].Bundle); err != nil || f.Close() != nil {
			fmt.Fprintln(stderr, "otrust: writing the attached certificate:", err)
			return 2
		}
		o.Bundle = f.Name()
	default:
		fmt.Fprintln(stderr, "usage: otrust policy [<certificate.sigstore.json>] [--image <name>@sha256:…] (--online | --trusted-root <file>)")
		return 2
	}
	draft, err := verify.DraftPolicy(o)
	if err != nil {
		fmt.Fprintln(stderr, "otrust:", err)
		return 2
	}
	fmt.Fprint(stdout, draft)
	return 0
}

// cmdAttach stores an existing certificate on its image in the registry (OCI referrer). It adds no
// trust, so anyone with push access may run it: buyers verify the signature as usual.
func cmdAttach(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("attach", flag.ContinueOnError)
	fs.SetOutput(stderr)
	image := fs.String("image", "", "the assessed image in its registry, pinned by digest (name@sha256:…)")
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
	if len(pos) != 1 || !subject.IsRef(*image) {
		fmt.Fprintln(stderr, "usage: otrust attach <certificate.sigstore.json> --image <name>@sha256:…")
		return 2
	}
	b, err := os.ReadFile(pos[0])
	if err != nil {
		fmt.Fprintln(stderr, "otrust:", err)
		return 2
	}
	digest, ann, err := certificateSubject(b)
	if err != nil {
		fmt.Fprintln(stderr, "otrust:", pos[0], err)
		return 2
	}
	d, err := subject.Attach(ctx, *image, digest, b, ann)
	if err != nil {
		fmt.Fprintln(stderr, "otrust:", err)
		return 2
	}
	fmt.Fprintf(stdout, "attached %s to %s as %s\n", pos[0], digest, d)
	return 0
}

// certificateSubject reads, without verifying (attaching adds no trust), the image manifest digest
// a certificate is about, and annotations for its referrer.
func certificateSubject(bundle []byte) (string, map[string]string, error) {
	var b struct {
		DsseEnvelope struct {
			Payload []byte `json:"payload"`
		} `json:"dsseEnvelope"`
	}
	var st struct {
		Subject []struct {
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
		Predicate struct {
			Policy             struct{ URI string } `json:"policy"`
			VerificationResult string               `json:"verificationResult"`
		} `json:"predicate"`
	}
	if err := json.Unmarshal(bundle, &b); err != nil || json.Unmarshal(b.DsseEnvelope.Payload, &st) != nil || len(st.Subject) != 1 || st.Subject[0].Digest["sha256"] == "" {
		return "", nil, errors.New("is not an Open Trust certificate (Sigstore bundle with one sha256 subject)")
	}
	ann := map[string]string{"dev.open-trust.result": st.Predicate.VerificationResult}
	if i := strings.LastIndex(st.Predicate.Policy.URI, "/profiles/"); i >= 0 {
		ann["dev.open-trust.profile"] = strings.Replace(st.Predicate.Policy.URI[i+len("/profiles/"):], "/", "@", 1)
	}
	return "sha256:" + st.Subject[0].Digest["sha256"], ann, nil
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
	scanners := fs.String("scanners", "docker", "docker (pinned images), or local: no docker; Syft and Trivy from their pinned release archives, Semgrep from PATH at the pinned version")
	fs.BoolVar(&o.Attach, "attach", false, "attach the signed certificate to the registry image (OCI referrer), so buyers verify by image reference alone")
	noSign := fs.Bool("no-sign", false, "write an unsigned statement only (local testing)")
	keyPath := fs.String("key", "", "sign with an ECDSA P-256 key (trust level L1): a key file (see `otrust keygen`) or a KMS key URI (awskms://, gcpkms://, azurekms://, hashivault://)")
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
	switch *scanners {
	case "docker":
	case "local":
		o.LocalScanners = true
	default:
		fmt.Fprintln(stderr, "--scanners must be docker or local")
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
		s, err := signer.LoadSigner(ctx, *keyPath)
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
			fmt.Fprintf(w, "    - %s %s%s (expires %s): %s\n", e.Check, e.ID, inFile(e.Path), e.Expires, e.Reason)
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
		if r.Attached != "" {
			fmt.Fprintf(w, "Attached  to the image's registry as %s: buyers verify with just --image and the same reference\n", r.Attached)
		}
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
	scanners := fs.String("scanners", "docker", "for --recheck: docker (pinned images), or local: Syft and Trivy from their pinned release archives, no docker")
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
	switch *scanners {
	case "docker":
	case "local":
		o.LocalScanners = true
	default:
		fmt.Fprintln(stderr, "--scanners must be docker or local")
		return 2
	}
	if len(pos) > 1 || o.Image == "" || (len(pos) == 0 && !subject.IsRef(o.Image)) {
		fmt.Fprintln(stderr, "usage: otrust verify [<certificate.sigstore.json>] --image <oci-layout | name@sha256:…> --trust-policy <trust.yaml> [flags]\n  (without a certificate file, --image must be a registry image with the certificate attached)")
		return 2
	}
	certName, attachedNote := "", ""
	if len(pos) == 1 {
		o.Bundle, certName = pos[0], pos[0]
	} else {
		found, err := subject.FindCertificates(ctx, o.Image)
		if err != nil {
			fmt.Fprintln(stderr, "otrust:", err)
			return 2
		}
		if len(found) == 0 {
			fmt.Fprintf(stderr, "otrust: no Open Trust certificate is attached to %s: ask the vendor for the certificate file, or to assess with --attach\n", o.Image)
			return 2
		}
		f, err := os.CreateTemp("", "otrust-attached-*.sigstore.json")
		if err != nil {
			fmt.Fprintln(stderr, "otrust:", err)
			return 2
		}
		defer os.Remove(f.Name())
		if _, err := f.Write(found[0].Bundle); err != nil || f.Close() != nil {
			fmt.Fprintln(stderr, "otrust: writing the attached certificate:", err)
			return 2
		}
		o.Bundle, certName = f.Name(), "attached to the image ("+found[0].Digest+")"
		attachedNote = fmt.Sprintf("certificate found attached to the image: %s, created %s (newest of %d)", found[0].Digest, found[0].Created, len(found))
	}
	r, err := verify.Verify(ctx, o)
	if err != nil {
		fmt.Fprintln(stderr, "otrust:", err)
		return 2
	}
	if attachedNote != "" {
		r.Notes = append(r.Notes, attachedNote)
	}
	printReport(stdout, r)
	if *report != "" {
		if err := os.WriteFile(*report, []byte(markdownReport(r, certName, o.Image)), 0o644); err != nil {
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
