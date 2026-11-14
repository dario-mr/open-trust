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
	"strings"

	"github.com/dario-mr/open-trust/internal/assess"
)

// Exit codes: 0 PASSED, 1 assessment FAILED, 2 usage or runtime error.
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: otrust assess --image <oci-layout> --no-sign [flags]")
		return 2
	}
	switch args[0] {
	case "assess":
		return cmdAssess(ctx, args[1:], stdout, stderr)
	case "version":
		fmt.Fprintln(stdout, assess.Version)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q (commands: assess, version)\n", args[0])
		return 2
	}
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
	noSign := fs.Bool("no-sign", false, "write an unsigned statement (required until signing lands in week 3)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if o.Image == "" {
		fmt.Fprintln(stderr, "--image is required")
		return 2
	}
	if !*noSign {
		// fail loudly rather than emit something that looks like a certificate
		fmt.Fprintln(stderr, "signing is not implemented yet; pass --no-sign to write an unsigned statement")
		return 2
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
	fmt.Fprintln(w, "Trust     unsigned (no signature; for local testing only)")
	fmt.Fprintf(w, "Output    %s\n", strings.TrimSuffix(r.OutDir, "/")+"/statement.json")
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
