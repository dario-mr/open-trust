// Package ci identifies the CI environment and source revision. Week 2: generic only
// (flags, else git); GitHub Actions and GitLab detection arrive in week 4 with their OIDC identities.
package ci

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

type Env struct {
	Provider string `json:"provider"` // "generic" | "github" | "gitlab"
	Repo     string `json:"repo"`
	Revision string `json:"revision"`
	RunURL   string `json:"runUrl,omitempty"`
	Runner   string `json:"runner,omitempty"` // "hosted" | "self-hosted" | "" (unknown)
}

// Detect fills Repo/Revision from overrides, falling back to git in sourceDir.
func Detect(ctx context.Context, sourceDir, repo, revision string) (Env, error) {
	e := Env{Provider: "generic", Repo: repo, Revision: revision}
	if e.Revision == "" {
		out, err := git(ctx, sourceDir, "rev-parse", "HEAD")
		if err != nil {
			return e, fmt.Errorf("no --source-revision given and git failed: %w", err)
		}
		e.Revision = out
		// a dirty tree means the scanned source is not exactly the revision we record
		if st, _ := git(ctx, sourceDir, "status", "--porcelain"); st != "" {
			e.Revision += "+dirty"
		}
	}
	if e.Repo == "" {
		e.Repo, _ = git(ctx, sourceDir, "remote", "get-url", "origin") // optional
	}
	return e, nil
}

func git(ctx context.Context, dir string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...).Output()
	return strings.TrimSpace(string(out)), err
}
