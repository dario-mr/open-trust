// Package ci identifies the CI environment, the source revision, and the CI's OIDC identity token.
// This is the only CI-specific code (poc-plan.md D8). Providers: GitHub Actions, GitLab CI, generic.
package ci

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
)

type Env struct {
	Provider string `json:"provider"` // "generic" | "github" | "gitlab"
	Repo     string `json:"repo"`
	Revision string `json:"revision"`
	RunURL   string `json:"runUrl,omitempty"`
	Runner   string `json:"runner,omitempty"` // "github-hosted" | "self-hosted" | "" (unknown)
}

// Getenv is swappable for tests.
var Getenv = os.Getenv

// Detect fills the environment: flags win, then the CI's own variables, then git in sourceDir.
func Detect(ctx context.Context, sourceDir, repo, revision string) (Env, error) {
	e := Env{Provider: "generic"}
	switch {
	case Getenv("GITLAB_CI") == "true":
		// Runner stays unknown here: GitLab exposes no reliable hosted/self-hosted variable;
		// the Fulcio certificate's runner_environment claim is what the verifier checks.
		e = Env{Provider: "gitlab", Repo: Getenv("CI_PROJECT_URL"), Revision: Getenv("CI_COMMIT_SHA"), RunURL: Getenv("CI_JOB_URL")}
	case Getenv("GITHUB_ACTIONS") == "true":
		server := Getenv("GITHUB_SERVER_URL")
		e = Env{
			Provider: "github",
			Repo:     server + "/" + Getenv("GITHUB_REPOSITORY"),
			Revision: Getenv("GITHUB_SHA"),
			RunURL:   fmt.Sprintf("%s/%s/actions/runs/%s/attempts/%s", server, Getenv("GITHUB_REPOSITORY"), Getenv("GITHUB_RUN_ID"), Getenv("GITHUB_RUN_ATTEMPT")),
			Runner:   Getenv("RUNNER_ENVIRONMENT"),
		}
	}
	if repo != "" {
		e.Repo = repo
	}
	if revision != "" {
		e.Revision = revision
	}
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

// IDToken returns an OIDC token for Sigstore: SIGSTORE_ID_TOKEN if set (any CI, e.g. GitLab id_tokens),
// else GitHub Actions' token endpoint (needs `permissions: id-token: write`).
func IDToken(ctx context.Context, audience string) (string, error) {
	if t := Getenv("SIGSTORE_ID_TOKEN"); t != "" {
		return t, nil
	}
	reqURL, reqTok := Getenv("ACTIONS_ID_TOKEN_REQUEST_URL"), Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if reqURL == "" || reqTok == "" {
		return "", errors.New("no CI identity token: set SIGSTORE_ID_TOKEN (GitLab: id_tokens with aud: sigstore), or run in GitHub Actions with `permissions: id-token: write`")
	}
	u, err := url.Parse(reqURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("audience", audience)
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+reqTok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub OIDC token request: %s", resp.Status)
	}
	var out struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.Value == "" {
		return "", errors.New("GitHub OIDC token response has no token")
	}
	return out.Value, nil
}
