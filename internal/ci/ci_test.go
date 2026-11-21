package ci

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func fakeEnv(t *testing.T, m map[string]string) {
	saved := Getenv
	Getenv = func(k string) string { return m[k] }
	t.Cleanup(func() { Getenv = saved })
}

func TestDetectGitHub(t *testing.T) {
	fakeEnv(t, map[string]string{
		"GITHUB_ACTIONS": "true", "GITHUB_SERVER_URL": "https://github.com", "GITHUB_REPOSITORY": "acme/svc",
		"GITHUB_SHA": "abc123", "GITHUB_RUN_ID": "42", "GITHUB_RUN_ATTEMPT": "1", "RUNNER_ENVIRONMENT": "github-hosted",
	})
	e, err := Detect(context.Background(), t.TempDir(), "", "")
	if err != nil {
		t.Fatal(err)
	}
	want := Env{Provider: "github", Repo: "https://github.com/acme/svc", Revision: "abc123",
		RunURL: "https://github.com/acme/svc/actions/runs/42/attempts/1", Runner: "github-hosted"}
	if e != want {
		t.Fatalf("got %+v\nwant %+v", e, want)
	}
	// explicit flags still win over the CI's variables
	if e, _ := Detect(context.Background(), t.TempDir(), "https://example.com/x", "def"); e.Repo != "https://example.com/x" || e.Revision != "def" {
		t.Fatalf("flags must override: %+v", e)
	}
}

func TestIDTokenFromGitHubEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer req-token" || r.URL.Query().Get("audience") != "sigstore" {
			http.Error(w, "bad request", http.StatusUnauthorized)
			return
		}
		w.Write([]byte(`{"value":"the-oidc-jwt"}`))
	}))
	defer srv.Close()
	fakeEnv(t, map[string]string{"ACTIONS_ID_TOKEN_REQUEST_URL": srv.URL + "/token?api-version=2.0", "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "req-token"})
	tok, err := IDToken(context.Background(), "sigstore")
	if err != nil || tok != "the-oidc-jwt" {
		t.Fatalf("got %q, %v", tok, err)
	}
}

func TestIDTokenEnvWinsAndMissingIsAnError(t *testing.T) {
	fakeEnv(t, map[string]string{"SIGSTORE_ID_TOKEN": "explicit"})
	if tok, _ := IDToken(context.Background(), "sigstore"); tok != "explicit" {
		t.Fatalf("got %q", tok)
	}
	fakeEnv(t, map[string]string{})
	if _, err := IDToken(context.Background(), "sigstore"); err == nil {
		t.Fatal("no token source must be an error")
	}
}

func TestDetectGitLab(t *testing.T) {
	fakeEnv(t, map[string]string{
		"GITLAB_CI": "true", "CI_PROJECT_URL": "https://gitlab.com/acme/svc", "CI_COMMIT_SHA": "abc123",
		"CI_JOB_URL": "https://gitlab.com/acme/svc/-/jobs/7",
	})
	e, err := Detect(context.Background(), t.TempDir(), "", "")
	if err != nil {
		t.Fatal(err)
	}
	want := Env{Provider: "gitlab", Repo: "https://gitlab.com/acme/svc", Revision: "abc123", RunURL: "https://gitlab.com/acme/svc/-/jobs/7"}
	if e != want {
		t.Fatalf("got %+v\nwant %+v", e, want)
	}
}

func TestDetectJenkinsAndAzureDevOps(t *testing.T) {
	for name, c := range map[string]struct {
		env  map[string]string
		want Env
	}{
		"jenkins": {map[string]string{"JENKINS_URL": "https://ci.example.com/", "GIT_URL": "https://bot:s3cret@git.example.com/acme/svc.git",
			"GIT_COMMIT": "abc123", "BUILD_URL": "https://ci.example.com/job/svc/7/"},
			Env{Provider: "jenkins", Repo: "https://git.example.com/acme/svc.git", Revision: "abc123", RunURL: "https://ci.example.com/job/svc/7/"}},
		"azure-devops": {map[string]string{"TF_BUILD": "True", "BUILD_REPOSITORY_URI": "https://dev.azure.com/acme/Svc%20Team/_git/svc",
			"BUILD_SOURCEVERSION": "abc123", "SYSTEM_COLLECTIONURI": "https://dev.azure.com/acme/", "SYSTEM_TEAMPROJECT": "Svc Team", "BUILD_BUILDID": "42"},
			Env{Provider: "azure-devops", Repo: "https://dev.azure.com/acme/Svc%20Team/_git/svc", Revision: "abc123",
				RunURL: "https://dev.azure.com/acme/Svc%20Team/_build/results?buildId=42"}},
	} {
		fakeEnv(t, c.env)
		e, err := Detect(context.Background(), t.TempDir(), "", "")
		if err != nil {
			t.Fatal(err)
		}
		if e != c.want {
			t.Errorf("%s: got %+v\nwant %+v", name, e, c.want)
		}
	}
}

func TestRepoCredentialsNeverRecorded(t *testing.T) {
	fakeEnv(t, map[string]string{})
	e, _ := Detect(context.Background(), t.TempDir(), "https://oauth2:glpat-x@gitlab.com/acme/svc", "abc")
	if e.Repo != "https://gitlab.com/acme/svc" {
		t.Fatalf("got %q", e.Repo)
	}
	if e, _ := Detect(context.Background(), t.TempDir(), "git@github.com:acme/svc.git", "abc"); e.Repo != "git@github.com:acme/svc.git" {
		t.Fatalf("scp-style remote changed: %q", e.Repo)
	}
}
