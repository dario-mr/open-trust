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
