package verify

import (
	"slices"
	"strings"
	"testing"
)

func TestPreviousListsChanges(t *testing.T) {
	old, cur := newCert(t, "vulnerable", nil), newCert(t, "clean", nil)
	ch := diff(run(t, old.opts), run(t, cur.opts))
	for _, want := range []string{"Image: ", "Result: FAILED → PASSED", "vulns: FAILED → PASSED", "Gone from vulns: CRITICAL CVE-2021-44228"} {
		if !slices.ContainsFunc(ch.Lines, func(l string) bool { return strings.HasPrefix(l, want) }) {
			t.Errorf("no line starting %q in %q", want, ch.Lines)
		}
	}
	if ch.SameArtifact {
		t.Error("different images reported as the same")
	}
	if same := diff(run(t, cur.opts), run(t, cur.opts)); len(same.Lines) != 0 || !same.SameArtifact {
		t.Errorf("a certificate compared with itself: %+v", same)
	}
}

// A "previous" certificate from a signer the trust policy doesn't list is not compared.
func TestPreviousMustAuthenticate(t *testing.T) {
	cur, other := newCert(t, "clean", nil), newCert(t, "vulnerable", nil)
	cur.opts.Previous = other.bundle
	r := run(t, cur.opts)
	expect(t, r, OK, "")
	if r.Changes != nil || !slices.ContainsFunc(r.Notes, func(n string) bool { return strings.Contains(n, "previous certificate not compared: UNTRUSTED_SIGNER") }) {
		t.Fatalf("changes = %+v, notes = %v", r.Changes, r.Notes)
	}
}
