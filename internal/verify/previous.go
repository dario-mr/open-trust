package verify

import (
	"fmt"
	"slices"
)

// Changes compares this certificate with an earlier one for the same product.
type Changes struct {
	Assessed     string   // the previous certificate's assessment time
	SameArtifact bool     // both certificates are for the same image digest
	Lines        []string // what changed, one item per line; empty means nothing did
}

// comparePrevious authenticates the previous certificate with the same trust policy (so a forged
// "previous" can't misreport changes) and lists what changed. A failure becomes a note, not a result.
func comparePrevious(path, trustedRoot string, tp *TrustPolicy, cur *Report) (*Changes, string, error) {
	prev, _, err := authenticate(path, trustedRoot, tp)
	if err != nil {
		return nil, "", err
	}
	if prev.Code != "" {
		return nil, fmt.Sprintf("previous certificate not compared: %s: %s", prev.Code, prev.Reason), nil
	}
	return diff(prev, cur), "", nil
}

func diff(prev, cur *Report) *Changes {
	a, b := prev.Predicate, cur.Predicate
	ch := &Changes{Assessed: a.TimeVerified, SameArtifact: prev.SubjectDigest == cur.SubjectDigest, Lines: []string{}}
	add := func(format string, v ...any) { ch.Lines = append(ch.Lines, fmt.Sprintf(format, v...)) }
	if !ch.SameArtifact {
		add("Image: %s → %s", prev.SubjectDigest, cur.SubjectDigest)
	}
	if a.Ext.CI.Revision != b.Ext.CI.Revision {
		add("Source revision: %s → %s", orNone(a.Ext.CI.Revision), orNone(b.Ext.CI.Revision))
	}
	if prev.TrustLevel != cur.TrustLevel {
		add("Trust level: %s → %s", prev.TrustLevel, cur.TrustLevel)
	}
	if a.VerificationResult != b.VerificationResult {
		add("Result: %s → %s", a.VerificationResult, b.VerificationResult)
	}
	old := map[string]checkState{}
	for _, c := range a.Ext.Checks {
		old[c.ID] = checkState{c.Result, c.Findings}
	}
	for _, c := range b.Ext.Checks {
		o := old[c.ID]
		if o.result != "" && o.result != c.Result {
			add("%s: %s → %s", c.ID, o.result, c.Result)
		}
		was, is := findingKeys(o.findings), findingKeys(c.Findings)
		for _, f := range c.Findings {
			if !was[findingKey(f)] {
				add("New in %s: %s", c.ID, f)
			}
		}
		for _, f := range o.findings {
			if !is[findingKey(f)] {
				add("Gone from %s: %s", c.ID, f)
			}
		}
	}
	var oldEx, newEx []string
	for _, e := range a.Ext.Exceptions {
		oldEx = append(oldEx, e.Check+" "+e.ID)
	}
	for _, e := range b.Ext.Exceptions {
		k := e.Check + " " + e.ID
		newEx = append(newEx, k)
		if !slices.Contains(oldEx, k) {
			add("New exception: %s (expires %s): %s", k, e.Expires, e.Reason)
		}
	}
	for _, k := range oldEx {
		if !slices.Contains(newEx, k) {
			add("Exception dropped: %s", k)
		}
	}
	return ch
}

type checkState struct {
	result   string
	findings []string
}

// findingKey identifies a vulnerability finding by ID and package, so a new "fixed in" version
// doesn't count as a change; other findings are compared as written.
func findingKey(f string) string {
	if id, pkg := vulnKey(f); id != "" {
		return id + " " + pkg
	}
	return f
}

func findingKeys(fs []string) map[string]bool {
	m := map[string]bool{}
	for _, f := range fs {
		m[findingKey(f)] = true
	}
	return m
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}
