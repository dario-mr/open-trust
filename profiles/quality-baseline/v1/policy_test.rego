package otrust.quality.v1_test

import rego.v1

import data.otrust.quality.v1 as q

future := "2099-01-01T00:00:00Z"

lib(purl, licences) := {"type": "library", "name": "x", "version": "1", "purl": purl, "licenses": [{"license": {"id": l}} | some l in licences]}

input_with(components, os) := {
	"now": "2026-11-28T00:00:00Z",
	"evidence": {"sbom": {"components": components}, "vulns": {"Metadata": {"OS": os}}},
	"exceptions": [],
}

debian := {"Family": "debian", "Name": "12.13"}

result_of(d, id) := r if {
	some c in d.checks
	c.id == id
	r := c.result
}

decide(inp) := d if d := q.decision with input as inp

test_permissive_dependencies_pass if {
	d := decide(input_with([lib("pkg:maven/a/b@1", ["Apache-2.0"]), lib("pkg:npm/c@2", ["MIT"])], debian))
	d.result == "PASSED"
	every c in d.checks { c.result == "PASSED" }
}

test_gpl_application_dependency_fails if {
	d := decide(input_with([lib("pkg:npm/c@2?arch=x", ["GPL-3.0-only"])], debian))
	result_of(d, "licenses") == "FAILED"
	"licenses: strong copyleft gpl-3.0-only in pkg:npm/c@2" in d.unmet_requirements
}

test_gpl_os_packages_are_fine if {
	d := decide(input_with([lib("pkg:deb/debian/tzdata@1", ["GPL-2.0-only"]), lib("pkg:apk/alpine/busybox@1", ["GPL-2.0-only"])], debian))
	result_of(d, "licenses") == "PASSED"
}

test_weak_copyleft_and_exceptions_and_dual_licences_pass if {
	d := decide(input_with([
		lib("pkg:maven/a/lgpl@1", ["LGPL-2.1-only"]),
		lib("pkg:maven/a/cp@1", ["GPL-2.0-with-classpath-exception"]),
		{"type": "library", "name": "d", "version": "1", "purl": "pkg:npm/d@1", "licenses": [{"expression": "MIT OR GPL-2.0-only"}]},
		{"type": "library", "name": "e", "version": "1", "purl": "pkg:maven/e@1", "licenses": [{"license": {"name": "https://www.eclipse.org/legal/epl-v20.html, https://www.gnu.org/licenses/old-licenses/gpl-2.0.html"}}]},
	], debian))
	result_of(d, "licenses") == "PASSED"
}

test_agpl_by_url_fails if {
	d := decide(input_with([{"type": "library", "name": "s", "version": "1", "purl": "pkg:maven/s@1", "licenses": [{"license": {"name": "https://www.gnu.org/licenses/agpl-3.0.html"}}]}], debian))
	result_of(d, "licenses") == "FAILED"
}

test_unknown_licences_warn_once if {
	d := decide(input_with([lib("pkg:golang/a@1", []), lib("pkg:golang/b@1", []), lib("pkg:golang/c@1", ["MIT"])], debian))
	result_of(d, "licenses") == "WARN"
	some c in d.checks
	c.id == "licenses"
	c.findings == ["2 of 3 application dependencies have no detected licence"]
}

test_missing_version_warns if {
	d := decide(input_with([{"type": "library", "name": "n", "purl": "pkg:npm/n", "licenses": [{"license": {"id": "MIT"}}]}], debian))
	result_of(d, "sbom_completeness") == "WARN"
}

test_end_of_life_os_fails if {
	d := decide(input_with([lib("pkg:npm/c@2", ["MIT"])], {"Family": "alpine", "Name": "3.15.4", "EOSL": true}))
	result_of(d, "os_support") == "FAILED"
	"os_support: alpine 3.15.4 is end of life: it gets no more security fixes" in d.unmet_requirements
}

test_copyleft_and_eol_can_be_excepted if {
	inp := object.union(input_with([lib("pkg:npm/c@2", ["GPL-3.0-only"])], {"Family": "alpine", "Name": "3.15.4", "EOSL": true}), {"exceptions": [
		{"check": "licenses", "id": "pkg:npm/c@2", "reason": "internal tool, not distributed", "expires": future},
		{"check": "os_support", "id": "eosl:alpine-3.15.4", "reason": "replaced next sprint", "expires": future},
	]})
	d := decide(inp)
	d.result == "PASSED"
	count(d.exceptions_applied) == 2
}

test_other_profiles_exceptions_are_not_ours if {
	inp := object.union(input_with([lib("pkg:npm/c@2", ["MIT"])], debian), {"exceptions": [
		{"check": "vulns", "id": "CVE-1", "reason": "r", "expires": future},
	]})
	d := decide(inp)
	count(d.exceptions_applied) == 0
	count(d.exceptions_ignored) == 0
}

test_missing_evidence_is_structural if {
	d := decide({"now": "2026-11-28T00:00:00Z", "evidence": {}, "exceptions": []})
	d.result == "FAILED"
	every c in d.checks { c.result == "FAILED" }
}
