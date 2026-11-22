# Run: ./test.sh  (opa test policy.rego policy_test.rego fixtures/inputs)
# fixtures/inputs/<case>/input.json is loaded as data.<case>: real tool output from fixtures/generate.sh.
package otrust.scb.v1_test

import rego.v1

import data.otrust.scb.v1 as scb
import data.otrust.scb.v1.source_path

clean := data.clean
vuln := data.vulnerable

decide(inp) := d if d := scb.decision with input as inp

check_result(d, id) := r if {
	some c in d.checks
	c.id == id
	r := c.result
}

future := "2099-01-01T00:00:00Z"

past := "2000-01-01T00:00:00Z"

# ---- real fixtures

test_clean_image_passes if {
	d := decide(clean)
	d.result == "PASSED"
	d.unmet_requirements == []
	every c in d.checks { c.result == "PASSED" }
}

test_vulnerable_image_fails_on_vulns_secrets_sast if {
	d := decide(vuln)
	d.result == "FAILED"
	{c.id | some c in d.checks; c.result == "FAILED"} == {"vulns", "secrets", "sast"}
	"vulns: CRITICAL CVE-2021-44228 in org.apache.logging.log4j:log4j-core@2.14.1 (fixed in: 2.15.0, 2.3.1, 2.12.2)" in d.unmet_requirements
}

test_medium_vulns_do_not_fail if {
	d := decide(vuln)
	every u in d.unmet_requirements { not contains(u, "MEDIUM") }
}

# ---- required checks

test_missing_check_evidence_fails if {
	d := decide(json.remove(clean, ["evidence/sast"]))
	d.result == "FAILED"
	"sast: missing SAST evidence" in d.unmet_requirements
}

test_empty_sbom_fails if {
	d := decide(json.patch(clean, [{"op": "replace", "path": "/evidence/sbom/components", "value": []}]))
	check_result(d, "sbom") == "FAILED"
}

test_vuln_scan_must_be_of_the_sbom if {
	d := decide(json.patch(clean, [{"op": "replace", "path": "/evidence/vulns/ArtifactType", "value": "filesystem"}]))
	check_result(d, "vulns") == "FAILED"
}

# ---- severity levels

high_no_fix := {"ArtifactType": "cyclonedx", "Results": [{"Vulnerabilities": [{"VulnerabilityID": "CVE-2026-0001", "Severity": "HIGH", "PkgName": "p", "InstalledVersion": "1.0"}]}]}

test_high_without_fix_warns_but_passes if {
	d := decide(json.patch(clean, [{"op": "replace", "path": "/evidence/vulns", "value": high_no_fix}]))
	check_result(d, "vulns") == "WARN"
	d.result == "PASSED"
}

sast_warning := {"results": [{"check_id": "r.warn", "path": "a.java", "start": {"line": 1}, "extra": {"severity": "WARNING"}}], "errors": []}

test_sast_warning_warns_but_passes if {
	d := decide(json.patch(clean, [{"op": "replace", "path": "/evidence/sast", "value": sast_warning}]))
	check_result(d, "sast") == "WARN"
	d.result == "PASSED"
}

test_sast_scan_errors_warn if {
	d := decide(json.patch(clean, [{"op": "replace", "path": "/evidence/sast/errors", "value": [{"message": "parse error"}]}]))
	check_result(d, "sast") == "WARN"
}

# ---- provenance & subject binding

test_missing_provenance_fails if {
	d := decide(json.patch(clean, [{"op": "replace", "path": "/provenance/present", "value": false}]))
	check_result(d, "provenance") == "FAILED"
}

test_unsigned_provenance_warns if {
	d := decide(json.patch(clean, [{"op": "replace", "path": "/provenance/signed", "value": false}]))
	check_result(d, "provenance") == "WARN"
	d.result == "PASSED"
}

test_subject_mismatch_fails if {
	d := decide(json.patch(clean, [{"op": "replace", "path": "/subject/assessed_digest", "value": "sha256:other"}]))
	check_result(d, "subject_binding") == "FAILED"
	d.result == "FAILED"
}

# ---- exceptions

with_exceptions(inp, es) := json.patch(inp, [{"op": "replace", "path": "/exceptions", "value": es}])

test_valid_exception_removes_finding_and_is_reported if {
	e := {"check": "vulns", "id": "CVE-2021-44228", "reason": "JNDI lookups disabled", "expires": future}
	d := decide(with_exceptions(vuln, [e]))
	every u in d.unmet_requirements { not contains(u, "CVE-2021-44228") }
	e in d.exceptions_applied
}

test_excepting_every_failure_passes if {
	es := [
		{"check": "vulns", "id": "CVE-2021-44228", "reason": "r", "expires": future},
		{"check": "vulns", "id": "CVE-2021-45046", "reason": "r", "expires": future},
		{"check": "vulns", "id": "CVE-2021-45105", "reason": "r", "expires": future},
		{"check": "secrets", "id": "config/deploy.pem#private-key", "reason": "test key", "expires": future},
		{"check": "sast", "id": sqli, "path": sqli_file, "reason": "r", "expires": future},
	]
	d := decide(with_exceptions(vuln, es))
	d.result == "PASSED"
	count(d.exceptions_applied) == 5
}

test_expired_exception_is_ignored if {
	e := {"check": "vulns", "id": "CVE-2021-44228", "reason": "r", "expires": past}
	d := decide(with_exceptions(vuln, [e]))
	some u in d.unmet_requirements
	contains(u, "CVE-2021-44228")
	count(d.exceptions_ignored) == 1
}

test_exception_without_reason_is_ignored if {
	e := {"check": "vulns", "id": "CVE-2021-44228", "reason": " ", "expires": future}
	d := decide(with_exceptions(vuln, [e]))
	count(d.exceptions_ignored) == 1
	count(d.exceptions_applied) == 0
}

test_structural_requirements_cannot_be_excepted if {
	inp := json.patch(clean, [{"op": "replace", "path": "/provenance/present", "value": false}])
	e := {"check": "provenance", "id": "no build provenance for the subject", "reason": "r", "expires": future}
	d := decide(with_exceptions(inp, [e]))
	d.result == "FAILED"
	count(d.exceptions_ignored) == 1
}

test_signed_provenance_from_another_repo_warns if {
	d := decide(json.patch(clean, [{"op": "replace", "path": "/provenance/signer_trusted", "value": false}]))
	check_result(d, "provenance") == "WARN"
	d.result == "PASSED"
}

test_provenance_for_another_artifact_fails if {
	d := decide(json.patch(clean, [{"op": "replace", "path": "/provenance/subject_match", "value": false}]))
	check_result(d, "provenance") == "FAILED"
	d.result == "FAILED"
}

# ---- 1.1.0: SAST coverage

test_uncovered_language_warns_but_does_not_fail if {
	inp := object.union(clean, {"sast_coverage": [
		{"language": "go", "files": 19, "rules": 84},
		{"language": "cpp", "files": 3, "rules": 0},
	]})
	d := decide(inp)
	d.result == "PASSED"
	check_result(d, "sast") == "WARN"
	some c in d.checks
	c.id == "sast"
	"no SAST rules for cpp (3 files): not analysed" in c.findings
}

test_covered_languages_stay_silent if {
	d := decide(object.union(clean, {"sast_coverage": [{"language": "java", "files": 1, "rules": 118}]}))
	check_result(d, "sast") == "PASSED"
}

test_uncovered_language_can_be_excepted if {
	inp := object.union(clean, {
		"sast_coverage": [{"language": "cpp", "files": 3, "rules": 0}],
		"exceptions": [{"check": "sast", "id": "no-rules:cpp", "reason": "vendored third-party C++, reviewed separately", "expires": future}],
	})
	check_result(decide(inp), "sast") == "PASSED"
}

# ---- 1.2.0: SAST exceptions are per file

sqli := "java.lang.security.audit.formatted-sql-string.formatted-sql-string"

sqli_file := "/fx/src/vulnerable/app/Main.java"

test_sast_exception_without_path_does_not_cover_a_file if {
	e := {"check": "sast", "id": sqli, "reason": "r", "expires": future}
	d := decide(with_exceptions(vuln, [e]))
	check_result(d, "sast") == "FAILED"
	count(d.exceptions_applied) == 0
}

test_sast_exception_for_another_file_does_not_apply if {
	e := {"check": "sast", "id": sqli, "path": "src/other/Main.java", "reason": "r", "expires": future}
	check_result(decide(with_exceptions(vuln, [e])), "sast") == "FAILED"
}

test_sast_exception_for_the_file_applies_once if {
	two := object.union(vuln, {"evidence": object.union(vuln.evidence, {"sast": object.union(vuln.evidence.sast, {"results": [
		vuln.evidence.sast.results[0],
		object.union(vuln.evidence.sast.results[0], {"start": {"line": 99}}),
	]})})})
	e := {"check": "sast", "id": sqli, "path": sqli_file, "reason": "fixture", "expires": future}
	d := decide(with_exceptions(two, [e]))
	check_result(d, "sast") != "FAILED"
	d.exceptions_applied == {e}
}

test_docker_and_local_paths_are_the_same_file if {
	source_path("/src/internal/a.go") == "internal/a.go"
	source_path("src/internal/a.go") == "internal/a.go"
}
