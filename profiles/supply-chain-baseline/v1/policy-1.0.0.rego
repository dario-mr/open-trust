# Supply-Chain Baseline v1 — see profile.md for the human-readable spec.
# Input: the document otrust assembles (fixtures/inputs/*/input.json shows the exact shape).
# Output: data.otrust.scb.v1.decision
package otrust.scb.v1

import rego.v1

profile := {"id": "supply-chain-baseline", "version": "1.0.0"}

required_checks := ["sbom", "vulns", "secrets", "sast", "provenance", "subject_binding"]

# Only finding-level results can be excepted; structural requirements never can.
exceptable := {"vulns", "secrets", "sast"}

# ---------------------------------------------------------------- findings
# findings[check] contains {"key", "level": "fail"|"warn", "message", "structural"?}

# sbom
findings.sbom contains structural("missing SBOM evidence") if not input.evidence.sbom

findings.sbom contains structural("SBOM is not CycloneDX") if {
	input.evidence.sbom
	input.evidence.sbom.bomFormat != "CycloneDX"
}

findings.sbom contains structural("SBOM has no components") if {
	input.evidence.sbom
	count(object.get(input.evidence.sbom, "components", [])) == 0
}

# vulns (trivy sbom JSON)
findings.vulns contains structural("missing vulnerability evidence") if not input.evidence.vulns

# D4: the vulnerability scan must be of the SBOM, not of something else
findings.vulns contains structural("vulnerability scan was not run on the CycloneDX SBOM") if {
	input.evidence.vulns
	input.evidence.vulns.ArtifactType != "cyclonedx"
}

findings.vulns contains f if {
	some r in object.get(input.evidence.vulns, "Results", [])
	some v in object.get(r, "Vulnerabilities", [])
	fixed := object.get(v, "FixedVersion", "")
	level := vuln_level(v.Severity, fixed)
	f := {
		"key": v.VulnerabilityID,
		"level": level,
		"message": sprintf("%s %s in %s@%s (fixed in: %s)", [v.Severity, v.VulnerabilityID, v.PkgName, v.InstalledVersion, fixed_or_none(fixed)]),
	}
}

vuln_level("CRITICAL", _) := "fail"

vuln_level("HIGH", fixed) := "fail" if fixed != ""

vuln_level("HIGH", "") := "warn"

fixed_or_none("") := "none"

fixed_or_none(x) := x if x != ""

# secrets (trivy fs --scanners secret JSON)
findings.secrets contains structural("missing secrets evidence") if not input.evidence.secrets

findings.secrets contains f if {
	some r in object.get(input.evidence.secrets, "Results", [])
	some s in object.get(r, "Secrets", [])
	f := {
		"key": sprintf("%s#%s", [r.Target, s.RuleID]),
		"level": "fail",
		"message": sprintf("%s secret '%s' in %s:%d", [s.Severity, s.Title, r.Target, s.StartLine]),
	}
}

# sast (semgrep --json)
findings.sast contains structural("missing SAST evidence") if not input.evidence.sast

findings.sast contains f if {
	some res in object.get(input.evidence.sast, "results", [])
	level := sast_level[res.extra.severity]
	f := {
		"key": res.check_id,
		"level": level,
		"message": sprintf("%s %s at %s:%d", [res.extra.severity, res.check_id, res.path, res.start.line]),
	}
}

sast_level := {"ERROR": "fail", "WARNING": "warn"}

# Partial scan coverage is visible but not fatal: parse errors are common in real code.
findings.sast contains {"key": "scan-errors", "level": "warn", "message": sprintf("semgrep reported %d scan error(s)", [n])} if {
	n := count(object.get(input.evidence.sast, "errors", []))
	n > 0
}

# provenance (computed by otrust from the provenance attestation)
findings.provenance contains structural("no build provenance for the subject") if not input.provenance.present

findings.provenance contains structural("provenance subject does not match the assessed artifact") if {
	input.provenance.present
	not input.provenance.subject_match
}

findings.provenance contains {"key": "unsigned", "level": "warn", "message": "provenance is not signed"} if {
	input.provenance.present
	not input.provenance.signed
}

findings.provenance contains {"key": "untrusted-signer", "level": "warn", "message": "provenance signer is not in the trust policy"} if {
	input.provenance.signed
	not input.provenance.signer_trusted
}

# subject binding (computed by otrust: digest assessed == digest signed)
findings.subject_binding contains structural("missing subject digest") if not input.subject.digest

findings.subject_binding contains structural(sprintf("assessed %s but certificate subject is %s", [input.subject.assessed_digest, input.subject.digest])) if {
	input.subject.digest
	input.subject.assessed_digest != input.subject.digest
}

structural(msg) := {"key": msg, "level": "fail", "message": msg, "structural": true}

# ---------------------------------------------------------------- exceptions

exception_valid(e) if {
	e.check in exceptable
	count(trim_space(object.get(e, "reason", ""))) > 0
	time.parse_rfc3339_ns(e.expires) > time.parse_rfc3339_ns(input.now)
}

excepted(check, f) if {
	not f.structural
	some e in object.get(input, "exceptions", [])
	e.check == check
	e.id == f.key
	exception_valid(e)
}

effective(check) := {f | some f in object.get(findings, check, set()); not excepted(check, f)}

# ---------------------------------------------------------------- results

has_level(fs, level) if {
	some f in fs
	f.level == level
}

result_of(fs) := "FAILED" if has_level(fs, "fail")

result_of(fs) := "WARN" if {
	not has_level(fs, "fail")
	has_level(fs, "warn")
}

result_of(fs) := "PASSED" if {
	not has_level(fs, "fail")
	not has_level(fs, "warn")
}

checks := [{"id": c, "result": result_of(effective(c)), "findings": sort([f.message | some f in effective(c)])} |
	some c in required_checks
]

default result := "PASSED"

result := "FAILED" if {
	some c in checks
	c.result == "FAILED"
}

decision := {
	"profile": profile,
	"result": result,
	"checks": checks,
	"unmet_requirements": sort([sprintf("%s: %s", [c, f.message]) |
		some c in required_checks
		some f in effective(c)
		f.level == "fail"
	]),
	"exceptions_applied": [e |
		some e in object.get(input, "exceptions", [])
		some f in object.get(findings, e.check, set())
		excepted(e.check, f)
		e.id == f.key
	],
	"exceptions_ignored": [{"exception": e, "reason": "invalid, expired, or not exceptable"} |
		some e in object.get(input, "exceptions", [])
		not exception_valid(e)
	],
}
