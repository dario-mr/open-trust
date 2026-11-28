# Quality Baseline v1: see profile.md. Same input document as Supply-Chain Baseline v1; it reads
# the SBOM (input.evidence.sbom) and the vulnerability scan's OS metadata (input.evidence.vulns).
# Output: data.otrust.quality.v1.decision
package otrust.quality.v1

import rego.v1

profile := {"id": "quality-baseline", "version": "1.0.0"}

required_checks := ["licenses", "sbom_completeness", "os_support"]

exceptable := {"licenses", "sbom_completeness", "os_support"}

# ---------------------------------------------------------------- application dependencies

# OS packages ship under their distribution's terms (Debian's own packages are often GPL); the
# licence and completeness rules are about the application's dependencies.
os_package_types := {"deb", "apk", "rpm", "alpm"}

app_deps := [c |
	some c in object.get(input.evidence.sbom, "components", [])
	c.type == "library"
	not purl_type(c) in os_package_types
]

purl_type(c) := t if {
	startswith(object.get(c, "purl", ""), "pkg:")
	t := split(substring(c.purl, 4, -1), "/")[0]
}

# a component's identity for findings and exceptions: its purl without qualifiers, or name@version
dep_key(c) := split(c.purl, "?")[0] if object.get(c, "purl", "") != ""

dep_key(c) := sprintf("%s@%s", [c.name, object.get(c, "version", "")]) if object.get(c, "purl", "") == ""

# every licence string a component declares; each entry, and each OR alternative, is a choice
licence_choices(c) := [lower(trim_space(alt)) |
	some l in object.get(c, "licenses", [])
	s := licence_string(l)
	some part in split(s, ",")
	some alt in regex.split(`(?i)\s+or\s+`, part)
	trim_space(alt) != ""
]

licence_string(l) := l.expression if l.expression

licence_string(l) := object.get(l.license, "id", object.get(l.license, "name", "")) if not l.expression

# strong copyleft: GPL (not LGPL), AGPL, SSPL; a GPL with an exception (e.g. Classpath) is not
strong_copyleft(s) if {
	regex.match(`(^|[^l])gpl|agpl|sspl|gnu\.org/licenses/(gpl|agpl)`, s)
	not contains(s, "exception")
	not contains(s, "lgpl")
}

# ---------------------------------------------------------------- findings

findings.licenses contains structural("missing SBOM evidence") if not input.evidence.sbom

# fails only when no choice is permissive: dual-licensed "MIT OR GPL-2.0" is fine
findings.licenses contains f if {
	some c in app_deps
	choices := licence_choices(c)
	count(choices) > 0
	every s in choices { strong_copyleft(s) }
	f := {
		"key": dep_key(c),
		"level": "fail",
		"message": sprintf("strong copyleft %s in %s", [concat(" OR ", choices), dep_key(c)]),
	}
}

findings.licenses contains f if {
	unknown := [c | some c in app_deps; count(licence_choices(c)) == 0]
	count(unknown) > 0
	f := {
		"key": "unknown-licenses",
		"level": "warn",
		"message": sprintf("%d of %d application dependencies have no detected licence", [count(unknown), count(app_deps)]),
	}
}

findings.sbom_completeness contains structural("missing SBOM evidence") if not input.evidence.sbom

findings.sbom_completeness contains structural("SBOM has no components") if {
	input.evidence.sbom
	count(object.get(input.evidence.sbom, "components", [])) == 0
}

findings.sbom_completeness contains f if {
	some field in ["version", "purl"]
	missing := [c | some c in app_deps; object.get(c, field, "") == ""]
	count(missing) > 0
	f := {
		"key": sprintf("missing-%s", [field]),
		"level": "warn",
		"message": sprintf("%d application dependencies have no %s", [count(missing), field]),
	}
}

findings.os_support contains structural("missing vulnerability evidence") if not input.evidence.vulns

# trivy marks an OS release whose security support has ended
findings.os_support contains f if {
	os := input.evidence.vulns.Metadata.OS
	os.EOSL == true
	f := {
		"key": sprintf("eosl:%s-%s", [os.Family, os.Name]),
		"level": "fail",
		"message": sprintf("%s %s is end of life: it gets no more security fixes", [os.Family, os.Name]),
	}
}

structural(msg) := {"key": msg, "level": "fail", "message": msg, "structural": true}

# ---------------------------------------------------------------- exceptions (this profile's checks only)

own_exceptions := [e | some e in object.get(input, "exceptions", []); e.check in required_checks]

exception_valid(e) if {
	e.check in exceptable
	count(trim_space(object.get(e, "reason", ""))) > 0
	time.parse_rfc3339_ns(e.expires) > time.parse_rfc3339_ns(input.now)
}

excepted(check, f) if {
	not f.structural
	some e in own_exceptions
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
	"exceptions_applied": {e |
		some e in own_exceptions
		some f in object.get(findings, e.check, set())
		excepted(e.check, f)
		e.id == f.key
	},
	"exceptions_ignored": [{"exception": e, "reason": "invalid, expired, or not exceptable"} |
		some e in own_exceptions
		not exception_valid(e)
	],
}
