# What a buyer sees

Real `otrust verify` reports, written with `--report <file>.md` from real certificates (otrust v0.1.16, profile 1.2.0):

| Report | Situation | Result |
|---|---|---|
| [1-verified.md](1-verified.md) | The demo's clean build, from the isolated assessor on GitHub, checked with the vendor's evidence and the buyer's own re-scan | `VERIFIED` |
| [2-assessment-failed.md](2-assessment-failed.md) | The same app with log4j 2.14.1 | `ASSESSMENT_FAILED` |
| [3-lying-vendor-caught.md](3-lying-vendor-caught.md) | A vendor who holds a signing key signs a clean result for the log4j image; the buyer's `--recheck` catches it ([terminal version](3-lying-vendor-caught.terminal.txt)) | `RECHECK_MISMATCH` |
| [4-node-service-failed.md](4-node-service-failed.md) | A third-party Node.js service (excalidraw-room) on end-of-life `node:12` | `ASSESSMENT_FAILED`, 94 known vulnerabilities |

Make your own from any certificate:

```bash
otrust verify certificate.sigstore.json --image image.oci.tar --trust-policy trust.yaml --online --report report.md
```
