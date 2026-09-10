# Docker Security Lab

A defensive DevSecOps, Container Security and Software Supply Chain portfolio project that demonstrates how container image and runtime metadata can be translated into repeatable security controls, explainable findings, remediation priorities and validation evidence.

## Problem statement

Container risk is rarely caused by one issue alone. Excessive privilege, weak artifact provenance, vulnerable base images, mutable references, missing ownership and weak runtime hardening often combine to increase exposure. This project models those concerns as deterministic, testable controls rather than relying on an opaque scanner score.

## Architecture

```text
Synthetic image/runtime metadata
            |
            v
Validated container model
            |
            v
Deterministic security controls
            |
            v
Severity + posture scoring
            |
            v
Markdown assessment
            |
            v
Remediation -> revalidation
```

## Implemented capabilities

- privileged-container detection
- root-execution detection
- privilege-escalation review
- dangerous Linux capability checks
- read-only root filesystem assessment
- immutable digest-pinning checks
- image-signature and provenance checks
- SBOM-presence checks
- critical/high vulnerability concentration checks
- ownership and health-check governance
- deterministic finding IDs
- bounded posture scoring
- MITRE ATT&CK contextual mappings
- realistic synthetic container inventory
- unit-tested defensive assessment logic
- least-privilege GitHub Actions quality gate

## Repository structure

```text
src/models.py                      validated data and finding models
src/analyzer.py                    deterministic security controls and posture score
src/reporting.py                   Markdown assessment output
data/synthetic_images.json         realistic synthetic container inventory
tests/test_analyzer.py             unit tests
docs/architecture-methodology.md   architecture, scoring and validation methodology
reports/example-assessment.md       recruiter-facing synthetic assessment
.github/workflows/security-quality.yml
README.md
```

## Control catalogue

| Control | Theme | Default severity |
|---|---|---|
| CTR-001 | Privileged container | Critical |
| CTR-002 | Root execution | High |
| CTR-003 | Privilege escalation allowed | High |
| CTR-004 | Dangerous Linux capabilities | High |
| CTR-005 | Writable root filesystem | Medium |
| CTR-006 | Image not digest pinned | Medium |
| CTR-007 | Missing image signature | High |
| CTR-008 | Missing SBOM | Medium |
| CTR-009 | Critical vulnerabilities | Critical |
| CTR-010 | High vulnerability concentration | High |
| CTR-011 | Missing ownership | Medium |
| CTR-012 | Missing health check | Low |

## MITRE ATT&CK context

The project maps relevant controls to **T1611 (Escape to Host)**, **T1195.002 (Compromise Software Supply Chain)** and **T1190 (Exploit Public-Facing Application)** where useful. These mappings communicate defensive threat context only; a failed control is not evidence that an adversary technique occurred.

## Example use

The synthetic inventory contains contrasting workloads: a hardened web image, a payments API with multiple governance and runtime weaknesses, and a batch worker with excessive privilege. The example report shows how the findings can be converted into an engineering remediation sequence rather than a flat vulnerability list.

## Testing

The unit suite validates the secure baseline, privileged mode, root execution, privilege escalation, dangerous capabilities, mutable references, signing/SBOM gaps, vulnerability thresholds, missing ownership/health checks, score bounds and input validation.

Run locally with:

```bash
python -m unittest discover -s tests -v
```

## Remediation and validation workflow

1. Confirm the finding against the intended release artifact or deployment configuration.
2. Assign an accountable engineering owner.
3. Prioritize critical privilege and vulnerable-component issues first.
4. Implement the smallest durable security change.
5. Rebuild/redeploy using an immutable image digest where applicable.
6. Re-run the same control against the final artifact/configuration.
7. Retain sanitized before/after evidence before closure.
8. Keep the control in CI/admission policy where practical to prevent regression.

## Skills demonstrated

Container security engineering, DevSecOps control design, software supply-chain security, vulnerability management, runtime hardening, artifact provenance, SBOM governance, defensive Python engineering, unit testing, security reporting, ATT&CK contextualization and remediation validation.

## Limitations

This repository uses synthetic metadata and does not connect to Docker sockets, Kubernetes clusters, registries, cloud accounts, CVE feeds or production workloads. It does not exploit containers, escape sandboxes, pull secrets, scan live systems or claim production validation.

## Roadmap

- add JSON ingestion and CLI execution path
- add Dockerfile/config lint adapters using synthetic fixtures
- add policy-as-code examples for admission control
- add structured JSON/SARIF-style output
- add remediation SLA and exception tracking
- expand supply-chain provenance validation

## Safety

All data and examples are synthetic. No employer/client information, real credentials, production targets, exploit payloads, malware, container-escape code or offensive automation are included.
