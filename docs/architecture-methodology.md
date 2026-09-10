# Architecture and Methodology

## Objective

This lab demonstrates a defensive container-security review workflow that combines workload hardening, artifact integrity, vulnerability context and ownership governance. It uses synthetic metadata only and performs no live Docker daemon interaction.

## Assessment flow

`synthetic image metadata -> validated model -> deterministic controls -> severity classification -> posture score -> remediation -> revalidation`

## Control families

- Runtime privilege: privileged mode, root execution, privilege escalation and dangerous Linux capabilities.
- Filesystem hardening: read-only root filesystem and explicit writable paths.
- Supply-chain integrity: digest pinning, signatures and SBOM presence.
- Vulnerability management: critical findings and concentrated high-severity backlog.
- Operational governance: ownership and health-check coverage.

## Scoring

Each finding has a severity weight. The posture score starts at 100 and subtracts capped severity-weighted risk. It is intended as a compact engineering indicator, not as a substitute for exploitability analysis, business context or production risk acceptance.

## MITRE ATT&CK context

- T1611 — Escape to Host: used as contextual mapping for excessive container privilege.
- T1195.002 — Compromise Software Supply Chain: used for image integrity and provenance gaps.
- T1190 — Exploit Public-Facing Application: used as contextual relevance for exploitable vulnerable workload components.

ATT&CK mappings communicate defensive threat context only and do not assert that exploitation occurred.

## Remediation validation

Closure requires a repeatable re-assessment of the exact intended release configuration or image digest. For example, removing `privileged=true` must be verified against the final deployment spec; signing claims should be validated against the released digest; vulnerability closure requires a re-scan of the exact artifact.

## Limitations

The project does not inspect real Docker sockets, Kubernetes clusters, registries, image layers or CVE feeds. It intentionally models assessment logic rather than performing production discovery or exploitation.
