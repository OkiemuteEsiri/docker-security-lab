# Example Container Security Assessment

> Synthetic example only. No production workload or organization was assessed.

## Executive summary

The synthetic `payments-api` image demonstrates a high-risk container posture driven by root execution, permitted privilege escalation, a dangerous Linux capability, mutable tag-only deployment, missing image signing/SBOM controls, a writable root filesystem, and a critical vulnerability. These conditions increase both compromise likelihood and blast radius if the workload is exposed.

## Priority findings

| Priority | Finding | Security concern |
|---|---|---|
| Immediate | Critical vulnerability present | Known vulnerable workload component requires remediation or governed exception |
| Immediate | Container runs with excessive privilege | Root/privilege escalation and NET_ADMIN expand potential impact |
| High | Image signature missing | Artifact provenance cannot be independently verified |
| High | Digest not pinned | Mutable references weaken reproducibility and deployment assurance |
| Medium | Writable root filesystem | Unnecessary write access increases post-compromise persistence opportunity |
| Medium | SBOM missing | Component inventory and downstream exposure analysis are weakened |

## Recommended sequence

1. Rebuild against a remediated base/dependency set and re-scan the exact digest.
2. Remove root execution and disable privilege escalation.
3. Drop NET_ADMIN unless a documented technical requirement exists.
4. Enable a read-only root filesystem with narrowly scoped writable mounts.
5. Sign the release artifact and verify the signature in deployment policy.
6. Generate an SBOM tied to the exact image digest.
7. Pin deployment references by digest.
8. Re-run the assessment and retain before/after evidence.

## Validation criteria

Closure is based on the final release artifact and deployment configuration, not only on source-code intent. Revalidation should prove that the remediated digest is deployed, critical findings have been addressed or explicitly governed, privilege controls are enforced, and provenance metadata matches the released artifact.
