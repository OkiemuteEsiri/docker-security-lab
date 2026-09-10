from __future__ import annotations
from .models import ContainerImage, Finding


def assess(image: ContainerImage) -> list[Finding]:
    findings: list[Finding] = []
    def add(control_id: str, title: str, severity: str, evidence: str, remediation: str, validation: str, attack=()):
        findings.append(Finding(control_id, title, severity, image.image, evidence, remediation, validation, tuple(attack)))

    if image.privileged:
        add("CTR-001", "Privileged container configuration", "critical", "privileged=true", "Remove privileged mode and grant only explicitly required permissions.", "Reassess runtime configuration and confirm privileged mode is disabled.", ("T1611",))
    if image.runs_as_root:
        add("CTR-002", "Container runs as root", "high", "effective user is root", "Use a dedicated non-root UID/GID and enforce it in image/runtime policy.", "Confirm runtime identity is non-root and application functionality remains intact.", ("T1611",))
    if image.allow_privilege_escalation:
        add("CTR-003", "Privilege escalation is allowed", "high", "allowPrivilegeEscalation=true", "Disable privilege escalation unless an approved exception exists.", "Confirm the runtime security context denies privilege escalation.", ("T1611",))
    dangerous = sorted(set(image.capabilities_added) & {"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "DAC_OVERRIDE"})
    if dangerous:
        add("CTR-004", "High-risk Linux capabilities added", "high", f"added={','.join(dangerous)}", "Drop unnecessary capabilities and use an allowlist based on application need.", "Reassess the final capability set and confirm high-risk additions are removed.", ("T1611",))
    if not image.read_only_rootfs:
        add("CTR-005", "Writable root filesystem", "medium", "readOnlyRootFilesystem=false", "Use a read-only root filesystem and explicit writable mounts where required.", "Confirm root filesystem is read-only in the deployment specification.")
    if not image.digest_pinned:
        add("CTR-006", "Image reference is not digest pinned", "medium", f"tag={image.tag}", "Pin deployment references to immutable image digests.", "Verify deployment resolves to the approved digest.", ("T1195.002",))
    if not image.signed:
        add("CTR-007", "Image signature missing", "high", "signed=false", "Sign release images and enforce signature verification in deployment policy.", "Verify the artifact signature and deployment admission decision.", ("T1195.002",))
    if not image.sbom_present:
        add("CTR-008", "SBOM missing", "medium", "sbom_present=false", "Generate and retain an SBOM for release artifacts.", "Confirm SBOM exists and matches the released image digest.", ("T1195.002",))
    if image.critical_vulns > 0:
        add("CTR-009", "Critical vulnerabilities present", "critical", f"critical_vulns={image.critical_vulns}", "Rebuild with remediated packages/base image or document a time-bounded exception.", "Re-scan the exact release digest and confirm critical findings are resolved or governed.", ("T1190",))
    elif image.high_vulns >= 5:
        add("CTR-010", "High vulnerability concentration", "high", f"high_vulns={image.high_vulns}", "Prioritize package/base-image updates and reduce inherited vulnerability backlog.", "Re-scan the exact release digest and compare residual risk.", ("T1190",))
    if not image.owner.strip():
        add("CTR-011", "Image ownership is missing", "medium", "owner is empty", "Assign an accountable service or engineering owner.", "Confirm ownership is present in artifact metadata and governance records.")
    if not image.healthcheck:
        add("CTR-012", "Container health check missing", "low", "healthcheck=false", "Define a health check appropriate to the workload.", "Confirm the orchestrator can detect unhealthy application state.")
    return sorted(findings, key=lambda f: ({"critical":0,"high":1,"medium":2,"low":3}[f.severity], f.finding_id))


def posture_score(findings: list[Finding]) -> int:
    weights = {"critical": 25, "high": 12, "medium": 6, "low": 2}
    return max(0, 100 - min(100, sum(weights[f.severity] for f in findings)))
