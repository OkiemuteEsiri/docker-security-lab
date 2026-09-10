from __future__ import annotations
from collections import Counter
from .models import ContainerImage, Finding
from .analyzer import posture_score


def render_markdown(image: ContainerImage, findings: list[Finding]) -> str:
    counts = Counter(f.severity for f in findings)
    lines = [
        f"# Container Security Assessment — {image.image}:{image.tag}",
        "",
        "> Synthetic assessment output. No production environment was assessed.",
        "",
        f"- Posture score: **{posture_score(findings)}/100**",
        f"- Findings: **{len(findings)}**",
        f"- Critical: **{counts['critical']}** | High: **{counts['high']}** | Medium: **{counts['medium']}** | Low: **{counts['low']}**",
        "",
        "| ID | Severity | Control | Evidence |",
        "|---|---|---|---|",
    ]
    for f in findings:
        lines.append(f"| {f.finding_id} | {f.severity.title()} | {f.control_id} — {f.title} | {f.evidence} |")
    lines.extend(["", "## Remediation and validation", ""])
    for f in findings:
        lines.extend([
            f"### {f.finding_id} — {f.title}",
            f"- Remediation: {f.remediation}",
            f"- Validation: {f.validation}",
            f"- ATT&CK context: {', '.join(f.attack_techniques) if f.attack_techniques else 'N/A'}",
            "",
        ])
    return "\n".join(lines)
