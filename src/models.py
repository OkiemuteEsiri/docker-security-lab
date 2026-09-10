from __future__ import annotations
from dataclasses import dataclass
from hashlib import sha256

SEVERITIES = {"critical", "high", "medium", "low"}

@dataclass(frozen=True)
class ContainerImage:
    image: str
    tag: str
    digest_pinned: bool
    runs_as_root: bool
    privileged: bool
    read_only_rootfs: bool
    allow_privilege_escalation: bool
    capabilities_added: tuple[str, ...]
    healthcheck: bool
    signed: bool
    sbom_present: bool
    critical_vulns: int
    high_vulns: int
    owner: str

    def __post_init__(self):
        if not self.image.strip() or not self.tag.strip():
            raise ValueError("image and tag are required")
        if self.critical_vulns < 0 or self.high_vulns < 0:
            raise ValueError("vulnerability counts cannot be negative")

@dataclass(frozen=True)
class Finding:
    control_id: str
    title: str
    severity: str
    image: str
    evidence: str
    remediation: str
    validation: str
    attack_techniques: tuple[str, ...] = ()

    def __post_init__(self):
        if self.severity not in SEVERITIES:
            raise ValueError("invalid severity")

    @property
    def finding_id(self) -> str:
        raw = f"{self.control_id}|{self.image}|{self.title}".lower().encode()
        return "CTR-" + sha256(raw).hexdigest()[:12].upper()
