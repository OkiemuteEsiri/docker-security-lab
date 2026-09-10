import unittest
from src.models import ContainerImage
from src.analyzer import assess, posture_score


class AnalyzerTests(unittest.TestCase):
    def image(self, **overrides):
        values = dict(
            image="registry.example.test/app",
            tag="1.0.0",
            digest_pinned=True,
            runs_as_root=False,
            privileged=False,
            read_only_rootfs=True,
            allow_privilege_escalation=False,
            capabilities_added=(),
            healthcheck=True,
            signed=True,
            sbom_present=True,
            critical_vulns=0,
            high_vulns=0,
            owner="App Team",
        )
        values.update(overrides)
        return ContainerImage(**values)

    def controls(self, image):
        return {f.control_id for f in assess(image)}

    def test_secure_baseline_has_no_findings(self):
        self.assertEqual(assess(self.image()), [])

    def test_privileged_container_is_critical(self):
        findings = assess(self.image(privileged=True))
        self.assertIn("CTR-001", {f.control_id for f in findings})
        self.assertEqual(next(f for f in findings if f.control_id == "CTR-001").severity, "critical")

    def test_root_and_privilege_escalation_are_detected(self):
        controls = self.controls(self.image(runs_as_root=True, allow_privilege_escalation=True))
        self.assertTrue({"CTR-002", "CTR-003"}.issubset(controls))

    def test_dangerous_capability_is_detected(self):
        self.assertIn("CTR-004", self.controls(self.image(capabilities_added=("NET_ADMIN",))))

    def test_unpinned_unsigned_missing_sbom_are_detected(self):
        controls = self.controls(self.image(digest_pinned=False, signed=False, sbom_present=False))
        self.assertTrue({"CTR-006", "CTR-007", "CTR-008"}.issubset(controls))

    def test_critical_vulnerability_is_detected(self):
        self.assertIn("CTR-009", self.controls(self.image(critical_vulns=1)))

    def test_high_vulnerability_concentration_is_detected(self):
        self.assertIn("CTR-010", self.controls(self.image(high_vulns=6)))

    def test_missing_owner_and_healthcheck_are_detected(self):
        controls = self.controls(self.image(owner="", healthcheck=False))
        self.assertTrue({"CTR-011", "CTR-012"}.issubset(controls))

    def test_posture_score_is_bounded(self):
        findings = assess(self.image(privileged=True, runs_as_root=True, critical_vulns=9, signed=False))
        self.assertGreaterEqual(posture_score(findings), 0)
        self.assertLessEqual(posture_score(findings), 100)

    def test_negative_vulnerability_count_is_rejected(self):
        with self.assertRaises(ValueError):
            self.image(critical_vulns=-1)


if __name__ == "__main__":
    unittest.main()
