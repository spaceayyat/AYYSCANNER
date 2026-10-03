import unittest

from ayyscanner.models import Finding, ScanResult
from ayyscanner.scanners import system


class SystemScannerSmokeTests(unittest.TestCase):
    """The system scanner inspects the machine it runs on, so these tests only assert
    the contract (well-formed results, no crash), not specific findings."""

    @classmethod
    def setUpClass(cls):
        cls.result = system.run_system_scan()

    def test_returns_a_well_formed_result(self):
        self.assertIsInstance(self.result, ScanResult)
        self.assertEqual(self.result.scan_type, "system")
        self.assertIsNotNone(self.result.finished_at)
        self.assertTrue(all(isinstance(f, Finding) and f.category == "system" for f in self.result.findings))

    def test_every_finding_is_complete_and_unique(self):
        for f in self.result.findings:
            self.assertTrue(f.id and f.title and f.description and f.remediation, f.id)
        keys = [f.dedupe_key for f in self.result.findings]
        self.assertEqual(len(keys), len(set(keys)))

    def test_result_serializes(self):
        self.assertEqual(ScanResult.from_dict(self.result.to_dict()).to_dict(), self.result.to_dict())


if __name__ == "__main__":
    unittest.main()
