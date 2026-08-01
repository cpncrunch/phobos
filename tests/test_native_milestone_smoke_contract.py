import re
import unittest
from pathlib import Path


class NativeMilestoneSmokeContractTests(unittest.TestCase):
    def test_native_milestone_aggregate_requires_every_native_smoke_check(self):
        repo_root = Path(__file__).resolve().parents[1]
        smoke_path = repo_root / "scripts" / "smoke_hermes_parity.py"
        text = smoke_path.read_text(encoding="utf-8")

        all_native_checks = sorted(set(re.findall(r'checks\["(native_[^"]+)"\]', text)))
        block = re.search(
            r"native_milestone_required_checks\s*=\s*\[(.*?)\]\s*native_milestone_missing_required_checks",
            text,
            re.S,
        )
        self.assertIsNotNone(block, "native milestone aggregate list was not found")
        required_native_checks = sorted(set(re.findall(r'"(native_[^"]+)"', block.group(1)))) if block else []

        excluded = {"native_tool_call_milestone_contract_ok"}
        missing = [name for name in all_native_checks if name not in excluded and name not in required_native_checks]
        stale = [name for name in required_native_checks if name not in all_native_checks]

        self.assertEqual(missing, [], "native smoke checks missing from milestone aggregate")
        self.assertEqual(stale, [], "native milestone aggregate references stale smoke checks")
        self.assertIn("native_milestone_missing_required_checks", text)
        self.assertIn("native_milestone_stale_required_checks", text)


if __name__ == "__main__":
    unittest.main()
