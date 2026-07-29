import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class CliTests(unittest.TestCase):
    def test_init_assess_plan(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            init = subprocess.run(
                [
                    sys.executable, "-m", "offsec_agent_harness", "init",
                    "--name", "CLI Test", "--scope", "app.example.test,10.10.0.0/24",
                    "--evidence-dir", str(tmp_path / "evidence"), "--out", str(engagement),
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(init.returncode, 0, init.stderr)
            self.assertTrue(engagement.exists())

            assess = subprocess.run(
                [
                    sys.executable, "-m", "offsec_agent_harness", "assess",
                    "--engagement", str(engagement), "--target", "app.example.test",
                    "--type", "web", "--purpose", "Capture headers", "--command", "curl -I https://app.example.test",
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(assess.returncode, 0, assess.stderr)
            data = json.loads(assess.stdout)
            self.assertEqual(data["decision"]["status"], "allow")

            plan = subprocess.run(
                [
                    sys.executable, "-m", "offsec_agent_harness", "plan",
                    "--engagement", str(engagement), "--finding", "Controlled IDOR proof",
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(plan.returncode, 0, plan.stderr)
            plan_path = Path(json.loads(plan.stdout)["plan_path"])
            self.assertTrue(plan_path.exists())
            self.assertIn("Safe Impact Validation Plan", plan_path.read_text())


if __name__ == "__main__":
    unittest.main()
