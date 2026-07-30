import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class CliTests(unittest.TestCase):
    def test_agent_deploy_kit_is_token_auth_bound_and_validated(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            out = tmp_path / "deploy-kit"
            generated = subprocess.run(
                [
                    sys.executable, "-m", "phobos_agent.agent_cli", "deploy-kit",
                    "--out", str(out),
                    "--domain", "phobos.example",
                    "--agent-url", "https://phobos.example",
                    "--allow-origin", "https://ui.example",
                    "--token-env", "PHOBOS_UNIT_GATEWAY_TOKEN",
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(generated.returncode, 0, generated.stderr)
            payload = json.loads(generated.stdout)
            self.assertEqual(payload["status"], "written")
            self.assertTrue(payload["auth_required"])
            self.assertEqual(payload["bind_host"], "127.0.0.1")
            self.assertFalse(payload["token_value_written"])
            expected = {
                "phobos-agent.service",
                "nginx-phobos-agent.conf",
                "phobos-agent.env.template",
                "ufw-commands.sh",
                "ssh-tunnel-example.sh",
                "phobos-remote-ui.html",
                "README.md",
            }
            self.assertTrue(expected.issubset({path.name for path in out.iterdir()}))
            service = (out / "phobos-agent.service").read_text(encoding="utf-8")
            env_template = (out / "phobos-agent.env.template").read_text(encoding="utf-8")
            ui = (out / "phobos-remote-ui.html").read_text(encoding="utf-8")
            self.assertIn("--host 127.0.0.1", service)
            self.assertIn("--token-env PHOBOS_UNIT_GATEWAY_TOKEN", service)
            self.assertIn("--allow-origin https://ui.example", service)
            self.assertIn("PHOBOS_UNIT_GATEWAY_TOKEN=REPLACE_WITH_LONG_RANDOM_SECRET", env_template)
            self.assertIn("Authorization: Bearer &lt;token&gt;</code>", ui)
            self.assertIn("https://phobos.example", ui)
            self.assertNotIn("smoke-gateway-token", service + env_template + ui)

            bad_out = tmp_path / "bad-deploy-kit"
            bad = subprocess.run(
                [
                    sys.executable, "-m", "phobos_agent.agent_cli", "deploy-kit",
                    "--out", str(bad_out),
                    "--domain", "phobos.example",
                    "--token-env", "BAD-NAME;--unsafe-no-auth",
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(bad.returncode, 0)
            self.assertFalse(bad_out.exists())
            self.assertIn("--token-env", bad.stderr or bad.stdout)

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
