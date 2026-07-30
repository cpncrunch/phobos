import json
import tempfile
import unittest
from pathlib import Path

from offsec_agent_harness import ActionRequest, DecisionStatus, EngagementROE, GuardrailEngine, OffSecHarness
from offsec_agent_harness.models import redact_secrets
from offsec_agent_harness.scope import target_in_scope


class GuardrailTests(unittest.TestCase):
    def make_roe(self, tmp: str) -> EngagementROE:
        return EngagementROE(
            name="Unit Test Engagement",
            authorized=True,
            in_scope_targets=["app.example.test", "*.corp.example", "10.10.0.0/24"],
            evidence_dir=tmp,
        )

    def test_scope_exact_wildcard_and_cidr(self):
        self.assertTrue(target_in_scope("https://app.example.test/login", ["app.example.test"]).in_scope)
        self.assertTrue(target_in_scope("api.corp.example", ["*.corp.example"]).in_scope)
        self.assertTrue(target_in_scope("10.10.0.50", ["10.10.0.0/24"]).in_scope)
        self.assertFalse(target_in_scope("example.org", ["*.corp.example"]).in_scope)

    def test_scope_normalizes_url_port_wildcard_and_ipv6_rules(self):
        rules = [
            "https://api.example.test:8443",
            "*.corp.example:443",
            "2001:db8::/126",
            "[2001:db8::8]:9443",
        ]
        self.assertTrue(target_in_scope("https://api.example.test:8443/v1?token=supersecret", rules).in_scope)
        self.assertFalse(target_in_scope("https://api.example.test:9443/v1", rules).in_scope)
        self.assertTrue(target_in_scope("team.corp.example:443", rules).in_scope)
        self.assertFalse(target_in_scope("team.corp.example:444", rules).in_scope)
        self.assertTrue(target_in_scope("http://[2001:db8::1]:8080/", rules).in_scope)
        self.assertTrue(target_in_scope("[2001:db8::8]:9443", rules).in_scope)
        self.assertFalse(target_in_scope("[2001:db8::8]:9444", rules).in_scope)
        self.assertFalse(target_in_scope("https://api.example.test:99999/v1", ["api.example.test"]).in_scope)
        self.assertFalse(target_in_scope("api.example.test:99999", ["api.example.test"]).in_scope)

    def test_guardrails_use_normalized_url_port_scope_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            roe = EngagementROE(
                name="Port Scoped Engagement",
                authorized=True,
                in_scope_targets=["https://api.example.test:8443"],
                evidence_dir=tmp,
            )
            allowed = GuardrailEngine().evaluate(
                roe,
                ActionRequest(
                    target="https://api.example.test:8443/v1?token=supersecret",
                    action_type="web",
                    purpose="Capture scoped API headers",
                    command="curl -I https://api.example.test:8443/v1",
                ),
            )
            blocked = GuardrailEngine().evaluate(
                roe,
                ActionRequest(
                    target="https://api.example.test:9443/v1",
                    action_type="web",
                    purpose="Capture API headers on the wrong port",
                    command="curl -I https://api.example.test:9443/v1",
                ),
            )
            self.assertEqual(allowed.status, DecisionStatus.ALLOW)
            self.assertEqual(blocked.status, DecisionStatus.BLOCK)

    def test_allows_low_risk_in_scope_read_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            roe = self.make_roe(tmp)
            decision = GuardrailEngine().evaluate(
                roe,
                ActionRequest(
                    target="app.example.test",
                    action_type="web",
                    purpose="Capture response headers",
                    command="curl -I https://app.example.test",
                ),
            )
            self.assertEqual(decision.status, DecisionStatus.ALLOW)

    def test_blocks_out_of_scope_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            roe = self.make_roe(tmp)
            decision = GuardrailEngine().evaluate(
                roe,
                ActionRequest(
                    target="evil.example",
                    action_type="web",
                    purpose="test",
                    command="curl -I https://evil.example",
                ),
            )
            self.assertEqual(decision.status, DecisionStatus.BLOCK)
            self.assertTrue(any("did not match" in r for r in decision.reasons))

    def test_blocks_destructive_and_dos_patterns(self):
        with tempfile.TemporaryDirectory() as tmp:
            roe = self.make_roe(tmp)
            destructive = GuardrailEngine().evaluate(
                roe,
                ActionRequest(target="app.example.test", action_type="host", purpose="cleanup", command="rm -rf /"),
            )
            dos = GuardrailEngine().evaluate(
                roe,
                ActionRequest(target="app.example.test", action_type="web", purpose="load", command="hping3 --flood app.example.test"),
            )
            self.assertEqual(destructive.status, DecisionStatus.BLOCK)
            self.assertEqual(dos.status, DecisionStatus.BLOCK)

    def test_non_destructive_mode_allows_active_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            roe = self.make_roe(tmp)
            decision = GuardrailEngine().evaluate(
                roe,
                ActionRequest(target="10.10.0.5", action_type="service-enumeration", purpose="version scan", command="nmap -sV 10.10.0.5"),
            )
            self.assertEqual(decision.status, DecisionStatus.ALLOW)

    def test_non_destructive_phrase_does_not_trip_destructive_keyword(self):
        with tempfile.TemporaryDirectory() as tmp:
            roe = self.make_roe(tmp)
            decision = GuardrailEngine().evaluate(
                roe,
                ActionRequest(target="app.example.test", action_type="host", purpose="non-destructive smoke", command="printf non-destructive-agent-ok"),
            )
            self.assertEqual(decision.status, DecisionStatus.ALLOW)

    def test_standard_mode_requires_confirmation_for_active_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            roe = self.make_roe(tmp)
            roe.safety_mode = "standard"
            decision = GuardrailEngine().evaluate(
                roe,
                ActionRequest(target="10.10.0.5", action_type="service-enumeration", purpose="version scan", command="nmap -sV 10.10.0.5"),
            )
            self.assertEqual(decision.status, DecisionStatus.CONFIRM)
            self.assertTrue(decision.required_confirmations)

    def test_non_destructive_mode_confirms_state_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            roe = self.make_roe(tmp)
            decision = GuardrailEngine().evaluate(
                roe,
                ActionRequest(target="app.example.test", action_type="web", purpose="controlled update", command="curl -X POST https://app.example.test/profile"),
            )
            self.assertEqual(decision.status, DecisionStatus.CONFIRM)
            self.assertTrue(any("state" in r.lower() for r in decision.reasons))

    def test_redacts_secret_like_values(self):
        redacted = redact_secrets("curl -H 'Authorization: Bearer abc.def.ghi' https://app password=hunter2 token=abcd")
        self.assertNotIn("hunter2", redacted)
        self.assertNotIn("abc.def.ghi", redacted)
        self.assertNotIn("abcd", redacted)

    def test_redacts_authorization_cookie_and_quoted_values(self):
        sample = (
            "curl -H 'Authorization: Basic QWxhZG...ZQ==' "
            "-H 'Cookie: sessionid=cookievalue; csrftoken=csrfvalue' "
            "https://app.example.test authorization=Bearer cli.secret "
            "api_key='quoted-key' password=\"quoted-pass\""
        )
        redacted = redact_secrets(sample) or ""
        for leaked in [
            "QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
            "cookievalue",
            "csrfvalue",
            "cli.secret",
            "quoted-key",
            "quoted-pass",
        ]:
            self.assertNotIn(leaked, redacted)
        self.assertIn("Cookie: <REDACTED>", redacted)
        self.assertIn("authorization=Bearer <REDACTED>", redacted)
        self.assertIn("api_key='<REDACTED>'", redacted)
        self.assertIn('password="<REDACTED>"', redacted)

    def test_redacts_cloud_oauth_headers_json_and_private_keys(self):
        sample = (
            "X-API-Key: header-secret-value\n"
            "AWS_SECRET_ACCESS_KEY=aws-secret-value "
            "client_secret=\"oauth-client-secret\" "
            "private_key='-----BEGIN PRIVATE KEY-----\nprivate-key-body\n-----END PRIVATE KEY-----' "
            "{\"session_token\":\"json-session-token\",\"proxy_authorization\":\"Bearer proxy-token\"}"
        )
        redacted = redact_secrets(sample) or ""
        for leaked in [
            "header-secret-value",
            "aws-secret-value",
            "oauth-client-secret",
            "private-key-body",
            "json-session-token",
            "proxy-token",
        ]:
            self.assertNotIn(leaked, redacted)
        self.assertIn("X-API-Key: <REDACTED>", redacted)
        self.assertIn("AWS_SECRET_ACCESS_KEY=<REDACTED>", redacted)
        self.assertIn('client_secret="<REDACTED>"', redacted)
        self.assertIn("private_key='<REDACTED>'", redacted)
        self.assertIn('"session_token":"<REDACTED>"', redacted)
        self.assertIn('"proxy_authorization":"<REDACTED>"', redacted)

    def test_harness_records_decision(self):
        with tempfile.TemporaryDirectory() as tmp:
            roe = self.make_roe(tmp)
            harness = OffSecHarness(roe)
            result = harness.assess(
                ActionRequest(target="app.example.test", action_type="web", purpose="headers", command="curl -I https://app.example.test"),
                execute=False,
            )
            self.assertEqual(result.decision.status, DecisionStatus.ALLOW)
            path = Path(result.evidence_path)
            self.assertTrue(path.exists())
            rows = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual(rows[-1]["decision"]["status"], "allow")
            self.assertTrue((path.parent / "command-log.md").exists())


if __name__ == "__main__":
    unittest.main()
