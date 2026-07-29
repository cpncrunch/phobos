import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from offsec_agent_harness.bloodhound import analyze_bloodhound
from offsec_agent_harness.cve_advisor import CveAdvisor
from offsec_agent_harness.model_adapters import build_adapter
from offsec_agent_harness.reporting import FindingInput, FindingMarkdownExporter


class ExtensionModuleTests(unittest.TestCase):
    def test_bloodhound_path_and_adcs_inventory(self):
        graph = {
            "nodes": [
                {"id": "u1", "name": "ALICE@CORP.LOCAL", "type": "User"},
                {"id": "g1", "name": "HELPDESK@CORP.LOCAL", "type": "Group"},
                {"id": "da", "name": "DOMAIN ADMINS@CORP.LOCAL", "type": "Group"},
                {"id": "tpl", "name": "ESC1 Certificate Template", "type": "CertTemplate"},
            ],
            "edges": [
                {"source": "u1", "target": "g1", "relationship": "MemberOf"},
                {"source": "g1", "target": "da", "relationship": "GenericAll"},
                {"source": "u1", "target": "tpl", "relationship": "ADCSESC1"},
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bh.json"
            path.write_text(json.dumps(graph))
            analysis = analyze_bloodhound(path, principal="ALICE@CORP.LOCAL")
        self.assertEqual(analysis.node_count, 4)
        self.assertTrue(analysis.paths)
        self.assertIn("DOMAIN ADMINS@CORP.LOCAL", analysis.paths[0].nodes)
        self.assertTrue(analysis.adcs_edges)
        self.assertIn("offline graph review only", analysis.to_markdown())

    def test_cve_advisor_catalog_and_dos_risk(self):
        catalog = [{
            "cve_id": "CVE-2099-0001",
            "component_patterns": ["ExampleServer"],
            "affected_versions": ["<=1.2.3"],
            "title": "ExampleServer crafted request denial of service",
            "summary": "A crafted request can cause a denial of service crash.",
            "severity": "High",
        }]
        advisor = CveAdvisor(catalog)
        advice = advisor.advise("ExampleServer", "1.2.0", evidence="banner grab")
        self.assertEqual(advice.candidates[0].cve_id, "CVE-2099-0001")
        self.assertEqual(advice.candidates[0].destructive_risk, "high")
        self.assertIn("Avoid production PoC", "\n".join(advice.candidates[0].safe_validation))

    def test_heuristic_model_adapter(self):
        adapter = build_adapter("heuristic")
        response = adapter.generate("safety", "Can we run this?", context="Authorized web assessment")
        self.assertEqual(response.provider, "heuristic")
        self.assertIn("Avoid destructive changes", response.content)

    def test_finding_markdown_exporter_confirmed_and_candidate(self):
        finding = FindingInput.from_dict({
            "title": "Improper Authorization Allows Access to Controlled Invoice",
            "severity": "High",
            "industry_reference": "OWASP A01: Broken Access Control",
            "impact": "Unauthorized Access",
            "root_cause": "Improper Authorization",
            "evidence": ["burp/idor-positive.http", "burp/idor-negative-control.http"],
            "affected_assets": ["GET /api/invoices/{id}"],
            "recommendation": "Enforce server-side object authorization for every invoice request.",
            "confirmed": True,
        })
        rendered = FindingMarkdownExporter().render_finding(finding)
        self.assertIn("## Risk Metadata", rendered)
        self.assertIn("OWASP A01", rendered)
        candidate = FindingInput.from_dict({"title": "Version-only Candidate", "confirmed": False})
        self.assertIn("Internal Candidate Note", FindingMarkdownExporter().render_finding(candidate))


class ExtensionCliTests(unittest.TestCase):
    def test_cli_extension_smoke(self):
        env = os.environ.copy()
        env["PYTHONPATH"] = "src"
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            init = subprocess.run([
                sys.executable, "-m", "offsec_agent_harness", "init",
                "--name", "Extension CLI", "--scope", "app.example.test,corp.local", "--evidence-dir", str(tmp_path / "evidence"), "--out", str(engagement),
            ], cwd=Path(__file__).parents[1], env=env, text=True, capture_output=True)
            self.assertEqual(init.returncode, 0, init.stderr)

            raw_request = tmp_path / "request.http"
            raw_request.write_text("GET / HTTP/1.1\r\nHost: app.example.test\r\n\r\n")
            burp = subprocess.run([
                sys.executable, "-m", "offsec_agent_harness", "burp-tab",
                "--engagement", str(engagement), "--mcp-url", "http://127.0.0.1:1/mcp", "--target", "app.example.test", "--tab-name", "headers", "--request-file", str(raw_request),
            ], cwd=Path(__file__).parents[1], env=env, text=True, capture_output=True)
            self.assertEqual(burp.returncode, 0, burp.stderr)
            self.assertTrue(Path(json.loads(burp.stdout)["artifacts"]["redacted_request"]).exists())

            graph = tmp_path / "bh.json"
            graph.write_text(json.dumps({"nodes": [{"id": "u", "name": "USER@CORP.LOCAL"}, {"id": "da", "name": "DOMAIN ADMINS@CORP.LOCAL"}], "edges": [{"source": "u", "target": "da", "relationship": "GenericAll"}]}))
            bh = subprocess.run([
                sys.executable, "-m", "offsec_agent_harness", "bloodhound-import", "--engagement", str(engagement), "--input", str(graph), "--principal", "USER@CORP.LOCAL",
            ], cwd=Path(__file__).parents[1], env=env, text=True, capture_output=True)
            self.assertEqual(bh.returncode, 0, bh.stderr)
            self.assertTrue(Path(json.loads(bh.stdout)["markdown_path"]).exists())

            catalog = tmp_path / "catalog.json"
            catalog.write_text(json.dumps({"cves": [{"cve_id": "CVE-2099-0002", "component": "Example", "affected_versions": ["1.*"], "summary": "Safe-to-check issue", "severity": "Medium"}]}))
            cve = subprocess.run([
                sys.executable, "-m", "offsec_agent_harness", "cve-advice", "--engagement", str(engagement), "--component", "Example", "--version", "1.0", "--catalog", str(catalog),
            ], cwd=Path(__file__).parents[1], env=env, text=True, capture_output=True)
            self.assertEqual(cve.returncode, 0, cve.stderr)
            self.assertTrue(Path(json.loads(cve.stdout)["markdown_path"]).exists())

            model = subprocess.run([
                sys.executable, "-m", "offsec_agent_harness", "model-draft", "--provider", "heuristic", "--role", "report", "--prompt", "Draft finding notes",
            ], cwd=Path(__file__).parents[1], env=env, text=True, capture_output=True)
            self.assertEqual(model.returncode, 0, model.stderr)
            self.assertIn("confirmed evidence", json.loads(model.stdout)["content"])

            finding = tmp_path / "finding.json"
            finding.write_text(json.dumps({"title": "Controlled IDOR", "confirmed": True, "evidence": ["burp/headers.http"], "affected_assets": ["GET /api/test"]}))
            export = subprocess.run([
                sys.executable, "-m", "offsec_agent_harness", "export-finding", "--engagement", str(engagement), "--finding-file", str(finding),
            ], cwd=Path(__file__).parents[1], env=env, text=True, capture_output=True)
            self.assertEqual(export.returncode, 0, export.stderr)
            self.assertTrue(Path(json.loads(export.stdout)["markdown_path"]).exists())


if __name__ == "__main__":
    unittest.main()
