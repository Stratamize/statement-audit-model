import importlib.util
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[1]
SERVICE_PATH = ROOT / "service/app.py"


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class ServiceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not SERVICE_PATH.is_file():
            raise AssertionError("service/app.py is required")
        cls.service = load_module(SERVICE_PATH, "statement_audit_service")
        cls.client = TestClient(cls.service.app)
        cls.valid_vector = (
            ROOT / "test-vectors/valid/standard-month.json"
        ).read_bytes()
        cls.invalid_vector = (
            ROOT / "test-vectors/invalid/fee-sum-mismatch.json"
        ).read_bytes()

    def post_json(self, body, **kwargs):
        return self.client.post(
            "/api/validate",
            content=body,
            headers={"Content-Type": "application/json"},
            **kwargs,
        )

    def test_health_reports_service_and_package_version(self):
        response = self.client.get("/api/health")
        self.assertEqual(200, response.status_code)
        payload = response.json()
        self.assertEqual("stratamize-statement-audit", payload["service"])
        self.assertEqual("ok", payload["status"])
        self.assertEqual("1.1.0", payload["version"])

    def test_valid_vector_is_accepted(self):
        response = self.post_json(self.valid_vector)
        self.assertEqual(200, response.status_code)
        payload = response.json()
        self.assertEqual("valid", payload["status"])
        self.assertEqual(0, payload["issue_count"])

    def test_invalid_vector_reports_expected_rule(self):
        response = self.post_json(self.invalid_vector)
        self.assertEqual(200, response.status_code)
        payload = response.json()
        self.assertEqual("invalid", payload["status"])
        codes = {issue["code"] for issue in payload["issues"]}
        self.assertIn("fee_group_reconciliation", codes)

    def test_duplicate_json_keys_are_rejected_by_the_validator_parser(self):
        record = json.loads(self.valid_vector)
        body = self.valid_vector.replace(
            b'"currency": "USD",', b'"currency": "USD", "currency": "USD",', 1
        )
        self.assertNotEqual(body, self.valid_vector)
        del record

        response = self.post_json(body)
        self.assertEqual(400, response.status_code)
        payload = response.json()
        self.assertEqual("invalid", payload["status"])
        self.assertEqual("duplicate_key", payload["issues"][0]["code"])

    def test_oversized_body_is_rejected_with_input_size(self):
        response = self.post_json(b"[" + b" " * 1_000_001 + b"]")
        self.assertEqual(413, response.status_code)
        self.assertEqual("input_size", response.json()["issues"][0]["code"])

    def test_non_utf8_body_is_rejected_without_echo(self):
        response = self.post_json(b"\xff\xfe{}")
        self.assertEqual(400, response.status_code)
        self.assertEqual("input_read", response.json()["issues"][0]["code"])

    def test_validation_errors_never_echo_submitted_values(self):
        marker = "EchoCanaryValue7731"
        record = json.loads(self.valid_vector)
        record["review_notes"] = [f"{marker} password: hunter2secret"]
        response = self.post_json(json.dumps(record).encode("utf-8"))
        self.assertEqual(200, response.status_code)
        payload = response.json()
        self.assertEqual("invalid", payload["status"])
        self.assertNotIn(marker, response.text)
        self.assertNotIn("hunter2secret", response.text)

    def test_schema_endpoint_serves_the_stratamize_contract(self):
        response = self.client.get("/api/schema")
        self.assertEqual(200, response.status_code)
        schema = response.json()
        self.assertEqual("Stratamize Statement Audit Model", schema["title"])
        self.assertIn("stratamize.com", schema["$id"])

    def test_csv_template_round_trips_as_valid(self):
        body = (ROOT / "payment-statement-audit-template.csv").read_bytes()
        response = self.client.post(
            "/api/validate-csv",
            content=body,
            headers={"Content-Type": "text/csv"},
        )
        self.assertEqual(200, response.status_code)
        self.assertEqual("valid", response.json()["status"])

    def test_csv_formula_prefix_is_rejected(self):
        text = (ROOT / "payment-statement-audit-template.csv").read_text(
            encoding="utf-8"
        )
        header, row = text.splitlines()[:2]
        cells = row.split(",")
        cells[-1] = "=2+2"
        response = self.client.post(
            "/api/validate-csv",
            content="\n".join((header, ",".join(cells))).encode("utf-8"),
            headers={"Content-Type": "text/csv"},
        )
        self.assertEqual(200, response.status_code)
        payload = response.json()
        self.assertEqual("invalid", payload["status"])
        codes = {issue["code"] for issue in payload["issues"]}
        self.assertIn("csv_formula", codes)

    def test_token_is_enforced_when_configured(self):
        with mock.patch.dict(
            "os.environ", {"STATEMENT_AUDIT_TOKEN": "local-test-token"}
        ):
            denied = self.client.get("/api/health")
            self.assertEqual(401, denied.status_code)

            wrong = self.client.get(
                "/api/health", headers={"X-Audit-Token": "wrong-token"}
            )
            self.assertEqual(401, wrong.status_code)

            bearer = self.client.get(
                "/api/health",
                headers={"Authorization": "Bearer local-test-token"},
            )
            self.assertEqual(200, bearer.status_code)

            header = self.client.get(
                "/api/health", headers={"X-Audit-Token": "local-test-token"}
            )
            self.assertEqual(200, header.status_code)

    def test_token_gates_every_data_endpoint(self):
        with mock.patch.dict(
            "os.environ", {"STATEMENT_AUDIT_TOKEN": "local-test-token"}
        ):
            requests = (
                ("post", "/api/validate", self.valid_vector),
                ("post", "/api/validate-csv", b"a,b\n1,2\n"),
                ("get", "/api/schema", None),
                ("get", "/api/corpus", None),
            )
            for method, url, body in requests:
                with self.subTest(url=url):
                    kwargs = {} if body is None else {"content": body}
                    denied = getattr(self.client, method)(url, **kwargs)
                    self.assertEqual(401, denied.status_code)

    def test_corpus_self_test_passes_end_to_end(self):
        response = self.client.get("/api/corpus")
        self.assertEqual(200, response.status_code)
        payload = response.json()
        self.assertEqual("pass", payload["status"])
        self.assertEqual(2, payload["valid_vectors"])
        self.assertEqual(17, payload["invalid_vectors"])


if __name__ == "__main__":
    unittest.main()
