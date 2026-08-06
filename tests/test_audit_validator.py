import copy
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from decimal import Decimal, Inexact, localcontext
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schema/payment-statement-audit.schema.json"
EXAMPLE_PATH = ROOT / "examples/payment-statement-audit-example.json"
VALIDATOR_PATH = ROOT / "tools/validate_audit.py"


def load_validator_module():
    spec = importlib.util.spec_from_file_location("audit_validator", VALIDATOR_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load the audit validator")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class AuditValidatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not VALIDATOR_PATH.is_file():
            raise AssertionError("tools/validate_audit.py is required")
        cls.validator = load_validator_module()
        cls.valid_record = cls.validator.load_record(EXAMPLE_PATH)

    def issue_codes(self, record):
        return {issue.code for issue in self.validator.validate_record(record)}

    def mutated(self, mutator):
        record = copy.deepcopy(self.valid_record)
        mutator(record)
        return record

    def test_schema_is_valid_draft_2020_12_and_example_passes_every_rule(self):
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        self.assertEqual([], self.validator.validate_record(self.valid_record))

    def test_json_loader_preserves_decimals_and_rejects_duplicate_keys(self):
        self.assertIsInstance(self.valid_record["card_volume"], Decimal)
        duplicate = '{"schema_version":"1.1.0","schema_version":"1.1.0"}'
        with self.assertRaisesRegex(ValueError, "duplicate_key"):
            self.validator.loads_record(duplicate)

    def test_reversed_and_overlong_statement_periods_are_rejected(self):
        reversed_record = self.mutated(
            lambda row: row["statement_period"].update(
                {"start": "2026-07-01", "end": "2026-06-30"}
            )
        )
        overlong_record = self.mutated(
            lambda row: row["statement_period"].update(
                {"start": "2026-01-01", "end": "2026-04-01"}
            )
        )
        self.assertIn("period_order", self.issue_codes(reversed_record))
        self.assertIn("period_duration", self.issue_codes(overlong_record))

    def test_invalid_calendar_dates_are_rejected_even_when_schema_format_is_annotation(self):
        record = self.mutated(
            lambda row: row["statement_period"].update({"end": "2026-02-30"})
        )
        self.assertIn("schema_format", self.issue_codes(record))

    def test_fee_categories_must_be_unique_and_reconcile_to_gross_fees(self):
        duplicate = self.mutated(
            lambda row: row["fee_groups"].append(copy.deepcopy(row["fee_groups"][0]))
        )
        mismatch = self.mutated(
            lambda row: row.update({"gross_processing_fees": Decimal("2864.74")})
        )
        self.assertIn("duplicate_fee_category", self.issue_codes(duplicate))
        self.assertIn("fee_group_reconciliation", self.issue_codes(mismatch))

    def test_statement_credits_reconcile_gross_and_net_processing_fees(self):
        valid_credit = self.mutated(
            lambda row: row.update(
                {
                    "statement_credits": Decimal("10.00"),
                    "total_processing_fees": Decimal("2854.75"),
                    "effective_rate": Decimal("0.022838"),
                }
            )
        )
        invalid_credit = self.mutated(
            lambda row: row.update({"statement_credits": Decimal("10.00")})
        )
        self.assertEqual([], self.validator.validate_record(valid_credit))
        self.assertIn("net_fee_reconciliation", self.issue_codes(invalid_credit))

    def test_effective_rate_and_average_ticket_are_recomputed(self):
        wrong_rate = self.mutated(
            lambda row: row.update({"effective_rate": Decimal("2.291800")})
        )
        wrong_ticket = self.mutated(
            lambda row: row.update({"average_ticket": Decimal("67.21")})
        )
        self.assertIn("effective_rate_mismatch", self.issue_codes(wrong_rate))
        self.assertIn("average_ticket_mismatch", self.issue_codes(wrong_ticket))

    def test_decimal_math_is_independent_of_the_callers_context(self):
        with localcontext() as context:
            context.prec = 4
            context.Emax = 9
            context.Emin = -9
            context.traps[Inexact] = True
            self.assertEqual([], self.validator.validate_record(self.valid_record))

    def test_money_and_rate_precision_are_explicit(self):
        fractional_cent = self.mutated(
            lambda row: row.update({"card_volume": Decimal("125000.001")})
        )
        overprecise_rate = self.mutated(
            lambda row: row.update({"effective_rate": Decimal("0.0229181")})
        )
        self.assertIn("money_precision", self.issue_codes(fractional_cent))
        self.assertIn("rate_precision", self.issue_codes(overprecise_rate))

    def test_zero_activity_semantics_are_unambiguous(self):
        zero = self.mutated(
            lambda row: row.update(
                {
                    "card_volume": Decimal("0.00"),
                    "transaction_count": 0,
                    "gross_processing_fees": Decimal("49.00"),
                    "statement_credits": Decimal("0.00"),
                    "total_processing_fees": Decimal("49.00"),
                    "effective_rate": None,
                    "average_ticket": None,
                    "fee_groups": [
                        {"category": "monthly", "amount": Decimal("49.00")}
                    ],
                }
            )
        )
        inconsistent = self.mutated(
            lambda row: row.update(
                {"card_volume": Decimal("0.00"), "effective_rate": None}
            )
        )
        self.assertEqual([], self.validator.validate_record(zero))
        self.assertIn("activity_pair", self.issue_codes(inconsistent))

        zero_fee = self.mutated(
            lambda row: row.update(
                {
                    "card_volume": Decimal("0.00"),
                    "transaction_count": 0,
                    "gross_processing_fees": Decimal("0.00"),
                    "statement_credits": Decimal("0.00"),
                    "total_processing_fees": Decimal("0.00"),
                    "effective_rate": None,
                    "average_ticket": None,
                    "fee_groups": [
                        {"category": "other", "amount": Decimal("0.00")}
                    ],
                }
            )
        )
        self.assertEqual([], self.validator.validate_record(zero_fee))

    def test_published_half_up_rounding_is_enforced_at_exact_ties(self):
        average_ticket_tie = self.mutated(
            lambda row: row.update(
                {
                    "card_volume": Decimal("0.01"),
                    "transaction_count": 2,
                    "gross_processing_fees": Decimal("0.00"),
                    "statement_credits": Decimal("0.00"),
                    "total_processing_fees": Decimal("0.00"),
                    "effective_rate": Decimal("0.000000"),
                    "average_ticket": Decimal("0.01"),
                    "fee_groups": [
                        {"category": "other", "amount": Decimal("0.00")}
                    ],
                }
            )
        )
        effective_rate_tie = self.mutated(
            lambda row: row.update(
                {
                    "card_volume": Decimal("20000.00"),
                    "transaction_count": 1,
                    "gross_processing_fees": Decimal("0.01"),
                    "statement_credits": Decimal("0.00"),
                    "total_processing_fees": Decimal("0.01"),
                    "effective_rate": Decimal("0.000001"),
                    "average_ticket": Decimal("20000.00"),
                    "fee_groups": [
                        {"category": "other", "amount": Decimal("0.01")}
                    ],
                }
            )
        )
        self.assertEqual([], self.validator.validate_record(average_ticket_tie))
        self.assertEqual([], self.validator.validate_record(effective_rate_tie))

    def test_non_finite_numbers_and_unknown_fields_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "non_finite_number"):
            self.validator.loads_record('{"card_volume": NaN}')
        unknown = self.mutated(lambda row: row.update({"merchant_name": "Example"}))
        self.assertIn("schema_additionalProperties", self.issue_codes(unknown))

    def test_pathological_number_literals_fail_closed_without_decimal_crashes(self):
        hostile_literals = (
            '{"card_volume":1e-999999}',
            '{"effective_rate":1e999999}',
            '{"transaction_count":' + ("9" * 5000) + "}",
        )
        for source in hostile_literals:
            with self.subTest(source_length=len(source)):
                with self.assertRaisesRegex(ValueError, "number_range"):
                    self.validator.loads_record(source)

        direct_record = self.mutated(
            lambda row: row.update({"card_volume": Decimal("1e-999999")})
        )
        self.assertIn("number_range", self.issue_codes(direct_record))

    def test_direct_nonfinite_and_extreme_numbers_are_safe_rejections(self):
        hostile_values = (
            Decimal("Infinity"),
            Decimal("NaN"),
            Decimal("1e999999"),
            float("inf"),
            float("nan"),
            10**32,
            10**5000,
        )
        for value in hostile_values:
            with self.subTest(value_type=type(value).__name__):
                record = self.mutated(
                    lambda row, hostile=value: row.update({"card_volume": hostile})
                )
                self.assertIn("number_range", self.issue_codes(record))

    def test_oversized_and_deeply_nested_inputs_fail_closed(self):
        oversized = '{"review_notes":["' + ("x" * 1_000_000) + '"]}'
        with self.assertRaisesRegex(ValueError, "input_size"):
            self.validator.loads_record(oversized)

        nested = "{}"
        for _ in range(40):
            nested = '{"unknown":' + nested + "}"
        with self.assertRaisesRegex(ValueError, "input_depth"):
            self.validator.loads_record(nested)

    def test_malformed_nested_shapes_return_issues_instead_of_crashing(self):
        malformed_records = [
            {"statement_period": []},
            {"fee_groups": [None, [], {"amount": []}]},
            {"statement_period": {"start": [], "end": {}}},
            {"review_notes": [{"unexpected": [1, 2, 3]}]},
        ]
        for record in malformed_records:
            with self.subTest(record=record):
                issues = self.validator.validate_record(record)
                self.assertTrue(issues)

    def test_luhn_pan_and_contextual_security_data_in_notes_are_rejected(self):
        pan = self.mutated(
            lambda row: row.update(
                {"review_notes": ["Card number 4111 1111 1111 1111"]}
            )
        )
        cvv = self.mutated(
            lambda row: row.update({"review_notes": ["CVV 123"]})
        )
        self.assertIn("prohibited_payment_data", self.issue_codes(pan))
        self.assertIn("prohibited_payment_data", self.issue_codes(cvv))

    def test_truncated_pan_and_display_control_spoofing_are_rejected(self):
        prohibited_notes = (
            "Card ending in 4242",
            "PAN **** **** **** 4242",
            "Account last four 4242",
            "Visa •••• 4242",
            "Mastercard last 4 digits 5454",
            "Card ends in 1111",
            "ending in 4242",
            "last four 4242",
            "xxxx-xxxx-xxxx-4242",
            "411111 **** 11111",
            "first six 411111, last five 11111",
        )
        for note in prohibited_notes:
            with self.subTest(note=note):
                record = self.mutated(
                    lambda row, value=note: row.update({"review_notes": [value]})
                )
                self.assertIn("prohibited_payment_data", self.issue_codes(record))

        for marker in ("\u202e", "\u2066", "\u0000"):
            with self.subTest(codepoint=ord(marker)):
                record = self.mutated(
                    lambda row, value=marker: row.update(
                        {"review_notes": [f"classification {value}reversed"]}
                    )
                )
                self.assertIn("unsafe_text_control", self.issue_codes(record))

    def test_identity_bank_and_credential_values_in_notes_are_rejected(self):
        prohibited_notes = (
            "Owner email is merchant@example.com",
            "Owner SSN is 123-45-6789",
            "Routing number: 021000021",
            "Password is CorrectHorseBatteryStaple",
        )
        for note in prohibited_notes:
            with self.subTest(note_kind=note.split()[0].lower()):
                record = self.mutated(
                    lambda row, value=note: row.update({"review_notes": [value]})
                )
                self.assertIn("prohibited_payment_data", self.issue_codes(record))

    def test_errors_never_echo_input_values(self):
        sensitive = "4111 1111 1111 1111"
        record = self.mutated(
            lambda row: row.update({"review_notes": [f"Card number {sensitive}"]})
        )
        report = self.validator.validation_result(record)
        rendered = json.dumps(report, sort_keys=True)
        self.assertNotIn(sensitive, rendered)
        self.assertEqual("invalid", report["status"])

    def test_unknown_field_names_never_leak_through_issue_paths(self):
        sensitive_key = "password_SUPERSECRET_12345"
        record = {sensitive_key: Decimal("1e999999")}
        rendered = json.dumps(
            self.validator.validation_result(record), sort_keys=True
        )
        self.assertNotIn(sensitive_key, rendered)
        self.assertIn("/_unknown", rendered)

    def test_csv_header_matches_the_documented_flat_contract(self):
        issues = self.validator.validate_csv_template(
            ROOT / "payment-statement-audit-template.csv"
        )
        self.assertEqual([], issues)

    def test_csv_rejects_spreadsheet_formula_payloads_without_echoing_them(self):
        formula_prefixes = (
            "=1+1",
            "+1+1",
            "-1+1",
            "@SUM(1)",
            "\t=1+1",
            "\ufeff=1+1",
        )
        for marker in formula_prefixes:
            with self.subTest(prefix=marker[0]):
                with tempfile.TemporaryDirectory() as directory:
                    candidate = Path(directory) / "statement.csv"
                    source = (
                        ROOT / "payment-statement-audit-template.csv"
                    ).read_text(encoding="utf-8")
                    lines = source.splitlines()
                    lines[1] = lines[1].rsplit(",", maxsplit=1)[0] + "," + marker
                    candidate.write_text(
                        "\n".join(lines) + "\n", encoding="utf-8"
                    )

                    issues = self.validator.validate_csv_template(candidate)
                    self.assertIn("csv_formula", {issue.code for issue in issues})
                    self.assertNotIn(
                        marker, json.dumps([issue.to_dict() for issue in issues])
                    )

    def test_shipped_corpus_has_broad_expected_failure_coverage(self):
        report = self.validator.build_corpus_report(ROOT)
        self.assertEqual("pass", report["status"])
        self.assertGreaterEqual(report["valid_vectors"], 2)
        self.assertGreaterEqual(report["invalid_vectors"], 12)
        self.assertEqual(0, report["unexpected_results"])
        self.assertIn("schema_sha256", report)
        self.assertIn("validator_sha256", report)

    def test_corpus_report_records_the_complete_pinned_validation_runtime(self):
        report = self.validator.build_corpus_report(ROOT)
        expected = {
            "attrs",
            "jsonschema",
            "jsonschema-specifications",
            "referencing",
            "rpds-py",
        }
        self.assertEqual(expected, set(report["dependency_versions"]))
        pins = {
            line.split("==", maxsplit=1)[0]: line.split("==", maxsplit=1)[1]
            for line in (ROOT / "requirements-validation.txt")
            .read_text(encoding="utf-8")
            .splitlines()
            if line and not line.startswith("#")
        }
        self.assertEqual(report["dependency_versions"], pins)

    def test_cli_returns_nonzero_and_machine_readable_safe_output_for_invalid_input(self):
        invalid_path = ROOT / "test-vectors/invalid/security-data-in-note.json"
        result = subprocess.run(
            [sys.executable, str(VALIDATOR_PATH), "--json", str(invalid_path)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        self.assertEqual(1, result.returncode)
        report = json.loads(result.stdout)
        self.assertEqual("invalid", report["status"])
        self.assertNotIn("4111", result.stdout)

    def test_cli_uses_a_stable_value_free_code_for_unreadable_input(self):
        marker = "private-merchant-statement-do-not-echo.json"
        result = subprocess.run(
            [sys.executable, str(VALIDATOR_PATH), "--json", str(ROOT / marker)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        self.assertEqual(1, result.returncode)
        report = json.loads(result.stdout)
        self.assertEqual("input_read", report["issues"][0]["code"])
        self.assertNotIn(marker, result.stdout)

    def test_corpus_reports_a_missing_vector_without_throwing(self):
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "release"
            shutil.copytree(ROOT, candidate)
            (candidate / "test-vectors/invalid/wrong-effective-rate.json").unlink()

            report = self.validator.build_corpus_report(candidate)
            self.assertEqual("fail", report["status"])
            self.assertGreaterEqual(report["unexpected_results"], 1)

    def test_corpus_rejects_a_missing_registered_valid_vector(self):
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "release"
            shutil.copytree(ROOT, candidate)
            (candidate / "test-vectors/valid/standard-month.json").unlink()

            report = self.validator.build_corpus_report(candidate)
            self.assertEqual("fail", report["status"])
            self.assertIn(
                {"file": "valid-corpus", "result": "inventory_mismatch"},
                report["unexpected"],
            )

    def test_corpus_rejects_an_unregistered_invalid_vector(self):
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "release"
            shutil.copytree(ROOT, candidate)
            shutil.copyfile(
                candidate / "test-vectors/valid/standard-month.json",
                candidate / "test-vectors/invalid/unregistered.json",
            )

            report = self.validator.build_corpus_report(candidate)
            self.assertEqual("fail", report["status"])
            self.assertIn(
                {"file": "invalid-corpus", "result": "inventory_mismatch"},
                report["unexpected"],
            )


if __name__ == "__main__":
    unittest.main()
