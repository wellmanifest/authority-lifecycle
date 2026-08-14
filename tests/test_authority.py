from __future__ import annotations

import copy
import importlib.util
import json
import sys
import unittest
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "authority_check", ROOT / "src" / "authority_check.py"
)
assert SPEC and SPEC.loader
authority_check = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = authority_check
SPEC.loader.exec_module(authority_check)


class AuthorityConformanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.valid_path = ROOT / "examples" / "valid" / "subactor-standing-grant.json"
        cls.valid = json.loads(cls.valid_path.read_text(encoding="utf-8"))
        cls.profile = json.loads(
            (ROOT / "profiles" / "subactor-semcod.profile.json").read_text(encoding="utf-8")
        )

    def codes(self, document: dict, at: datetime | None = None) -> set[str]:
        return {finding.code for finding in authority_check.validate_document(document, at)}

    def test_valid_grant_and_profile_pass(self) -> None:
        self.assertEqual(set(), self.codes(self.valid))
        self.assertEqual(set(), self.codes(self.profile))

    def test_invalid_fixtures_emit_declared_codes(self) -> None:
        for path in sorted((ROOT / "examples" / "invalid").glob("*.json")):
            case = json.loads(path.read_text(encoding="utf-8"))
            observed = {finding.code for finding in authority_check.load_and_validate(path)}
            self.assertLessEqual(set(case["expectedCodes"]), observed, path.name)

    def test_unknown_fields_fail_closed(self) -> None:
        mutation = copy.deepcopy(self.valid)
        mutation["authorityOverride"] = True
        self.assertIn(authority_check.SYNTAX, self.codes(mutation))
        mutation = copy.deepcopy(self.valid)
        mutation["scope"]["wildcard"] = "*"
        self.assertIn(authority_check.SYNTAX, self.codes(mutation))

    def test_subject_cannot_issue_or_renew_own_grant(self) -> None:
        mutation = copy.deepcopy(self.valid)
        mutation["issuer"] = mutation["subject"]
        self.assertIn(authority_check.IDENTITY, self.codes(mutation))
        mutation = copy.deepcopy(self.valid)
        mutation["renewal"]["issuer"] = mutation["subject"]
        self.assertIn(authority_check.RENEWAL, self.codes(mutation))

    def test_mandatory_denials_cannot_be_removed(self) -> None:
        mutation = copy.deepcopy(self.valid)
        mutation["scope"]["deniedEffects"].remove("grant.expand")
        self.assertIn(authority_check.SCOPE, self.codes(mutation))

    def test_allowed_and_denied_overlap_is_rejected(self) -> None:
        mutation = copy.deepcopy(self.valid)
        mutation["scope"]["allowedEffects"].append("grant.issue")
        self.assertIn(authority_check.SCOPE, self.codes(mutation))

    def test_expired_grant_and_lease_fail_runtime_evaluation(self) -> None:
        at = datetime.fromisoformat("2026-09-02T00:00:00+00:00")
        self.assertIn(authority_check.TIME, self.codes(self.valid, at))

    def test_terminal_grant_cannot_be_used(self) -> None:
        mutation = copy.deepcopy(self.valid)
        mutation["state"] = "revoked"
        mutation["history"].append(
            {
                "from": "active",
                "to": "revoked",
                "reason": "kill switch",
                "receipt": {
                    "receiptId": "authority://receipt/subactor/revoked-001",
                    "actor": mutation["issuer"],
                    "at": "2026-08-14T12:30:00Z",
                    "subjectDigest": "sha256:" + "4" * 64,
                },
            }
        )
        at = datetime.fromisoformat("2026-08-14T12:40:00+00:00")
        self.assertIn(authority_check.STATE, self.codes(mutation, at))

    def test_history_must_be_contiguous_and_match_state(self) -> None:
        mutation = copy.deepcopy(self.valid)
        mutation["history"][1]["from"] = "suspended"
        self.assertIn(authority_check.STATE, self.codes(mutation))
        mutation = copy.deepcopy(self.valid)
        mutation["state"] = "suspended"
        self.assertIn(authority_check.STATE, self.codes(mutation))

    def test_receipt_replay_is_rejected(self) -> None:
        mutation = copy.deepcopy(self.valid)
        mutation["history"][1]["receipt"]["receiptId"] = mutation["history"][0][
            "receipt"
        ]["receiptId"]
        self.assertIn(authority_check.RECEIPT, self.codes(mutation))

    def test_secret_bearing_fields_are_rejected(self) -> None:
        mutation = copy.deepcopy(self.valid)
        mutation["subject"]["token"] = "Bearer not-a-real-secret"
        codes = self.codes(mutation)
        self.assertIn(authority_check.SECRET, codes)
        self.assertIn(authority_check.SYNTAX, codes)

    def test_profile_requires_exact_stage_modes_and_separation(self) -> None:
        mutation = copy.deepcopy(self.profile)
        execute = next(item for item in mutation["bindings"] if item["stage"] == "execute")
        execute["mode"] = "protected-write"
        self.assertIn(authority_check.PROFILE, self.codes(mutation))
        mutation = copy.deepcopy(self.profile)
        issue = next(item for item in mutation["bindings"] if item["stage"] == "issue")
        execute = next(item for item in mutation["bindings"] if item["stage"] == "execute")
        execute["principal"] = issue["principal"]
        self.assertIn(authority_check.PROFILE, self.codes(mutation))

    def test_public_schema_is_closed_draft_2020_12(self) -> None:
        schema = json.loads(
            (ROOT / "schemas" / "authority-lifecycle.schema.json").read_text(encoding="utf-8")
        )
        self.assertEqual("https://json-schema.org/draft/2020-12/schema", schema["$schema"])
        for name in ("grant", "profile", "principal", "receipt", "transition", "binding"):
            self.assertFalse(schema["$defs"][name]["additionalProperties"])

    def test_invalid_case_cannot_escape_examples_root(self) -> None:
        case = {
            "schema": "wellmanifest.authority/invalid-case/v1",
            "base": "../../../README.md",
            "mutations": [],
            "expectedCodes": [authority_check.SYNTAX],
        }
        _, _, findings = authority_check.apply_invalid_case(
            case, ROOT / "examples" / "invalid" / "synthetic.json"
        )
        self.assertIn(authority_check.SYNTAX, {finding.code for finding in findings})


if __name__ == "__main__":
    unittest.main()
