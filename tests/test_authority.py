from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
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

    def test_explicit_no_lease_policy_is_valid_without_synthetic_coordinates(self) -> None:
        mutation = copy.deepcopy(self.valid)
        mutation["lease"] = {"required": False}
        self.assertEqual(set(), self.codes(mutation))

        mutation["lease"]["leaseId"] = "authority://lease/subactor/not-needed"
        self.assertIn(authority_check.SYNTAX, self.codes(mutation))

    def test_delegation_is_digest_bound_and_narrow_only(self) -> None:
        mutation = copy.deepcopy(self.valid)
        mutation["delegation"] = {
            "mode": "protected-narrow-only",
            "parentGrantId": "authority://grant/subactor/founder-parent",
            "parentGrantDigest": "sha256:" + "5" * 64,
            "delegator": {"uri": "authority://principal/subactor-founder", "kind": "human"},
            "depth": 1,
            "maxDepth": 2,
            "scopePolicy": "subset-only",
            "budgetPolicy": "no-increase",
            "validityPolicy": "not-after-parent",
        }
        self.assertEqual(set(), self.codes(mutation))

        invalid = copy.deepcopy(mutation)
        invalid["delegation"]["budgetPolicy"] = "may-increase"
        self.assertIn(authority_check.DELEGATION, self.codes(invalid))

        invalid = copy.deepcopy(mutation)
        invalid["delegation"]["depth"] = 3
        self.assertIn(authority_check.DELEGATION, self.codes(invalid))

        invalid = copy.deepcopy(mutation)
        invalid["delegation"]["delegator"] = invalid["subject"]
        self.assertIn(authority_check.IDENTITY, self.codes(invalid))

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
        for name in (
            "grant", "profile", "principal", "receipt", "transition", "binding",
            "delegation",
        ):
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

    def test_booleans_are_rejected_for_integer_authority_fields(self) -> None:
        mutation = copy.deepcopy(self.valid)
        mutation["revision"] = True
        self.assertIn(authority_check.SYNTAX, self.codes(mutation))

        for field in ("maxUses", "maxConcurrent", "maxCostMinor"):
            mutation = copy.deepcopy(self.valid)
            mutation["budgets"][field] = True
            self.assertIn(authority_check.SCOPE, self.codes(mutation), field)

        mutation = copy.deepcopy(self.valid)
        mutation["renewal"]["maxRenewals"] = False
        self.assertIn(authority_check.RENEWAL, self.codes(mutation))

        mutation = copy.deepcopy(self.valid)
        mutation["lease"]["epoch"] = True
        self.assertIn(authority_check.LEASE, self.codes(mutation))

    def test_malformed_types_do_not_crash_scope_or_receipt_actor(self) -> None:
        mutation = copy.deepcopy(self.valid)
        mutation["scope"]["allowedEffects"] = 123
        mutation["scope"]["deniedEffects"] = [{}]
        self.assertIn(authority_check.SYNTAX, self.codes(mutation))

        mutation = copy.deepcopy(self.valid)
        mutation["history"][0]["receipt"]["actor"] = "not-an-object"
        codes = self.codes(mutation)
        self.assertIn(authority_check.SYNTAX, codes)
        self.assertIn(authority_check.IDENTITY, codes)

    def test_lease_id_receipt_id_reason_and_scope_uris_enforce_schema_patterns(self) -> None:
        mutation = copy.deepcopy(self.valid)
        mutation["lease"]["leaseId"] = ""
        self.assertIn(authority_check.LEASE, self.codes(mutation))

        mutation = copy.deepcopy(self.valid)
        mutation["lease"]["leaseId"] = "authority://lease/subactor/../escape"
        self.assertIn(authority_check.LEASE, self.codes(mutation))

        mutation = copy.deepcopy(self.valid)
        mutation["history"][0]["receipt"]["receiptId"] = "authority://receipt/"
        self.assertIn(authority_check.RECEIPT, self.codes(mutation))

        mutation = copy.deepcopy(self.valid)
        mutation["history"][0]["reason"] = "  "
        self.assertIn(authority_check.SYNTAX, self.codes(mutation))

        mutation = copy.deepcopy(self.valid)
        mutation["scope"]["capabilities"] = ["not-a-capability"]
        self.assertIn(authority_check.SYNTAX, self.codes(mutation))

        mutation = copy.deepcopy(self.valid)
        mutation["scope"]["resources"] = ["github://wellmanifest/bad space"]
        self.assertIn(authority_check.SYNTAX, self.codes(mutation))

        mutation = copy.deepcopy(self.valid)
        mutation["scope"]["allowedEffects"] = ["BAD_EFFECT"]
        self.assertIn(authority_check.SYNTAX, self.codes(mutation))

    def test_profile_identity_version_ownership_and_binding_uri_are_enforced(self) -> None:
        mutation = copy.deepcopy(self.profile)
        mutation["profileId"] = "authority://profile/"
        self.assertIn(authority_check.SYNTAX, self.codes(mutation))

        mutation = copy.deepcopy(self.profile)
        mutation["version"] = "v1"
        self.assertIn(authority_check.SYNTAX, self.codes(mutation))

        mutation = copy.deepcopy(self.profile)
        mutation["ownership"]["runtimeOwner"] = "unknown/owner"
        self.assertIn(authority_check.PROFILE, self.codes(mutation))

        mutation = copy.deepcopy(self.profile)
        mutation["ownership"]["adopts"].append("wellmanifest/autonomy")
        self.assertIn(authority_check.PROFILE, self.codes(mutation))

        mutation = copy.deepcopy(self.profile)
        mutation["bindings"][0]["uri"] = "http://example.com/process"
        self.assertIn(authority_check.SYNTAX, self.codes(mutation))

    def test_strict_rfc3339_duplicate_json_keys_and_invalid_utf8_fail_closed(self) -> None:
        mutation = copy.deepcopy(self.valid)
        mutation["validity"]["notBefore"] = "2026-08-01 00:00:00+00:00"
        self.assertIn(authority_check.SYNTAX, self.codes(mutation))

        with tempfile.TemporaryDirectory() as tmp:
            dup_path = Path(tmp) / "dup.json"
            raw = self.valid_path.read_text(encoding="utf-8")
            dup_raw = raw.replace(
                '"state": "active",',
                '"state": "revoked", "state": "active",',
                1,
            )
            dup_path.write_text(dup_raw, encoding="utf-8")
            findings = authority_check.load_and_validate(dup_path)
            self.assertEqual([authority_check.SYNTAX], [item.code for item in findings])

            bad_utf8 = Path(tmp) / "bad.json"
            bad_utf8.write_bytes(b"\xff\xfe{}")
            findings = authority_check.load_and_validate(bad_utf8)
            self.assertEqual([authority_check.SYNTAX], [item.code for item in findings])


if __name__ == "__main__":
    unittest.main()
