"""Adversarial regression tests for authority checker types, RFC 6901 pointers, and bounded I/O."""

from __future__ import annotations

import copy
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "authority_check", ROOT / "src" / "authority_check.py"
)
assert SPEC and SPEC.loader
authority_check = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = authority_check
SPEC.loader.exec_module(authority_check)


class AuthorityHardeningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.valid_path = ROOT / "examples" / "valid" / "subactor-standing-grant.json"
        cls.valid = json.loads(cls.valid_path.read_text(encoding="utf-8"))
        cls.profile = json.loads(
            (ROOT / "profiles" / "subactor-semcod.profile.json").read_text(encoding="utf-8")
        )

    def codes(self, document: object) -> set[str]:
        return {f.code for f in authority_check.validate_document(document)}

    def test_unhashable_state_stage_mode_and_non_string_keys_do_not_crash(self) -> None:
        grant = copy.deepcopy(self.valid)
        grant["state"] = ["active"]
        grant["issuer"][123] = "non-string-key"
        found = self.codes(grant)
        self.assertIn(authority_check.SYNTAX, found)
        self.assertIn(authority_check.STATE, found)

        prof = copy.deepcopy(self.profile)
        prof["bindings"][0]["stage"] = ["issue"]
        prof["bindings"][1]["mode"] = None
        prof["bindings"].append("extra-item")
        found_prof = self.codes(prof)
        self.assertIn(authority_check.SYNTAX, found_prof)
        self.assertIn(authority_check.PROFILE, found_prof)

    def test_rfc6901_array_indices_reject_negative_leading_zero_and_out_of_range(self) -> None:
        for bad_path in ("/history/-1/to", "/history/00/to", "/history/+0/to", "/history/99/to"):
            case = {
                "schema": "wellmanifest.authority/invalid-case/v1",
                "base": "../valid/subactor-standing-grant.json",
                "mutations": [{"op": "replace", "path": bad_path, "value": "revoked"}],
                "expectedCodes": [authority_check.SYNTAX],
            }
            _, _, findings = authority_check.apply_invalid_case(
                case, ROOT / "examples" / "invalid" / "synthetic.json"
            )
            self.assertEqual([authority_check.SYNTAX], [f.code for f in findings], bad_path)

    def test_json_loader_rejects_nan_infinity_deep_nesting_symlinks_and_fifos(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for idx, payload in enumerate((
                b'{"schema": NaN}',
                b'{"schema": Infinity}',
                b'{"schema": -Infinity}',
                b"[" * 200 + b"]" * 200,
            )):
                path = root / f"bad-{idx}.json"
                path.write_bytes(payload)
                findings = authority_check.load_and_validate(path)
                self.assertEqual([authority_check.SYNTAX], [f.code for f in findings])

            sym = root / "sym.json"
            sym.symlink_to(self.valid_path)
            findings = authority_check.load_and_validate(sym)
            self.assertEqual([authority_check.SYNTAX], [f.code for f in findings])

            if hasattr(os, "mkfifo"):
                fifo = root / "pipe.json"
                os.mkfifo(fifo)
                findings = authority_check.load_and_validate(fifo)
                self.assertEqual([authority_check.SYNTAX], [f.code for f in findings])

    def test_cli_fails_closed_on_empty_or_symlink_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            empty_dir = Path(tmp) / "empty"
            empty_dir.mkdir()
            err = io.StringIO()
            with redirect_stderr(err):
                self.assertEqual(authority_check.main(["validate", str(empty_dir)]), 1)
            self.assertIn(authority_check.SYNTAX, err.getvalue())

            sym_dir = Path(tmp) / "with_sym"
            sym_dir.mkdir()
            (sym_dir / "link.json").symlink_to(self.valid_path)
            err = io.StringIO()
            with redirect_stderr(err):
                self.assertEqual(authority_check.main(["validate", str(sym_dir)]), 1)
            self.assertIn(authority_check.SYNTAX, err.getvalue())

    def test_unhashable_principal_kind_and_history_transitions_do_not_crash(self) -> None:
        grant = copy.deepcopy(self.valid)
        grant["issuer"]["kind"] = ["protected-authority"]
        grant["subject"] = {"kind": {"bad": 1}}
        grant["renewal"]["issuer"] = {"kind": "protected-authority"}
        grant["delegation"] = {
            "mode": "protected-narrow-only",
            "parentGrantId": "authority://grant/subactor/founder-parent",
            "parentGrantDigest": "sha256:" + "5" * 64,
            "delegator": {"kind": ["human"]},
            "depth": 1,
            "maxDepth": 2,
            "scopePolicy": "subset-only",
            "budgetPolicy": "no-increase",
            "validityPolicy": "not-after-parent",
        }
        grant["history"][0]["from"] = ["none"]
        grant["history"][0]["to"] = ["issued"]
        findings = authority_check.validate_document(grant)
        found = {f.code for f in findings}
        messages = {f.message for f in findings}
        self.assertIn(authority_check.SYNTAX, found)
        self.assertIn(authority_check.STATE, found)
        self.assertNotIn("subject cannot renew its own grant", messages)
        self.assertNotIn("delegator and child subject must differ", messages)

    def test_json_loader_rejects_float_overflow_and_malformed_invalid_cases(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for idx, payload in enumerate((
                b'{"schema": 1e999}',
                b'{"schema": -1e999}',
            )):
                path = root / f"overflow-{idx}.json"
                path.write_bytes(payload)
                findings = authority_check.load_and_validate(path)
                self.assertEqual([authority_check.SYNTAX], [f.code for f in findings])

        for bad_case in (
            {
                "schema": "wellmanifest.authority/invalid-case/v1",
                "base": "../valid/subactor-standing-grant.json",
                "mutations": [
                    {"op": "replace", "path": "/state", "value": "revoked", "extra": 1}
                ],
                "expectedCodes": [authority_check.STATE],
            },
            {
                "schema": "wellmanifest.authority/invalid-case/v1",
                "base": "../valid/subactor-standing-grant.json",
                "mutations": [{"op": "remove", "path": "/state", "value": "unexpected"}],
                "expectedCodes": [authority_check.SYNTAX],
            },
            {
                "schema": "wellmanifest.authority/invalid-case/v1",
                "base": "../valid/subactor-standing-grant.json",
                "mutations": [],
                "expectedCodes": [],
            },
        ):
            _, _, findings = authority_check.apply_invalid_case(
                bad_case, ROOT / "examples" / "invalid" / "synthetic.json"
            )
            self.assertEqual([authority_check.SYNTAX], [f.code for f in findings])

    def test_unhashable_profile_principal_uri_and_huge_array_index_and_regex_anchors(self) -> None:
        import authority_primitives as ap

        prof = copy.deepcopy(self.profile)
        prof["bindings"][0]["principal"]["uri"] = ["unhashable-list"]
        prof["bindings"][4]["principal"]["uri"] = {"unhashable": "dict"}
        findings = authority_check.validate_document(prof)
        self.assertIn(authority_check.SYNTAX, {f.code for f in findings})

        with self.assertRaises(IndexError):
            ap.parse_array_index("9" * 5000, 3)

        self.assertIsNone(ap.DIGEST.match("sha256:" + "a" * 64 + "\n"))
        self.assertIsNone(ap.SEMVER.match("1.2.3\n"))

        for name in ("authority_check.py", "authority_primitives.py"):
            lines = (ROOT / "src" / name).read_text(encoding="utf-8").splitlines()
            self.assertLess(len(lines), 500, f"{name} exceeded 500 lines: {len(lines)}")

        with tempfile.TemporaryDirectory() as tmp:
            real_dir = Path(tmp) / "real"
            real_dir.mkdir()
            (real_dir / "doc.json").write_text(json.dumps(self.valid), encoding="utf-8")
            sym_parent = Path(tmp) / "sym_parent"
            sym_parent.symlink_to(real_dir)
            old_cwd = Path.cwd()
            try:
                os.chdir(tmp)
                with self.assertRaises(OSError):
                    ap.iter_json_paths(Path("sym_parent"))
            finally:
                os.chdir(old_cwd)

    def test_huge_int_lone_surrogates_resource_uri_traversal_and_read_ancestors(self) -> None:
        import authority_primitives as ap

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for idx, payload in enumerate((
                b'{"schema": ' + (b"9" * 400) + b"}",
                b'{"schema": "\\ud800"}',
                b'{"\\udfff": 1}',
            )):
                p = root / f"sur-{idx}.json"
                p.write_bytes(payload)
                findings = authority_check.load_and_validate(p)
                self.assertEqual([authority_check.SYNTAX], [f.code for f in findings])

            real_dir = root / "real_grants"
            real_dir.mkdir()
            (real_dir / "grant.json").write_text(json.dumps(self.valid), encoding="utf-8")
            sym_dir = root / "sym_grants"
            sym_dir.symlink_to(real_dir)
            findings_sym = authority_check.load_and_validate(sym_dir / "grant.json")
            self.assertEqual([authority_check.SYNTAX], [f.code for f in findings_sym])

            for bad_max in (True, False, 0, -1):
                with self.subTest(max_bytes=bad_max):
                    with self.assertRaises(ValueError):
                        ap.read_regular_file_bytes(self.valid_path, max_bytes=bad_max)  # type: ignore[arg-type]

        for bad_res in (
            "github://wellmanifest/../secret",
            "github://wellmanifest/./repo",
            "github://wellmanifest//repo",
            "github://wellmanifest/repo/",
            "github://wellmanifest/repo\\sub",
            "github://wellmanifest/repo?query=1",
            "github://wellmanifest/repo#frag",
            "github://wellmanifest/foo:..:bar",
        ):
            with self.subTest(resource=bad_res):
                grant = copy.deepcopy(self.valid)
                grant["scope"]["resources"] = [bad_res]
                self.assertIn(authority_check.SYNTAX, self.codes(grant))

        self.assertFalse(
            ap.valid_hierarchical_id("authority://grant/subactor/foo:..:bar", ap.GRANT_URI)
        )
        self.assertIsNone(ap.DIGEST.fullmatch("\nsha256:" + "a" * 64))


if __name__ == "__main__":
    unittest.main()
