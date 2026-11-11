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


if __name__ == "__main__":
    unittest.main()
