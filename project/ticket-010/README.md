# Ticket 010: Harden authority checker unhashable kind and history guards, finite float parsing, and invalid-case mutations

- **ID**: ticket-010
- **Owner**: tom
- **Status**: DONE
- **Workflow state**: MERGED
- **Created**: 2026-11-11

## Goal and scope

Eliminate `TypeError` crashes on unhashable `principal.kind` and `history[*].from` / `history[*].to` fields; enforce schema-bound lifecycle state enums in `_validate_history` and prevent false-positive `None == None` URI collisions when `subject.uri` is missing; reject `1e999` / `-1e999` float overflow in `loads_strict_json` and `_enforce_json_depth`; validate closed mutation fields and non-empty `expectedCodes` in `apply_invalid_case`; and reconcile merged `ticket-008` and `ticket-009` statuses to `DONE`.

## Acceptance criteria

- [x] AC-01: Malformed unhashable `principal.kind`, `history[*].from`, and `history[*].to` emit deterministic `AUTH-SYNTAX-001` / `AUTH-STATE-001` findings without `TypeError`, and missing `subject.uri` does not trigger false-positive `AUTH-RENEWAL-001` / `AUTH-IDENTITY-001` self-URI findings.
- [x] AC-02: `loads_strict_json` and `_enforce_json_depth` reject `1e999` / `-1e999` float overflow and non-string nested object keys, and `apply_invalid_case` rejects unknown mutation fields and empty `expectedCodes`.
- [x] AC-03: All `src/` and `tests/` Python modules remain strictly below 500 lines, and `ruff check src tests`, `pytest -q`, `python3 -m unittest discover -s tests -v`, `python3 src/authority_check.py self-test`, `./project/governance-check.sh --base origin/main`, and `wellman check` pass with 0 errors.

## Tracking boundary

This directory contains the minimal reviewed intent. Optional participant prose
and raw command logs are not required delivery output.
