# Ticket 014: Harden authority_io symlink CWD/relative base guards, RFC3339 subseconds, and history reason controls

- **ID**: ticket-014
- **Owner**: tom
- **Status**: IN_PROGRESS
- **Workflow state**: EDIT
- **Created**: 2026-11-11

## Goal and scope

SESSION_EXECUTION_AUTHORIZATION: On 2026-11-11 user authorized auditing, fixing bugs, optimizing, and hardening `wellmanifest/*` standard repositories.

Move RFC 6901 pointer helpers into `src/authority_io.py` so `src/authority_primitives.py` stays comfortably below 500 lines; harden `_check_no_symlink_ancestors` against un-normalized absolute (`sym_dir/../real`), relative (`../sym_dir`), and CWD-under-symlink traversal; enforce relative-only non-blank control-char-free `base` paths in `resolve_within_examples`; normalize 7–9 digit RFC3339 fractional seconds in `parse_rfc3339`; reject ASCII C0/DEL and newline characters in `history[i].reason`; expand `tests/test_authority_hardening.py`; and reconcile merged `project/ticket-013/README.md` to `DONE`.

## Acceptance criteria

- [x] AC-01: Harden `src/authority_io.py` and `src/authority_primitives.py` against un-normalized/relative/CWD symlink traversal, absolute invalid-case `base` paths, 7–9 digit RFC3339 subsecond precision, and C0/DEL/newline `history[i].reason` strings, and mark merged `project/ticket-013/README.md` `DONE`.
- [x] AC-02: All Python modules in `src/` and `tests/` remain strictly `< 500` lines and pass `ruff check --no-cache src tests`, `pytest -q -p no:cacheprovider`, `python3 src/authority_check.py self-test`, `./project/governance-check.sh --base origin/main`, and `wellman check` with 0 errors.

## Tracking boundary

This directory contains the minimal reviewed intent. Optional participant prose
and raw command logs are not required delivery output.
