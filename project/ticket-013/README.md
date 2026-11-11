# Ticket 013: Modularize authority_io and harden deep ancestor symlinks, JSON digit/surrogate bounds, and secret scanning

- **ID**: ticket-013
- **Owner**: tom
- **Status**: DONE
- **Workflow state**: DONE
- **Created**: 2026-11-11

## Goal and scope

SESSION_EXECUTION_AUTHORIZATION: On 2026-11-11 user authorized auditing, fixing bugs, optimizing, and hardening `wellmanifest/*` standard repositories.

Extract bounded regular-file/JSON I/O and secret material definitions into `src/authority_io.py` so `src/authority_primitives.py` stays well below 500 lines; reject deep absolute symlink ancestors in both `read_regular_file_bytes` and `iter_json_paths`; bound JSON integer digit count before `int()` conversion in `loads_strict_json`; reject lone UTF-16 surrogates in programmatic document validation and `loads_strict_json`; expand `scan_secrets` to detect credential literals (GitHub PATs, API keys, AWS key IDs, PEM private keys) across keys and values; validate `schema` and mutation values in `apply_invalid_case`; and reconcile merged `project/ticket-012/README.md` status to `DONE`.

## Acceptance criteria

- [x] AC-01: Extract `src/authority_io.py` (< 500L), reject deep absolute symlink ancestors in `read_regular_file_bytes` and `iter_json_paths`, reject 5000+ digit JSON integers and lone UTF-16 surrogates across file and programmatic entrypoints, detect credential literals in `scan_secrets`, harden `apply_invalid_case`, and mark `project/ticket-012/README.md` `DONE`.
- [x] AC-02: All Python modules in `src/` and `tests/` remain strictly `< 500` lines and pass `ruff check --no-cache src tests`, `pytest -q -p no:cacheprovider`, `python3 src/authority_check.py self-test`, `./project/governance-check.sh --base origin/main`, and `wellman check` with 0 errors.

## Tracking boundary

This directory contains the minimal reviewed intent. Optional participant prose
and raw command logs are not required delivery output.
