# Ticket 009: Harden authority checker unhashable guards, RFC6901 mutations, and bounded JSON I/O

- **ID**: ticket-009
- **Owner**: unresolved:human
- **Status**: DONE
- **Workflow state**: DONE
- **Created**: 2026-11-11

## Goal and scope

Eliminate `TypeError` and `RecursionError` crashes in `src/authority_check.py` and `src/authority_primitives.py` when validating malformed non-scalar `state`, `stage`, `mode`, or non-string object keys; enforce RFC 6901 array indices (`0|[1-9][0-9]*`) and non-symlink traversal in `apply_invalid_case` / `pointer_parent`; fail closed on empty or symlink-containing CLI directories; and harden `load_strict_json` / `loads_strict_json` / `scan_secrets` with `O_NOFOLLOW | O_NONBLOCK` 4 MiB regular-file reads, `NaN`/`Infinity` rejection, and iterative `MAX_JSON_DEPTH = 64` bounds while keeping all modules comfortably under 500 lines.

## Acceptance criteria

- [x] AC-01: Malformed unhashable `grant.state`, `binding.stage`, non-string `binding.mode`, extra `bindings` items (`!= 6`), and non-string dict keys emit deterministic `AUTH-*` findings without `TypeError`.
- [x] AC-02: `loads_strict_json` / `load_strict_json` reject `NaN`/`Infinity`, nesting `> 64`, symlinks, FIFOs, and `> 4 MiB` payloads; `pointer_parent` and `apply_invalid_case` reject negative/leading-zero RFC 6901 array indices and symlinked base paths; CLI directory validation fails closed on empty or symlink-containing directories.
- [x] AC-03: All `src/` and `tests/` Python modules stay strictly under 500 lines, and `pytest -q`, `python3 src/authority_check.py self-test`, `ruff check src tests`, `./project/governance-check.sh --base origin/main`, and `wellman check` pass with 0 errors.

## Tracking boundary

This directory contains the minimal reviewed intent. Optional participant prose
and raw command logs are not required delivery output.
