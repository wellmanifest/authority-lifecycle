# Ticket 011: Harden profile principal URI set, RFC 6901 index digits, ancestor symlinks, and regex anchors

- **ID**: ticket-011
- **Owner**: tom
- **Status**: IN_PROGRESS
- **Workflow state**: PUBLICATION
- **Created**: 2026-11-11

## Goal and scope

SESSION_EXECUTION_AUTHORIZATION: On 2026-11-11 user authorized auditing, fixing bugs, optimizing, and hardening `wellmanifest/*` standard repositories.

Eliminate `TypeError` crash when profile `issue` or `revoke` `principal.uri` is an unhashable JSON container (`list`/`dict`); bound RFC 6901 array index length before `int()` so >4300-digit tokens raise `IndexError` instead of Python's integer conversion `ValueError`; enforce `lstat`+`fstat` regular-file inode stability and relative ancestor symlink checks in `iter_json_paths`; anchor all authority regexes with `\Z`; and mark merged `ticket-010` `DONE`.

## Acceptance criteria

- [x] AC-01: Unhashable profile `principal.uri` containers emit `AUTH-SYNTAX-001` without `TypeError`, >4300-digit RFC 6901 array indices raise `IndexError`, `\Z` anchors reject trailing newlines, relative ancestor symlinks fail closed, and `pytest -q` + `authority_check.py self-test` pass.
- [x] AC-02: All Python modules remain `< 500` lines and `ruff check --no-cache src tests`, `./project/governance-check.sh --base origin/main --actor agent`, and `wellman check` pass with 0 errors.

## Tracking boundary

This directory contains the minimal reviewed intent. Optional participant prose
and raw command logs are not required delivery output.
