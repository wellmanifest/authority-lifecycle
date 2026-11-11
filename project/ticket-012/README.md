# Ticket 012: Harden authority JSON overflow/surrogates, resource URI traversal, and ancestor symlinks

- **ID**: ticket-012
- **Owner**: tom
- **Status**: DONE
- **Workflow state**: MERGED
- **Created**: 2026-11-11

## Goal and scope

Harden `src/authority_primitives.py` and `src/authority_check.py` against
`10**400` integer overflow, lone UTF-16 surrogates, resource and hierarchical
URI traversal (`.`, `..`, `//`, `\`, `?`, `#`, colon `..`), symlink ancestor
reads in `read_regular_file_bytes`, and `\A...\Z` regex anchors while keeping
all modules strictly under 500 lines, expand `tests/test_authority_hardening.py`,
and mark merged `ticket-011` `DONE`.

## Acceptance criteria

- [x] AC-01: Anchor all regexes with `\A...\Z`, reject `10**400` integer
      overflow and lone UTF-16 surrogates in strict JSON, block resource/URI
      traversal segments and query/fragment/backslash characters, and enforce
      positive integer `max_bytes` and symlink ancestor rejection in
      `read_regular_file_bytes` while keeping `src/*.py` < 500 lines.
- [x] AC-02: Pass `ruff check --no-cache src tests`, `pytest -q -p no:cacheprovider`,
      `python3 src/authority_check.py self-test`,
      `./project/governance-check.sh --base origin/main`, and `wellman check`.

## Tracking boundary

This directory contains the minimal reviewed intent. Optional participant prose
and raw command logs are not required delivery output.
