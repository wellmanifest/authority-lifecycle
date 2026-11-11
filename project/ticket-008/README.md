# Ticket 008: Harden authority lifecycle validator and schema parity

- **ID**: ticket-008
- **Owner**: unresolved:human
- **Status**: DONE
- **Workflow state**: DONE
- **Created**: 2026-11-11

## Goal and scope

Close fail-open gaps and crash vectors in `src/authority_check.py` so the
semantic conformance checker enforces full parity with
`schemas/authority-lifecycle.schema.json` and keeps every Python module well
under 500 lines (`src/authority_primitives.py` + `src/authority_check.py`).

## Acceptance criteria

- [x] AC-01: Reject boolean values in integer authority fields (`revision`,
      `budgets.*`, `renewal.maxRenewals`, `lease.epoch`, `delegation.*`),
      duplicate JSON object keys, invalid UTF-8 inputs, and non-RFC3339
      timestamps (`AUTH-SYNTAX-001` / domain codes).
- [x] AC-02: Eliminate `TypeError` and `AttributeError` crashes on malformed
      `scope.allowedEffects`/`deniedEffects` and non-object `receipt.actor`
      values while returning structured `Finding` diagnostics.
- [x] AC-03: Enforce schema-bound patterns and path-segment hygiene on
      `leaseId`, `receiptId`, `history[*].reason`, `scope.*` items, `profileId`,
      `version`, `ownership.runtimeOwner`, `ownership.adopts`, and
      `bindings[*].uri`.
- [x] AC-04: Pass `ruff`, `pytest`, `unittest`, `src/authority_check.py self-test`,
      `./project/governance-check.sh --base origin/main`, and `wellman check`.

## Tracking boundary

This directory contains the minimal reviewed intent. Optional participant prose
and raw command logs are not required delivery output.
