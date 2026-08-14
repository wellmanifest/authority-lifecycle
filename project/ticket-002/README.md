# Ticket 002: Onboard protected autonomous validation

- **ID**: ticket-002
- **Owner**: unresolved:human
- **Status**: IN_PROGRESS
- **Workflow state**: PUBLICATION
- **Created**: 2026-08-14

## Goal and scope

Add a deterministic GitHub Actions check for the authority standard, then
publish it through the protected Validator App path without per-PR human
approval. The ticket owns CI onboarding only; it does not change normative
authority semantics.

## Acceptance criteria

- [x] AC-01: `standards / authority conformance` runs unit tests, the checker
  self-test and bytecode compilation on pull requests and `main`.
- [x] AC-02: Local governance and standard conformance checks pass.
- [ ] AC-03: The implementation PR carries exact ticket and correlation
  metadata and remains at `IN_PROGRESS / PUBLICATION` until trusted merge.
- [ ] AC-04: The protected ruleset requires current-head governance,
  conformance and one non-author review.
- [ ] AC-05: Validator App approves and merges the exact PR head, deletes the
  ticket branch and the merged workflow is readable from `main`.

## Participants

- Human participant: unresolved; no user-* file was created by this script.
- Agent participant: [ai-codex.md](ai-codex.md)
