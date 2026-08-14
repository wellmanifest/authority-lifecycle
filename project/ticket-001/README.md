# Ticket 001: Define machine authority lifecycle standard

- **ID**: ticket-001
- **Owner**: unresolved:human
- **Status**: DONE
- **Workflow state**: DONE
- **Created**: 2026-08-14

## Goal and scope

Define a reusable standard for machine authority that lets an autonomous
principal continue bounded work without per-action human approval while
preventing self-issuance, self-extension, replay, privilege widening and action
after expiry or revocation.

## Acceptance criteria

- [x] AC-01: The user's continuation request is recorded as bounded session
  execution authorization.
- [x] AC-02: A closed JSON contract defines issuer, subject, capability,
  resource, effect, budget, validity, lease and revocation bindings.
- [x] AC-03: The lifecycle rejects self-issuance, self-renewal, widening
  renewal, stale leases and terminal-state reuse.
- [x] AC-04: Grant evaluation is fail-closed and produces stable findings.
- [x] AC-05: Activation, use, renewal, revocation and expiry require immutable
  receipts without carrying credentials or secrets.
- [x] AC-06: A Subactor/Semcod profile maps protected authority services and
  execution lanes without moving runtime ownership into Wellmanifest.
- [x] AC-07: Positive and negative fixtures exercise normative invariants.
- [x] AC-08: Architecture, logic flow and integration guidance are documented.
- [x] AC-09: Governance, unit tests, compilation and lint checks pass.

## Participants

- Human participant: unresolved; no user-* file was created by this script.
- Agent participant: [ai-codex.md](ai-codex.md)
