# Ticket 006: Separate delegation, leases, authority budgets and commercial entitlement

- **ID**: ticket-006
- **Owner**: unresolved:human
- **Status**: IN_PROGRESS
- **Workflow state**: EDIT
- **Created**: 2026-09-02

## Goal and scope

Correct the v1 authority contract so a fenced lease is an explicit concurrency
policy rather than a mandatory property of every grant. Add a protected,
digest-bound delegation provenance contract whose child authority can only be
narrower than its parent. Clarify that authority budgets constrain execution
risk and never represent a commercial entitlement, usage balance or charge.

The request to execute and publish this standards-first refactor is recorded as
`SESSION_EXECUTION_AUTHORIZATION`. It permits implementation and protected
delivery without another confirmation, but it does not substitute for trusted
exact-head review or grant merge authority to this agent.

## Acceptance criteria

- [x] AC-01: `lease.required=false` is a closed valid policy with no synthetic
      lease identity, while required leases remain fenced and time bounded.
- [x] AC-02: delegated grants bind the parent id and digest, delegator, depth
      and explicit subset/no-increase policies; malformed or self-delegated
      documents fail closed.
- [x] AC-03: normative guidance separates authority, lease, delegation,
      validation and commercial usage settlement.
- [x] AC-04: schema, semantic, unit and governance checks pass.

## Participants

- Human participant: unresolved; no user-* file was created by this script.
- Agent participant: [ai-codex.md](ai-codex.md)
