# Logic flow

## Grant creation and use

1. A trusted intake resolves a bounded requested capability and resource.
2. The protected issuer evaluates policy and emits revision 1 in `issued`.
3. A protected activation transition produces a digest-bound receipt.
4. The evaluator resolves any parent grant and verifies narrow-only delegation.
5. When the explicit lease policy requires fencing, the executor requests a
   lease using its own principal identity; otherwise no lease identity exists.
6. The evaluator checks current state, time, scope, authority risk budget,
   applicable fencing epoch and kill switch.
7. A separate entitlement/metering boundary admits or rejects commercial
   package consumption when the operation is billable.
8. The executor performs at most the declared effect.
9. Execution, usage settlement and read-back receipts are appended
   independently and correlated without being conflated.

## Delegation

1. A parent subject requests a child scope; that request is not a grant.
2. The protected issuer resolves the parent by id and digest.
3. It compares capability, resource, effect, denial, remaining budget,
   validity and depth boundaries.
4. It issues a distinct child revision with delegation provenance or denies
   the request. The parent remains unchanged.
5. Every child use rechecks parent terminal state and the bound parent digest.

## Renewal

Renewal creates a new revision through the protected issuer. The new revision
must reference the prior digest and may only preserve or narrow capabilities,
resources, effects, time and budgets. The subject cannot request an effective
widening by changing repository-controlled declarations.

## Failure behavior

Missing state, unknown fields, stale policy, a missing required lease,
unexpected coordinates on a no-lease policy, unresolved delegation ancestry,
ambiguous resource, authority-budget exhaustion or a terminal grant produces a denial with a stable code.
The runtime may open a diagnostic ticket, but that ticket is not repair or
grant authority.
