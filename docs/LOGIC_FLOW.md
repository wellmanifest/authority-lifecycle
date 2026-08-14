# Logic flow

## Grant creation and use

1. A trusted intake resolves a bounded requested capability and resource.
2. The protected issuer evaluates policy and emits revision 1 in `issued`.
3. A protected activation transition produces a digest-bound receipt.
4. The executor requests a lease using its own principal identity.
5. The evaluator checks current state, time, scope, budget, policy digest,
   fencing epoch and kill switch.
6. The executor performs at most the declared effect.
7. Execution and read-back receipts are appended independently.

## Renewal

Renewal creates a new revision through the protected issuer. The new revision
must reference the prior digest and may only preserve or narrow capabilities,
resources, effects, time and budgets. The subject cannot request an effective
widening by changing repository-controlled declarations.

## Failure behavior

Missing state, unknown fields, stale policy, stale lease, ambiguous resource,
budget exhaustion or a terminal grant produces a denial with a stable code.
The runtime may open a diagnostic ticket, but that ticket is not repair or
grant authority.
