# Wellmanifest Authority Lifecycle Standard

Version `0.1.0-dev` defines a closed contract for authority used by autonomous
software agents. The key words MUST, MUST NOT, REQUIRED, SHOULD and MAY are
normative.

## 1. Boundary

Authority is a protected fact that answers whether one principal may perform a
specific effect on a specific resource at a specific time. A plan, ticket,
diagnostic, model response, repository file, review comment or successful test
MUST NOT create authority.

Wellmanifest owns this domain contract. Adopting runtimes such as Subactor own
signing, protected storage, lease coordination, execution and read-back.

## 2. Grant identity and protection

A grant MUST bind an immutable `grantId`, issuer, subject, capabilities,
resources, allowed effects, denied effects, budgets and validity interval. The
issuer MUST be a protected authority principal and MUST differ from the
subject. Credentials and secrets MUST NOT appear in a grant or receipt.

The authoritative grant MUST live outside the candidate-controlled checkout.
A repository copy MAY be an advisory declaration but MUST NOT be accepted as
the active protected grant.

An authority budget limits the risk or concurrency of effects admitted by this
grant. In particular, `maxCostMinor` is an execution safety ceiling in the
runtime's policy-defined cost basis. It MUST NOT be treated as a customer
allowance, invoice amount, paid package balance or usage charge. Commercial
entitlement and settlement belong to an adopted SaaS lifecycle/metering
contract and require their own receipts.

## 3. Lifecycle

The states are `issued`, `active`, `suspended`, `revoked`, `expired` and
`exhausted`. Allowed transitions are:

```text
issued    -> active | revoked | expired
active    -> suspended | revoked | expired | exhausted
suspended -> active | revoked | expired
revoked   -> terminal
expired   -> terminal
exhausted -> terminal
```

The current state MUST equal the terminal `to` value in the ordered history.
Every transition MUST have an immutable receipt bound to the grant and a
digest of the resulting subject. Terminal grants MUST NOT be reused or
reactivated.

## 4. Use and leases

An effect is authorized only when all of the following are true:

1. the protected grant resolves uniquely and is `active`;
2. evaluation time is within `notBefore` and `expiresAt`;
3. requested principal, capability, resource and effect match exactly;
4. the effect is not denied and budgets remain available;
5. the explicit lease policy is satisfied: when `required=true`, the fenced
   lease is current, owned by the subject and within grant time; when
   `required=false`, no lease coordinates are present;
6. the policy digest still matches protected policy;
7. the use produces a receipt and the effect is later verified separately.

Unknown or ambiguous evidence MUST fail closed.

A lease coordinates concurrent use; it does not delegate authority and does
not reserve commercial usage. An issuer MAY select `required=false` only when
the effect boundary is already concurrency-safe, for example a read-only
operation or an atomic single-use admission. `maxConcurrent`, idempotency,
revocation and receipt requirements continue to apply. Mutating effects that
can race SHOULD use a fenced lease.

## 5. Delegation

Delegation creates a new child grant; it never mutates the parent and never
transfers credentials. The child MUST bind the immutable parent grant id and
digest, its delegator, and a bounded chain depth. A protected issuer MUST
resolve that exact parent revision and prove all of the following before issue
and again before use:

1. the delegator is the parent subject and the parent is active;
2. child capabilities, resources and allowed effects are subsets of the parent;
3. child denied effects include every parent denial;
4. child budgets do not exceed the parent's remaining budgets;
5. child validity does not outlive the parent; and
6. `depth <= maxDepth` and the parent permits another child.

The document constants `protected-narrow-only`, `subset-only`, `no-increase`
and `not-after-parent` declare those checks; they are not evidence that the
checks happened. The protected issuer/evaluator produces that evidence.
The child subject MUST NOT issue the child or widen either grant.

## 6. Renewal and revocation

Renewal MUST be `external-only`. The subject, implementer, validator and
publisher MUST NOT renew or widen their own authority. A renewal MUST create a
new grant revision, preserve or narrow all scopes and budgets, bind the prior
grant digest and use a fresh receipt. It MUST NOT revive a terminal grant.

Revocation MUST take effect independently of agent availability. A kill switch
MUST be evaluated before each lease acquisition and before each publication
effect.

## 7. Separation from identity, entitlement and validation

Authority permits an effect; it does not prove the candidate is correct.
Validation attestations and effect read-back are separate facts. A grant MUST
deny grant issuance, grant renewal, policy modification and validator
attestation to ordinary execution subjects.

Authentication proves a principal, commercial entitlement proves access to a
product or allowance, and usage settlement changes a commercial balance.
None of those facts creates effect authority, and an authority grant does not
create any of them. A runtime may require all layers for one operation, but it
MUST evaluate and receipt them independently.

## 8. Conformance

Conforming implementations MUST validate the public JSON Schema and all
semantic invariants enforced by `src/authority_check.py`. Schema validity alone
is insufficient. Model output MAY advise but MUST NOT suppress a finding.
