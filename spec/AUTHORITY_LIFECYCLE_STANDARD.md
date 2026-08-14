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
5. a required lease is current, owned by the subject and within grant time;
6. the policy digest still matches protected policy;
7. the use produces a receipt and the effect is later verified separately.

Unknown or ambiguous evidence MUST fail closed.

## 5. Renewal and revocation

Renewal MUST be `external-only`. The subject, implementer, validator and
publisher MUST NOT renew or widen their own authority. A renewal MUST create a
new grant revision, preserve or narrow all scopes and budgets, bind the prior
grant digest and use a fresh receipt. It MUST NOT revive a terminal grant.

Revocation MUST take effect independently of agent availability. A kill switch
MUST be evaluated before each lease acquisition and before each publication
effect.

## 6. Separation from validation

Authority permits an effect; it does not prove the candidate is correct.
Validation attestations and effect read-back are separate facts. A grant MUST
deny grant issuance, grant renewal, policy modification and validator
attestation to ordinary execution subjects.

## 7. Conformance

Conforming implementations MUST validate the public JSON Schema and all
semantic invariants enforced by `src/authority_check.py`. Schema validity alone
is insufficient. Model output MAY advise but MUST NOT suppress a finding.
