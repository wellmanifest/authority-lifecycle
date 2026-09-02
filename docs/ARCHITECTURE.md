# Architecture

The standard separates five trust domains:

```text
declaration -> protected issuer -> protected grant store -> evaluator
                                                            |
                                      optional fenced lease -+
                                                            v
                                                     bounded executor
                                                            |
                                                            v
                                                  append-only receipts
```

Repository declarations are untrusted inputs. The issuer resolves policy and
creates an immutable grant revision. For delegated authority it also resolves
the exact parent revision and proves that the child only narrows scope, budget
and validity. The evaluator reads protected state and, when policy requires
exclusive coordination, issues a fenced lease. The executor receives only the bounded use decision and
short-lived capability needed for the declared effect. Receipts record facts;
they do not carry credentials and do not create new authority.

The boundaries are intentionally orthogonal:

```text
authentication -> identifies principal
commercial entitlement -> permits package consumption
authority grant -> permits a bounded effect
lease -> coordinates concurrent grant use
usage settlement -> debits or waives a measured unit
validation/read-back -> proves outcome
```

Passing one boundary never implies that another passed. In particular an
authority risk budget is not a customer balance, and a commercial package is
not permission to mutate a resource.

The issuer/revoker, executor, independent validator and publisher should use
separate service identities and preferably separate process or container
boundaries. Different model names are not evidence of independence.

Subactor is the runtime owner. Wellmanifest provides the portable contract,
schema and tests. Semcod tools may propose scope or inspect receipts but cannot
materialize a grant.
