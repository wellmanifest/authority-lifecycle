# Architecture

The standard separates five trust domains:

```text
declaration -> protected issuer -> protected grant store -> lease/evaluator
                                                            |
                                                            v
                                                     bounded executor
                                                            |
                                                            v
                                                  append-only receipts
```

Repository declarations are untrusted inputs. The issuer resolves policy and
creates an immutable grant revision. The evaluator reads protected state and
issues a fenced lease. The executor receives only the bounded use decision and
short-lived capability needed for the declared effect. Receipts record facts;
they do not carry credentials and do not create new authority.

The issuer/revoker, executor, independent validator and publisher should use
separate service identities and preferably separate process or container
boundaries. Different model names are not evidence of independence.

Subactor is the runtime owner. Wellmanifest provides the portable contract,
schema and tests. Semcod tools may propose scope or inspect receipts but cannot
materialize a grant.
