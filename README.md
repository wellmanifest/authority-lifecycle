# wellmanifest/authority-lifecycle

Normative Wellmanifest domain pack for issuing, activating, leasing, renewing,
revoking, expiring, and auditing bounded machine authority.

The standard will ensure that an autonomous agent can act without per-action
human approval only while an independently issued grant is current, exact in
scope, and protected from self-extension.

Status: `0.1.0-dev`, governed implementation pending.

## HOME vs ADOPT (boundary matrix)

`HOME` wellmanifest · `shape` domain_pack. This pack owns **AuthZ** only.

| Concern | HOME | This pack |
| --- | --- | --- |
| AuthN profiles / binding receipts (`otp-email`, …) | `wellmanifest/auth-lifecycle` | **ADOPT signal only** — never redefine OTP procedures |
| AuthZ grants / leases / revoke / expire | **this pack** | Owns |
| Isolated tool runtimes / secret-free receipts | `wellmanifest/account-runtime` | Consumes grant shape; does not mint grants |
| Commercial onboarding order | `wellmanifest/saas-lifecycle` | Orthogonal; membership signal ≠ authority grant |
| Portal UI / OTP handlers | `subactor/www-sub-actor` (`runtime_service`) | Uses Control grants after membership |

See also: `docs/ARCHITECTURE.md`. Cross-ref LC-030.
