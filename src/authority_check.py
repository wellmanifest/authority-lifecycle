#!/usr/bin/env python3
"""Dependency-free semantic conformance checker for authority lifecycle v1."""

from __future__ import annotations

import argparse
import copy
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = (ROOT / "examples").resolve()

SYNTAX = "AUTH-SYNTAX-001"
IDENTITY = "AUTH-IDENTITY-001"
SCOPE = "AUTH-SCOPE-001"
TIME = "AUTH-TIME-001"
RENEWAL = "AUTH-RENEWAL-001"
STATE = "AUTH-STATE-001"
RECEIPT = "AUTH-RECEIPT-001"
SECRET = "AUTH-SECRET-001"
PROFILE = "AUTH-PROFILE-001"

DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
PRINCIPAL_URI = re.compile(r"^authority://principal/[a-z0-9][a-z0-9._/-]*$")
GRANT_URI = re.compile(r"^authority://grant/[a-z0-9][a-z0-9._/-]*$")
MANDATORY_DENIED = {
    "grant.issue",
    "grant.renew",
    "grant.expand",
    "grant.revoke",
    "policy.modify",
    "validator.attest",
    "git.main.write",
}
TRANSITIONS = {
    "issued": {"active", "revoked", "expired"},
    "active": {"suspended", "revoked", "expired", "exhausted"},
    "suspended": {"active", "revoked", "expired"},
    "revoked": set(),
    "expired": set(),
    "exhausted": set(),
}
PROFILE_MODES = {
    "issue": "protected-write",
    "evaluate": "read-only",
    "lease": "protected-write",
    "execute": "consume-only",
    "revoke": "protected-write",
    "audit": "append-only",
}


@dataclass(frozen=True)
class Finding:
    code: str
    path: str
    message: str
    severity: str = "critical"

    def render(self) -> str:
        return f"{self.code} {self.severity} {self.path}: {self.message}"


def _add(findings: list[Finding], code: str, path: str, message: str) -> None:
    findings.append(Finding(code, path, message))


def _closed(
    value: Any,
    path: str,
    required: set[str],
    allowed: set[str],
    findings: list[Finding],
) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        _add(findings, SYNTAX, path, "must be an object")
        return None
    missing = sorted(required - set(value))
    unknown = sorted(set(value) - allowed)
    if missing:
        _add(findings, SYNTAX, path, f"missing fields: {', '.join(missing)}")
    if unknown:
        _add(findings, SYNTAX, path, f"unknown fields: {', '.join(unknown)}")
    return value


def _time(value: Any, path: str, findings: list[Finding]) -> datetime | None:
    if not isinstance(value, str):
        _add(findings, SYNTAX, path, "must be an RFC3339 timestamp")
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        _add(findings, SYNTAX, path, "must be an RFC3339 timestamp")
        return None
    if parsed.tzinfo is None:
        _add(findings, SYNTAX, path, "must include a timezone")
        return None
    return parsed


def _principal(value: Any, path: str, findings: list[Finding]) -> dict[str, Any] | None:
    principal = _closed(value, path, {"uri", "kind"}, {"uri", "kind"}, findings)
    if principal is None:
        return None
    if not isinstance(principal.get("uri"), str) or not PRINCIPAL_URI.fullmatch(principal["uri"]):
        _add(findings, SYNTAX, f"{path}/uri", "invalid authority principal URI")
    if principal.get("kind") not in {"protected-authority", "agent", "service", "human"}:
        _add(findings, SYNTAX, f"{path}/kind", "unknown principal kind")
    return principal


def _scan_secrets(value: Any, path: str, findings: list[Finding]) -> None:
    denied = ("token", "secret", "password", "credential", "privatekey", "apikey")
    if isinstance(value, dict):
        for key, nested in value.items():
            normalized = re.sub(r"[^a-z]", "", str(key).lower())
            if any(part in normalized for part in denied):
                _add(findings, SECRET, f"{path}/{key}", "secret-bearing field is forbidden")
            _scan_secrets(nested, f"{path}/{key}", findings)
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _scan_secrets(nested, f"{path}/{index}", findings)
    elif isinstance(value, str) and re.search(r"(?i)\bbearer\s+[a-z0-9._-]+", value):
        _add(findings, SECRET, path, "credential-like value is forbidden")


def _receipt(value: Any, path: str, findings: list[Finding]) -> dict[str, Any] | None:
    receipt = _closed(
        value,
        path,
        {"receiptId", "actor", "at", "subjectDigest"},
        {"receiptId", "actor", "at", "subjectDigest"},
        findings,
    )
    if receipt is None:
        return None
    receipt_id = receipt.get("receiptId")
    if not isinstance(receipt_id, str) or not receipt_id.startswith("authority://receipt/"):
        _add(findings, RECEIPT, f"{path}/receiptId", "invalid receipt URI")
    _principal(receipt.get("actor"), f"{path}/actor", findings)
    _time(receipt.get("at"), f"{path}/at", findings)
    if not isinstance(receipt.get("subjectDigest"), str) or not DIGEST.fullmatch(
        receipt["subjectDigest"]
    ):
        _add(findings, RECEIPT, f"{path}/subjectDigest", "exact SHA-256 binding required")
    return receipt


def _validate_scope(value: Any, findings: list[Finding]) -> None:
    scope = _closed(
        value,
        "/scope",
        {"capabilities", "resources", "allowedEffects", "deniedEffects"},
        {"capabilities", "resources", "allowedEffects", "deniedEffects"},
        findings,
    )
    if scope is None:
        return
    for field in ("capabilities", "resources", "allowedEffects", "deniedEffects"):
        items = scope.get(field)
        if (
            not isinstance(items, list)
            or not items
            or not all(isinstance(item, str) for item in items)
        ):
            _add(findings, SYNTAX, f"/scope/{field}", "must be a non-empty string array")
        elif len(items) != len(set(items)):
            _add(findings, SCOPE, f"/scope/{field}", "duplicates are forbidden")
    allowed = set(scope.get("allowedEffects") or [])
    denied = set(scope.get("deniedEffects") or [])
    overlap = allowed & denied
    if overlap:
        _add(findings, SCOPE, "/scope", f"effects both allowed and denied: {sorted(overlap)}")
    missing = MANDATORY_DENIED - denied
    if missing:
        _add(
            findings,
            SCOPE,
            "/scope/deniedEffects",
            f"mandatory denials missing: {sorted(missing)}",
        )


def _validate_history(
    history: Any,
    state: Any,
    issuer_uri: str | None,
    findings: list[Finding],
) -> None:
    if not isinstance(history, list) or not history:
        _add(findings, SYNTAX, "/history", "must be a non-empty transition array")
        return
    previous: str | None = None
    seen_receipts: set[str] = set()
    for index, value in enumerate(history):
        path = f"/history/{index}"
        event = _closed(
            value,
            path,
            {"from", "to", "reason", "receipt"},
            {"from", "to", "reason", "receipt"},
            findings,
        )
        if event is None:
            continue
        source, target = event.get("from"), event.get("to")
        valid = target == "issued" and source is None and index == 0
        if not valid:
            valid = source == previous and target in TRANSITIONS.get(str(source), set())
        if not valid:
            _add(findings, STATE, path, f"invalid transition {source!r} -> {target!r}")
        receipt = _receipt(event.get("receipt"), f"{path}/receipt", findings)
        if receipt:
            receipt_id = str(receipt.get("receiptId"))
            if receipt_id in seen_receipts:
                _add(findings, RECEIPT, f"{path}/receipt/receiptId", "receipt replay detected")
            seen_receipts.add(receipt_id)
            actor = receipt.get("actor") or {}
            if target in {"issued", "active"} and actor.get("uri") != issuer_uri:
                _add(
                    findings,
                    IDENTITY,
                    f"{path}/receipt/actor",
                    "issuance requires the grant issuer",
                )
        previous = target if isinstance(target, str) else previous
    if previous != state:
        _add(findings, STATE, "/state", "current state must equal the last transition target")


def _validate_grant(document: dict[str, Any], at: datetime | None) -> list[Finding]:
    findings: list[Finding] = []
    required = {
        "schema", "grantId", "revision", "state", "issuer", "subject", "policyDigest",
        "scope", "budgets", "validity", "renewal", "lease", "history",
    }
    grant = _closed(document, "", required, required, findings)
    if grant is None:
        return findings
    if not isinstance(grant.get("grantId"), str) or not GRANT_URI.fullmatch(grant["grantId"]):
        _add(findings, SYNTAX, "/grantId", "invalid grant URI")
    if not isinstance(grant.get("revision"), int) or grant["revision"] < 1:
        _add(findings, SYNTAX, "/revision", "must be a positive integer")
    if grant.get("state") not in TRANSITIONS:
        _add(findings, SYNTAX, "/state", "unknown lifecycle state")

    issuer = _principal(grant.get("issuer"), "/issuer", findings)
    subject = _principal(grant.get("subject"), "/subject", findings)
    issuer_uri = issuer.get("uri") if issuer else None
    subject_uri = subject.get("uri") if subject else None
    if issuer and issuer.get("kind") != "protected-authority":
        _add(findings, IDENTITY, "/issuer/kind", "issuer must be protected-authority")
    if issuer_uri and issuer_uri == subject_uri:
        _add(findings, IDENTITY, "/subject", "issuer and subject must be different principals")
    if not isinstance(grant.get("policyDigest"), str) or not DIGEST.fullmatch(
        grant["policyDigest"]
    ):
        _add(findings, SYNTAX, "/policyDigest", "exact SHA-256 policy binding required")
    _validate_scope(grant.get("scope"), findings)

    budgets = _closed(
        grant.get("budgets"),
        "/budgets",
        {"maxUses", "maxConcurrent", "maxCostMinor"},
        {"maxUses", "maxConcurrent", "maxCostMinor"},
        findings,
    )
    if budgets:
        for field, minimum in (("maxUses", 1), ("maxConcurrent", 1), ("maxCostMinor", 0)):
            if not isinstance(budgets.get(field), int) or budgets[field] < minimum:
                _add(findings, SCOPE, f"/budgets/{field}", f"must be an integer >= {minimum}")

    validity = _closed(
        grant.get("validity"),
        "/validity",
        {"notBefore", "expiresAt"},
        {"notBefore", "expiresAt"},
        findings,
    )
    not_before = expires_at = None
    if validity:
        not_before = _time(validity.get("notBefore"), "/validity/notBefore", findings)
        expires_at = _time(validity.get("expiresAt"), "/validity/expiresAt", findings)
        if not_before and expires_at and not_before >= expires_at:
            _add(findings, TIME, "/validity", "notBefore must precede expiresAt")

    renewal = _closed(
        grant.get("renewal"),
        "/renewal",
        {"mode", "issuer", "maxRenewals", "priorGrantDigestRequired"},
        {"mode", "issuer", "maxRenewals", "priorGrantDigestRequired"},
        findings,
    )
    if renewal:
        renewer = _principal(renewal.get("issuer"), "/renewal/issuer", findings)
        if (
            renewal.get("mode") != "external-only"
            or renewal.get("priorGrantDigestRequired") is not True
        ):
            _add(
                findings,
                RENEWAL,
                "/renewal",
                "renewal must be external-only and prior-digest bound",
            )
        if renewer and renewer.get("kind") != "protected-authority":
            _add(findings, RENEWAL, "/renewal/issuer", "renewal issuer must be protected")
        if renewer and renewer.get("uri") == subject_uri:
            _add(findings, RENEWAL, "/renewal/issuer", "subject cannot renew its own grant")
        if renewer and issuer_uri and renewer.get("uri") != issuer_uri:
            _add(findings, RENEWAL, "/renewal/issuer", "renewal issuer must match original issuer")
        if not isinstance(renewal.get("maxRenewals"), int) or renewal["maxRenewals"] < 0:
            _add(findings, RENEWAL, "/renewal/maxRenewals", "must be a non-negative integer")

    lease = _closed(
        grant.get("lease"),
        "/lease",
        {"required", "leaseId", "owner", "epoch", "acquiredAt", "expiresAt"},
        {"required", "leaseId", "owner", "epoch", "acquiredAt", "expiresAt"},
        findings,
    )
    lease_start = lease_end = None
    if lease:
        owner = _principal(lease.get("owner"), "/lease/owner", findings)
        if lease.get("required") is not True:
            _add(findings, TIME, "/lease/required", "bounded autonomous use requires a lease")
        if owner and owner.get("uri") != subject_uri:
            _add(findings, IDENTITY, "/lease/owner", "lease owner must equal grant subject")
        if not isinstance(lease.get("epoch"), int) or lease["epoch"] < 1:
            _add(findings, TIME, "/lease/epoch", "must be a positive fencing epoch")
        lease_start = _time(lease.get("acquiredAt"), "/lease/acquiredAt", findings)
        lease_end = _time(lease.get("expiresAt"), "/lease/expiresAt", findings)
        if lease_start and lease_end and lease_start >= lease_end:
            _add(findings, TIME, "/lease", "lease acquisition must precede expiry")
        if not_before and lease_start and lease_start < not_before:
            _add(findings, TIME, "/lease/acquiredAt", "lease starts before the grant")
        if expires_at and lease_end and lease_end > expires_at:
            _add(findings, TIME, "/lease/expiresAt", "lease outlives the grant")

    _validate_history(grant.get("history"), grant.get("state"), issuer_uri, findings)
    if at is not None:
        if grant.get("state") != "active":
            _add(findings, STATE, "/state", "runtime evaluation requires an active grant")
        if not_before and at < not_before or expires_at and at >= expires_at:
            _add(findings, TIME, "/validity", "grant is not current at evaluation time")
        if lease_start and at < lease_start or lease_end and at >= lease_end:
            _add(findings, TIME, "/lease", "lease is not current at evaluation time")
    _scan_secrets(grant, "", findings)
    return findings


def _validate_profile(document: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    required = {"schema", "profileId", "version", "ownership", "bindings"}
    profile = _closed(document, "", required, required, findings)
    if profile is None:
        return findings
    ownership = _closed(
        profile.get("ownership"),
        "/ownership",
        {"standardOwner", "runtimeOwner", "adopts"},
        {"standardOwner", "runtimeOwner", "adopts"},
        findings,
    )
    if ownership:
        if ownership.get("standardOwner") != "wellmanifest/authority-lifecycle":
            _add(findings, PROFILE, "/ownership/standardOwner", "wrong standard owner")
        runtime_owner = ownership.get("runtimeOwner")
        if not isinstance(runtime_owner, str) or runtime_owner.startswith("wellmanifest/"):
            _add(
                findings,
                PROFILE,
                "/ownership/runtimeOwner",
                "runtime must remain outside Wellmanifest",
            )
        adopts = ownership.get("adopts")
        if not isinstance(adopts, list) or "wellmanifest/autonomy" not in adopts:
            _add(findings, PROFILE, "/ownership/adopts", "autonomy adoption is required")
    bindings = profile.get("bindings")
    if not isinstance(bindings, list):
        _add(findings, SYNTAX, "/bindings", "must be an array")
        return findings
    observed: dict[str, str] = {}
    principals: dict[str, dict[str, Any]] = {}
    for index, value in enumerate(bindings):
        path = f"/bindings/{index}"
        binding = _closed(
            value,
            path,
            {"stage", "uri", "principal", "mode"},
            {"stage", "uri", "principal", "mode"},
            findings,
        )
        if binding is None:
            continue
        stage = binding.get("stage")
        if stage in observed:
            _add(findings, PROFILE, f"{path}/stage", "duplicate stage")
        if isinstance(stage, str):
            observed[stage] = str(binding.get("mode"))
            principal = _principal(binding.get("principal"), f"{path}/principal", findings)
            if principal:
                principals[stage] = principal
    if observed != PROFILE_MODES:
        _add(findings, PROFILE, "/bindings", "exact stage and mode mapping is required")
    for stage in ("issue", "lease", "revoke"):
        if principals.get(stage, {}).get("kind") != "protected-authority":
            _add(findings, PROFILE, f"/bindings/{stage}", "protected authority required")
    if principals.get("execute", {}).get("uri") in {
        principals.get("issue", {}).get("uri"),
        principals.get("revoke", {}).get("uri"),
    }:
        _add(findings, PROFILE, "/bindings", "executor cannot issue or revoke grants")
    _scan_secrets(profile, "", findings)
    return findings


def validate_document(document: Any, at: datetime | None = None) -> list[Finding]:
    if not isinstance(document, dict):
        return [Finding(SYNTAX, "", "document must be an object")]
    schema = document.get("schema")
    if schema == "wellmanifest.authority/grant/v1":
        return _validate_grant(document, at)
    if schema == "wellmanifest.authority/profile/v1":
        return _validate_profile(document)
    return [Finding(SYNTAX, "/schema", "unsupported authority document schema")]


def _pointer_parent(document: Any, pointer: str) -> tuple[Any, str]:
    if not pointer.startswith("/"):
        raise ValueError("mutation path must be an absolute JSON Pointer")
    parts = [part.replace("~1", "/").replace("~0", "~") for part in pointer[1:].split("/")]
    current = document
    for part in parts[:-1]:
        current = current[int(part)] if isinstance(current, list) else current[part]
    return current, parts[-1]


def apply_invalid_case(
    case: dict[str, Any], case_path: Path
) -> tuple[Any, datetime | None, list[Finding]]:
    allowed = {"schema", "base", "mutations", "expectedCodes", "evaluationTime"}
    findings: list[Finding] = []
    if set(case) - allowed:
        _add(findings, SYNTAX, "", "unknown invalid-case fields")
    try:
        base = (case_path.parent / str(case["base"])).resolve()
        base.relative_to(EXAMPLES)
    except (KeyError, ValueError):
        return {}, None, [Finding(SYNTAX, "/base", "base escapes examples root")]
    try:
        document = json.loads(base.read_text(encoding="utf-8"))
        document = copy.deepcopy(document)
        for mutation in case.get("mutations", []):
            parent, key = _pointer_parent(document, mutation["path"])
            if mutation["op"] == "replace":
                if isinstance(parent, list):
                    parent[int(key)] = mutation["value"]
                else:
                    parent[key] = mutation["value"]
            elif mutation["op"] == "remove":
                if isinstance(parent, list):
                    parent.pop(int(key))
                else:
                    del parent[key]
            else:
                raise ValueError("unsupported mutation")
    except (OSError, KeyError, IndexError, TypeError, ValueError, json.JSONDecodeError) as error:
        return {}, None, [Finding(SYNTAX, "/mutations", f"invalid case: {error}")]
    at = None
    if "evaluationTime" in case:
        at = _time(case["evaluationTime"], "/evaluationTime", findings)
    return document, at, findings


def load_and_validate(path: Path, at: datetime | None = None) -> list[Finding]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return [Finding(SYNTAX, "", str(error))]
    prefix: list[Finding] = []
    if (
        isinstance(document, dict)
        and document.get("schema") == "wellmanifest.authority/invalid-case/v1"
    ):
        document, case_at, prefix = apply_invalid_case(document, path.resolve())
        at = case_at if case_at is not None else at
    return prefix + validate_document(document, at)


def self_test() -> int:
    failures: list[str] = []
    for path in sorted((EXAMPLES / "valid").glob("*.json")):
        findings = load_and_validate(path)
        if findings:
            failures.append(f"{path.name}: expected valid, got {[item.code for item in findings]}")
    profile_findings = load_and_validate(ROOT / "profiles" / "subactor-semcod.profile.json")
    if profile_findings:
        failures.append(f"profile: expected valid, got {[item.code for item in profile_findings]}")
    for path in sorted((EXAMPLES / "invalid").glob("*.json")):
        case = json.loads(path.read_text(encoding="utf-8"))
        observed = {item.code for item in load_and_validate(path)}
        expected = set(case.get("expectedCodes", []))
        if not expected <= observed:
            failures.append(f"{path.name}: expected {sorted(expected)}, got {sorted(observed)}")
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print("AUTH-PASS: valid fixtures and declared negative findings passed")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate = subparsers.add_parser("validate")
    validate.add_argument("path", type=Path)
    validate.add_argument("--at")
    subparsers.add_parser("self-test")
    args = parser.parse_args(argv)
    if args.command == "self-test":
        return self_test()
    at = None
    if args.at:
        temp: list[Finding] = []
        at = _time(args.at, "--at", temp)
        if temp:
            print(temp[0].render(), file=sys.stderr)
            return 2
    paths = sorted(args.path.rglob("*.json")) if args.path.is_dir() else [args.path]
    failed = False
    for path in paths:
        findings = load_and_validate(path, at)
        for finding in findings:
            print(f"{path}: {finding.render()}")
        failed = failed or bool(findings)
    if not failed:
        print(f"AUTH-PASS: {len(paths)} document(s) conform")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
