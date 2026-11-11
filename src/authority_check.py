#!/usr/bin/env python3
"""Dependency-free semantic conformance checker for authority lifecycle v1."""

from __future__ import annotations

import argparse
import copy
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

_SRC_DIR = str(Path(__file__).resolve().parent)
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from authority_primitives import (  # noqa: E402
    ADOPTED_STANDARD,
    CAPABILITY_URI,
    DELEGATION,
    DIGEST,
    EFFECT_NAME,
    GRANT_URI,
    IDENTITY,
    LEASE,
    MANDATORY_DENIED,
    PROCESS_URI,
    PROFILE,
    PROFILE_MODES,
    PROFILE_URI,
    RECEIPT,
    RENEWAL,
    RESOURCE_URI,
    RUNTIME_OWNER,
    SCOPE,
    SECRET,
    SEMVER,
    STATE,
    SYNTAX,
    TIME,
    TRANSITIONS,
    DuplicateKeyError,
    Finding,
    add_finding,
    closed_object,
    is_strict_int,
    iter_json_paths,
    load_strict_json,
    parse_array_index,
    parse_rfc3339,
    pointer_parent,
    resolve_within_examples,
    scan_secrets,
    valid_hierarchical_id,
    validate_delegation,
    validate_lease,
    validate_principal,
    validate_receipt,
)

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = (ROOT / "examples").resolve()

__all__ = [
    "DELEGATION",
    "Finding",
    "IDENTITY",
    "LEASE",
    "PROFILE",
    "RECEIPT",
    "RENEWAL",
    "SCOPE",
    "SECRET",
    "STATE",
    "SYNTAX",
    "TIME",
    "apply_invalid_case",
    "load_and_validate",
    "main",
    "self_test",
    "validate_document",
]


def _validate_scope_items(field: str, items: list[str], findings: list[Finding]) -> None:
    for index, item in enumerate(items):
        item_path = f"/scope/{field}/{index}"
        if field == "capabilities" and not valid_hierarchical_id(item, CAPABILITY_URI):
            add_finding(findings, SYNTAX, item_path, "invalid capability URI")
        elif field == "resources" and RESOURCE_URI.fullmatch(item) is None:
            add_finding(findings, SYNTAX, item_path, "invalid resource URI")
        elif field in {"allowedEffects", "deniedEffects"} and EFFECT_NAME.fullmatch(item) is None:
            add_finding(findings, SYNTAX, item_path, "invalid effect identifier")


def _validate_scope(value: Any, findings: list[Finding]) -> None:
    fields = {"capabilities", "resources", "allowedEffects", "deniedEffects"}
    scope = closed_object(value, "/scope", fields, fields, findings)
    if scope is None:
        return
    clean_sets: dict[str, set[str]] = {}
    for field in ("capabilities", "resources", "allowedEffects", "deniedEffects"):
        items = scope.get(field)
        if not isinstance(items, list) or not items or not all(isinstance(x, str) for x in items):
            add_finding(findings, SYNTAX, f"/scope/{field}", "must be a non-empty string array")
            clean_sets[field] = set()
            continue
        if len(items) != len(set(items)):
            add_finding(findings, SCOPE, f"/scope/{field}", "duplicates are forbidden")
        _validate_scope_items(field, items, findings)
        clean_sets[field] = set(items)
    overlap = clean_sets["allowedEffects"] & clean_sets["deniedEffects"]
    if overlap:
        add_finding(
            findings, SCOPE, "/scope", f"effects both allowed and denied: {sorted(overlap)}"
        )
    if isinstance(scope.get("deniedEffects"), list):
        missing = MANDATORY_DENIED - clean_sets["deniedEffects"]
        if missing:
            add_finding(
                findings,
                SCOPE,
                "/scope/deniedEffects",
                f"mandatory denials missing: {sorted(missing)}",
            )


def _validate_history(
    history: Any, state: Any, issuer_uri: str | None, findings: list[Finding]
) -> None:
    if not isinstance(history, list) or not history:
        add_finding(findings, SYNTAX, "/history", "must be a non-empty transition array")
        return
    previous: str | None = None
    seen_receipts: set[str] = set()
    event_fields = {"from", "to", "reason", "receipt"}
    for index, value in enumerate(history):
        path = f"/history/{index}"
        event = closed_object(value, path, event_fields, event_fields, findings)
        if event is None:
            continue
        source, target, reason = event.get("from"), event.get("to"), event.get("reason")
        if source is not None and (not isinstance(source, str) or source not in TRANSITIONS):
            add_finding(findings, SYNTAX, f"{path}/from", "unknown source lifecycle state")
        if not isinstance(target, str) or target not in TRANSITIONS:
            add_finding(findings, SYNTAX, f"{path}/to", "unknown target lifecycle state")
        if not isinstance(reason, str) or len(reason.strip()) < 3 or len(reason) > 240:
            add_finding(
                findings, SYNTAX, f"{path}/reason", "reason must be 3..240 non-blank chars"
            )
        valid = target == "issued" and source is None and index == 0
        if not valid:
            valid = (
                isinstance(source, str)
                and source == previous
                and isinstance(target, str)
                and target in TRANSITIONS.get(source, set())
            )
        if not valid:
            add_finding(findings, STATE, path, f"invalid transition {source!r} -> {target!r}")
        receipt = validate_receipt(event.get("receipt"), f"{path}/receipt", findings)
        if receipt is not None:
            receipt_id = receipt.get("receiptId")
            if isinstance(receipt_id, str):
                if receipt_id in seen_receipts:
                    add_finding(
                        findings, RECEIPT, f"{path}/receipt/receiptId", "receipt replay detected"
                    )
                seen_receipts.add(receipt_id)
            actor = receipt.get("actor")
            actor_uri = actor.get("uri") if isinstance(actor, dict) else None
            if (
                isinstance(target, str)
                and target in {"issued", "active"}
                and actor_uri != issuer_uri
            ):
                add_finding(
                    findings, IDENTITY, f"{path}/receipt/actor", "issuance requires grant issuer"
                )
        previous = target if isinstance(target, str) else previous
    if not isinstance(state, str) or previous != state:
        add_finding(findings, STATE, "/state", "current state must equal last transition target")


def _principal_uri(principal: dict[str, Any] | None) -> str | None:
    if isinstance(principal, dict) and isinstance(principal.get("uri"), str):
        return principal["uri"]
    return None


def _validate_grant(document: dict[str, Any], at: datetime | None) -> list[Finding]:
    findings: list[Finding] = []
    required = {
        "schema", "grantId", "revision", "state", "issuer", "subject", "policyDigest",
        "scope", "budgets", "validity", "renewal", "lease", "history",
    }
    grant = closed_object(document, "", required, required | {"delegation"}, findings)
    if grant is None:
        return findings
    if not valid_hierarchical_id(grant.get("grantId"), GRANT_URI):
        add_finding(findings, SYNTAX, "/grantId", "invalid grant URI")
    revision = grant.get("revision")
    if not is_strict_int(revision) or revision < 1:
        add_finding(findings, SYNTAX, "/revision", "must be a positive integer")
    grant_state = grant.get("state")
    if not isinstance(grant_state, str) or grant_state not in TRANSITIONS:
        add_finding(findings, SYNTAX, "/state", "unknown lifecycle state")

    issuer = validate_principal(grant.get("issuer"), "/issuer", findings)
    subject = validate_principal(grant.get("subject"), "/subject", findings)
    issuer_uri, subject_uri = _principal_uri(issuer), _principal_uri(subject)
    if issuer and issuer.get("kind") != "protected-authority":
        add_finding(findings, IDENTITY, "/issuer/kind", "issuer must be protected-authority")
    if issuer_uri and issuer_uri == subject_uri:
        add_finding(findings, IDENTITY, "/subject", "issuer and subject must differ")
    policy_digest = grant.get("policyDigest")
    if not isinstance(policy_digest, str) or not DIGEST.fullmatch(policy_digest):
        add_finding(findings, SYNTAX, "/policyDigest", "exact SHA-256 policy binding required")
    _validate_scope(grant.get("scope"), findings)

    budget_fields = {"maxUses", "maxConcurrent", "maxCostMinor"}
    budgets = closed_object(
        grant.get("budgets"), "/budgets", budget_fields, budget_fields, findings
    )
    if budgets:
        for field, minimum in (("maxUses", 1), ("maxConcurrent", 1), ("maxCostMinor", 0)):
            val = budgets.get(field)
            if not is_strict_int(val) or val < minimum:
                add_finding(findings, SCOPE, f"/budgets/{field}", f"must be integer >= {minimum}")

    val_fields = {"notBefore", "expiresAt"}
    validity = closed_object(grant.get("validity"), "/validity", val_fields, val_fields, findings)
    not_before = expires_at = None
    if validity:
        not_before = parse_rfc3339(validity.get("notBefore"), "/validity/notBefore", findings)
        expires_at = parse_rfc3339(validity.get("expiresAt"), "/validity/expiresAt", findings)
        if not_before and expires_at and not_before >= expires_at:
            add_finding(findings, TIME, "/validity", "notBefore must precede expiresAt")

    ren_fields = {"mode", "issuer", "maxRenewals", "priorGrantDigestRequired"}
    renewal = closed_object(grant.get("renewal"), "/renewal", ren_fields, ren_fields, findings)
    if renewal:
        renewer = validate_principal(renewal.get("issuer"), "/renewal/issuer", findings)
        if (
            renewal.get("mode") != "external-only"
            or renewal.get("priorGrantDigestRequired") is not True
        ):
            add_finding(findings, RENEWAL, "/renewal", "must be external-only and prior-digest")
        if renewer and renewer.get("kind") != "protected-authority":
            add_finding(findings, RENEWAL, "/renewal/issuer", "renewal issuer must be protected")
        if renewer and isinstance(subject_uri, str) and renewer.get("uri") == subject_uri:
            add_finding(findings, RENEWAL, "/renewal/issuer", "subject cannot renew its own grant")
        if renewer and issuer_uri and renewer.get("uri") != issuer_uri:
            add_finding(findings, RENEWAL, "/renewal/issuer", "renewal issuer must match issuer")
        max_renewals = renewal.get("maxRenewals")
        if not is_strict_int(max_renewals) or max_renewals < 0:
            add_finding(findings, RENEWAL, "/renewal/maxRenewals", "must be a non-negative integer")

    lease_start, lease_end = validate_lease(grant, subject_uri, not_before, expires_at, findings)
    validate_delegation(grant, subject_uri, findings)
    _validate_history(grant.get("history"), grant_state, issuer_uri, findings)
    if at is not None:
        if grant_state != "active":
            add_finding(findings, STATE, "/state", "runtime evaluation requires an active grant")
        if (not_before and at < not_before) or (expires_at and at >= expires_at):
            add_finding(findings, TIME, "/validity", "grant is not current at evaluation time")
        if (lease_start and at < lease_start) or (lease_end and at >= lease_end):
            add_finding(findings, TIME, "/lease", "lease is not current at evaluation time")
    scan_secrets(grant, "", findings)
    return findings


def _validate_profile(document: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    required = {"schema", "profileId", "version", "ownership", "bindings"}
    profile = closed_object(document, "", required, required, findings)
    if profile is None:
        return findings
    if not valid_hierarchical_id(profile.get("profileId"), PROFILE_URI):
        add_finding(findings, SYNTAX, "/profileId", "invalid profile URI")
    version = profile.get("version")
    if not isinstance(version, str) or SEMVER.fullmatch(version) is None:
        add_finding(findings, SYNTAX, "/version", "must be a semantic version X.Y.Z")
    own_fields = {"standardOwner", "runtimeOwner", "adopts"}
    ownership = closed_object(
        profile.get("ownership"), "/ownership", own_fields, own_fields, findings
    )
    if ownership:
        if ownership.get("standardOwner") != "wellmanifest/authority-lifecycle":
            add_finding(findings, PROFILE, "/ownership/standardOwner", "wrong standard owner")
        if not valid_hierarchical_id(ownership.get("runtimeOwner"), RUNTIME_OWNER):
            add_finding(findings, PROFILE, "/ownership/runtimeOwner", "invalid runtime owner")
        adopts = ownership.get("adopts")
        if (
            not isinstance(adopts, list)
            or not adopts
            or not all(valid_hierarchical_id(x, ADOPTED_STANDARD) for x in adopts)
        ):
            add_finding(findings, PROFILE, "/ownership/adopts", "must list wellmanifest/*")
        else:
            if len(adopts) != len(set(adopts)):
                add_finding(findings, PROFILE, "/ownership/adopts", "duplicate standards forbidden")
            if "wellmanifest/autonomy" not in adopts:
                add_finding(findings, PROFILE, "/ownership/adopts", "autonomy adoption is required")
    bindings = profile.get("bindings")
    if not isinstance(bindings, list):
        add_finding(findings, SYNTAX, "/bindings", "must be an array")
        return findings
    if len(bindings) != len(PROFILE_MODES):
        add_finding(findings, PROFILE, "/bindings", "must declare exactly 6 stage bindings")
    observed: dict[str, str] = {}
    principals: dict[str, dict[str, Any]] = {}
    binding_fields = {"stage", "uri", "principal", "mode"}
    for index, value in enumerate(bindings):
        path = f"/bindings/{index}"
        binding = closed_object(value, path, binding_fields, binding_fields, findings)
        if binding is None:
            continue
        if not valid_hierarchical_id(binding.get("uri"), PROCESS_URI):
            add_finding(findings, SYNTAX, f"{path}/uri", "invalid process URI")
        stage, mode = binding.get("stage"), binding.get("mode")
        if not isinstance(stage, str):
            add_finding(findings, SYNTAX, f"{path}/stage", "stage must be a string")
        elif stage in observed:
            add_finding(findings, PROFILE, f"{path}/stage", "duplicate stage")
        if not isinstance(mode, str):
            add_finding(findings, SYNTAX, f"{path}/mode", "mode must be a string")
        if isinstance(stage, str):
            if isinstance(mode, str) and stage not in observed:
                observed[stage] = mode
            principal = validate_principal(binding.get("principal"), f"{path}/principal", findings)
            if principal:
                principals[stage] = principal
    if observed != PROFILE_MODES:
        add_finding(findings, PROFILE, "/bindings", "exact stage and mode mapping is required")
    for stage in ("issue", "lease", "revoke"):
        if principals.get(stage, {}).get("kind") != "protected-authority":
            add_finding(findings, PROFILE, f"/bindings/{stage}", "protected authority required")
    exec_uri = principals.get("execute", {}).get("uri")
    if isinstance(exec_uri, str) and exec_uri in {
        principals.get("issue", {}).get("uri"),
        principals.get("revoke", {}).get("uri"),
    }:
        add_finding(findings, PROFILE, "/bindings", "executor cannot issue or revoke grants")
    scan_secrets(profile, "", findings)
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


def apply_invalid_case(
    case: dict[str, Any], case_path: Path
) -> tuple[Any, datetime | None, list[Finding]]:
    allowed = {"schema", "base", "mutations", "expectedCodes", "evaluationTime"}
    findings: list[Finding] = []
    if any(not isinstance(k, str) or k not in allowed for k in case):
        add_finding(findings, SYNTAX, "", "unknown invalid-case fields")
    expected_codes = case.get("expectedCodes")
    if (
        not isinstance(expected_codes, list)
        or not expected_codes
        or not all(isinstance(code, str) and code for code in expected_codes)
    ):
        add_finding(findings, SYNTAX, "/expectedCodes", "must be a non-empty string array")
    try:
        base = resolve_within_examples(case["base"], case_path, EXAMPLES)
    except (KeyError, OSError, ValueError):
        return {}, None, [Finding(SYNTAX, "/base", "base escapes examples root")]
    try:
        document = copy.deepcopy(load_strict_json(base))
        mutations = case.get("mutations", [])
        if not isinstance(mutations, list):
            raise ValueError("mutations must be a list")
        for mutation in mutations:
            if not isinstance(mutation, dict) or any(not isinstance(k, str) for k in mutation):
                raise ValueError("mutation must be an object with string keys")
            op = mutation.get("op")
            parent, key = pointer_parent(document, mutation["path"])
            if op == "replace" and set(mutation) == {"op", "path", "value"}:
                if isinstance(parent, list):
                    parent[parse_array_index(key, len(parent))] = mutation["value"]
                else:
                    parent[key] = mutation["value"]
            elif op == "remove" and set(mutation) == {"op", "path"}:
                if isinstance(parent, list):
                    parent.pop(parse_array_index(key, len(parent)))
                else:
                    del parent[key]
            else:
                raise ValueError("unsupported or malformed mutation")
    except (
        OSError, UnicodeDecodeError, KeyError, IndexError, TypeError,
        ValueError, DuplicateKeyError, json.JSONDecodeError,
    ) as error:
        return {}, None, [Finding(SYNTAX, "/mutations", f"invalid case: {error}")]
    at = None
    if "evaluationTime" in case:
        at = parse_rfc3339(case["evaluationTime"], "/evaluationTime", findings)
    return document, at, findings


def load_and_validate(path: Path, at: datetime | None = None) -> list[Finding]:
    try:
        document = load_strict_json(path)
    except (
        OSError,
        UnicodeDecodeError,
        ValueError,
        DuplicateKeyError,
        json.JSONDecodeError,
    ) as error:
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
            failures.append(f"{path.name}: expected valid, got {[x.code for x in findings]}")
    profile_findings = load_and_validate(ROOT / "profiles" / "subactor-semcod.profile.json")
    if profile_findings:
        failures.append(f"profile: expected valid, got {[x.code for x in profile_findings]}")
    for path in sorted((EXAMPLES / "invalid").glob("*.json")):
        case = load_strict_json(path)
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
        at = parse_rfc3339(args.at, "--at", temp)
        if temp:
            print(temp[0].render(), file=sys.stderr)
            return 2
    try:
        paths = iter_json_paths(args.path)
    except (OSError, ValueError) as error:
        print(f"{args.path}: {Finding(SYNTAX, '', str(error)).render()}", file=sys.stderr)
        return 1
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
