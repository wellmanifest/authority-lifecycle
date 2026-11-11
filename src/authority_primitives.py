"""Core diagnostic codes, URI/timestamp patterns, and shared validators for authority v1."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from authority_io import (
    ARRAY_INDEX,
    DENIED_SECRET_KEYS,
    MAX_FILE_BYTES,
    MAX_JSON_DEPTH,
    SECRET_MATERIAL,
    DuplicateKeyError,
    _enforce_json_depth,
    _has_control_chars,
    _has_surrogate,
    iter_json_paths,
    load_strict_json,
    loads_strict_json,
    parse_array_index,
    pointer_parent,
    read_regular_file_bytes,
    resolve_within_examples,
)

__all__ = [
    "ADOPTED_STANDARD",
    "ARRAY_INDEX",
    "CAPABILITY_URI",
    "DELEGATION",
    "DIGEST",
    "EFFECT_NAME",
    "GRANT_URI",
    "IDENTITY",
    "LEASE",
    "LEASE_URI",
    "MANDATORY_DENIED",
    "MAX_FILE_BYTES",
    "MAX_JSON_DEPTH",
    "PRINCIPAL_URI",
    "PROCESS_URI",
    "PROFILE",
    "PROFILE_MODES",
    "PROFILE_URI",
    "RECEIPT",
    "RECEIPT_URI",
    "RENEWAL",
    "RESOURCE_URI",
    "RFC3339",
    "RUNTIME_OWNER",
    "SCOPE",
    "SECRET",
    "SECRET_MATERIAL",
    "SEMVER",
    "STATE",
    "SYNTAX",
    "TIME",
    "TRANSITIONS",
    "DuplicateKeyError",
    "Finding",
    "_enforce_json_depth",
    "_has_control_chars",
    "_has_surrogate",
    "add_finding",
    "closed_object",
    "is_strict_int",
    "iter_json_paths",
    "load_strict_json",
    "loads_strict_json",
    "parse_array_index",
    "parse_rfc3339",
    "pointer_parent",
    "principal_uri",
    "read_regular_file_bytes",
    "resolve_within_examples",
    "scan_secrets",
    "valid_hierarchical_id",
    "valid_resource_uri",
    "validate_delegation",
    "validate_history",
    "validate_lease",
    "validate_principal",
    "validate_receipt",
]

SYNTAX = "AUTH-SYNTAX-001"
IDENTITY = "AUTH-IDENTITY-001"
SCOPE = "AUTH-SCOPE-001"
TIME = "AUTH-TIME-001"
RENEWAL = "AUTH-RENEWAL-001"
STATE = "AUTH-STATE-001"
RECEIPT = "AUTH-RECEIPT-001"
SECRET = "AUTH-SECRET-001"
PROFILE = "AUTH-PROFILE-001"
LEASE = "AUTH-LEASE-001"
DELEGATION = "AUTH-DELEGATION-001"

DIGEST = re.compile(r"\Asha256:[a-f0-9]{64}\Z")
PRINCIPAL_URI = re.compile(r"\Aauthority://principal/[a-z0-9][a-z0-9._/-]*\Z")
GRANT_URI = re.compile(r"\Aauthority://grant/[a-z0-9][a-z0-9._/-]*\Z")
RECEIPT_URI = re.compile(r"\Aauthority://receipt/[a-z0-9][a-z0-9._/-]*\Z")
LEASE_URI = re.compile(r"\Aauthority://lease/[a-z0-9][a-z0-9._/-]*\Z")
PROFILE_URI = re.compile(r"\Aauthority://profile/[a-z0-9][a-z0-9._/-]*\Z")
CAPABILITY_URI = re.compile(r"\Asubactor://capability/[a-z0-9][a-z0-9._/-]*\Z")
PROCESS_URI = re.compile(r"\Asubactor://process/[a-z0-9][a-z0-9._/-]*\Z")
RESOURCE_URI = re.compile(r"\A[a-z][a-z0-9+.-]*://[^\s\x00-\x1f\x7f\\?#]+\Z")
EFFECT_NAME = re.compile(r"\A[a-z][a-z0-9.-]+\Z")
SEMVER = re.compile(r"\A[0-9]+\.[0-9]+\.[0-9]+\Z")
RUNTIME_OWNER = re.compile(r"\A(?:subactor|semcod)/[a-z0-9][a-z0-9._/-]*\Z")
ADOPTED_STANDARD = re.compile(r"\Awellmanifest/[a-z0-9][a-z0-9._/-]*\Z")
RFC3339 = re.compile(
    r"\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,9})?(?:Z|[+-][0-9]{2}:[0-9]{2})\Z"
)
_SUBSEC_TRIM = re.compile(r"\.([0-9]{6})[0-9]+")

MANDATORY_DENIED = {
    "grant.issue",
    "grant.renew",
    "grant.expand",
    "grant.revoke",
    "policy.modify",
    "validator.attest",
    "git.main.write",
}
TRANSITIONS: dict[str, set[str]] = {
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


def add_finding(findings: list[Finding], code: str, path: str, message: str) -> None:
    findings.append(Finding(code, path, message))


def is_strict_int(value: Any) -> bool:
    return type(value) is int


def valid_hierarchical_id(
    value: Any, pattern: re.Pattern[str], slash_prefix_parts: int = 1
) -> bool:
    if not isinstance(value, str) or _has_surrogate(value) or pattern.fullmatch(value) is None:
        return False
    tail = value.split("://", 1)[1] if "://" in value else value
    segments = tail.split("/")
    if len(segments) <= slash_prefix_parts:
        return False
    for seg in segments:
        if seg in {"", ".", ".."}:
            return False
        if ":" in seg and any(sub in {"", ".", ".."} for sub in seg.split(":")):
            return False
    return True


def valid_resource_uri(value: Any) -> bool:
    if not isinstance(value, str) or _has_surrogate(value) or RESOURCE_URI.fullmatch(value) is None:
        return False
    _, sep, tail = value.partition("://")
    if not sep or not tail or tail.startswith("/") or tail.endswith("/"):
        return False
    for seg in tail.split("/"):
        if seg in {"", ".", ".."}:
            return False
        if ":" in seg and any(sub in {"", ".", ".."} for sub in seg.split(":")):
            return False
    return True


def parse_rfc3339(value: Any, path: str, findings: list[Finding]) -> datetime | None:
    if not isinstance(value, str) or RFC3339.fullmatch(value) is None:
        add_finding(findings, SYNTAX, path, "must be an RFC3339 timestamp")
        return None
    normalized = _SUBSEC_TRIM.sub(r".\1", value).replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        add_finding(findings, SYNTAX, path, "must be an RFC3339 timestamp")
        return None
    if parsed.tzinfo is None:
        add_finding(findings, SYNTAX, path, "must include a timezone")
        return None
    return parsed


def closed_object(
    value: Any,
    path: str,
    required: set[str],
    allowed: set[str],
    findings: list[Finding],
) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        add_finding(findings, SYNTAX, path, "must be an object")
        return None
    non_str = [key for key in value if not isinstance(key, str)]
    if non_str:
        add_finding(findings, SYNTAX, path, "non-string object keys forbidden")
    str_keys = {key for key in value if isinstance(key, str)}
    if any(_has_surrogate(key) for key in str_keys):
        add_finding(findings, SYNTAX, path, "lone UTF-16 surrogate in object key forbidden")
    missing = sorted(required - str_keys)
    unknown = sorted(str_keys - allowed)
    if missing:
        add_finding(findings, SYNTAX, path, f"missing fields: {', '.join(missing)}")
    if unknown:
        add_finding(findings, SYNTAX, path, f"unknown fields: {', '.join(unknown)}")
    return value


def validate_principal(value: Any, path: str, findings: list[Finding]) -> dict[str, Any] | None:
    principal = closed_object(value, path, {"uri", "kind"}, {"uri", "kind"}, findings)
    if principal is None:
        return None
    if not valid_hierarchical_id(principal.get("uri"), PRINCIPAL_URI):
        add_finding(findings, SYNTAX, f"{path}/uri", "invalid authority principal URI")
    kind = principal.get("kind")
    valid_kinds = {"protected-authority", "agent", "service", "human"}
    if not isinstance(kind, str) or kind not in valid_kinds:
        add_finding(findings, SYNTAX, f"{path}/kind", "unknown principal kind")
    return principal


def validate_receipt(value: Any, path: str, findings: list[Finding]) -> dict[str, Any] | None:
    fields = {"receiptId", "actor", "at", "subjectDigest"}
    receipt = closed_object(value, path, fields, fields, findings)
    if receipt is None:
        return None
    if not valid_hierarchical_id(receipt.get("receiptId"), RECEIPT_URI):
        add_finding(findings, RECEIPT, f"{path}/receiptId", "invalid receipt URI")
    validate_principal(receipt.get("actor"), f"{path}/actor", findings)
    parse_rfc3339(receipt.get("at"), f"{path}/at", findings)
    digest = receipt.get("subjectDigest")
    if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
        add_finding(findings, RECEIPT, f"{path}/subjectDigest", "exact SHA-256 binding required")
    return receipt


def scan_secrets(value: Any, path: str, findings: list[Finding]) -> None:
    stack: list[tuple[Any, str]] = [(value, path)]
    while stack:
        current, cur_path = stack.pop()
        if isinstance(current, dict):
            for key, nested in reversed(list(current.items())):
                key_str = str(key)
                normalized = re.sub(r"[^a-z]", "", key_str.lower())
                if any(part in normalized for part in DENIED_SECRET_KEYS) or (
                    isinstance(key, str) and not _has_surrogate(key) and SECRET_MATERIAL.search(key)
                ):
                    add_finding(
                        findings, SECRET, f"{cur_path}/{key}", "secret-bearing field is forbidden"
                    )
                stack.append((nested, f"{cur_path}/{key}"))
        elif isinstance(current, list):
            for index in range(len(current) - 1, -1, -1):
                stack.append((current[index], f"{cur_path}/{index}"))
        elif isinstance(current, str):
            if _has_surrogate(current):
                add_finding(findings, SYNTAX, cur_path, "lone UTF-16 surrogate is forbidden")
            elif SECRET_MATERIAL.search(current):
                add_finding(findings, SECRET, cur_path, "credential-like value is forbidden")


def validate_delegation(
    grant: dict[str, Any], subject_uri: str | None, findings: list[Finding]
) -> None:
    if "delegation" not in grant:
        return
    fields = {
        "mode",
        "parentGrantId",
        "parentGrantDigest",
        "delegator",
        "depth",
        "maxDepth",
        "scopePolicy",
        "budgetPolicy",
        "validityPolicy",
    }
    delegation = closed_object(grant.get("delegation"), "/delegation", fields, fields, findings)
    if delegation is None:
        return
    parent_id = delegation.get("parentGrantId")
    if not valid_hierarchical_id(parent_id, GRANT_URI):
        add_finding(findings, DELEGATION, "/delegation/parentGrantId", "invalid parent grant URI")
    elif parent_id == grant.get("grantId"):
        add_finding(findings, DELEGATION, "/delegation/parentGrantId", "grant cannot parent itself")
    parent_digest = delegation.get("parentGrantDigest")
    if not isinstance(parent_digest, str) or not DIGEST.fullmatch(parent_digest):
        add_finding(
            findings, DELEGATION, "/delegation/parentGrantDigest", "exact parent digest required"
        )
    delegator = validate_principal(delegation.get("delegator"), "/delegation/delegator", findings)
    if delegator and isinstance(subject_uri, str) and delegator.get("uri") == subject_uri:
        add_finding(
            findings, IDENTITY, "/delegation/delegator", "delegator and child subject must differ"
        )
    expected = {
        "mode": "protected-narrow-only",
        "scopePolicy": "subset-only",
        "budgetPolicy": "no-increase",
        "validityPolicy": "not-after-parent",
    }
    for field, value in expected.items():
        if delegation.get(field) != value:
            add_finding(findings, DELEGATION, f"/delegation/{field}", f"must equal {value!r}")
    depth, max_depth = delegation.get("depth"), delegation.get("maxDepth")
    if not is_strict_int(depth) or not is_strict_int(max_depth):
        add_finding(findings, DELEGATION, "/delegation", "depth and maxDepth must be integers")
    elif not 1 <= depth <= max_depth <= 16:
        add_finding(findings, DELEGATION, "/delegation", "delegation depth exceeds bounded chain")


def validate_lease(
    grant: dict[str, Any],
    subject_uri: str | None,
    not_before: datetime | None,
    expires_at: datetime | None,
    findings: list[Finding],
) -> tuple[datetime | None, datetime | None]:
    lease_value = grant.get("lease")
    lease_required = isinstance(lease_value, dict) and lease_value.get("required") is True
    lease_fields = {"required", "leaseId", "owner", "epoch", "acquiredAt", "expiresAt"}
    allowed = lease_fields if lease_required else {"required"}
    lease = closed_object(lease_value, "/lease", allowed, allowed, findings)
    if lease is None:
        return None, None
    if not isinstance(lease.get("required"), bool):
        add_finding(findings, LEASE, "/lease/required", "must explicitly select true or false")
    if not lease_required:
        return None, None
    if not valid_hierarchical_id(lease.get("leaseId"), LEASE_URI):
        add_finding(findings, LEASE, "/lease/leaseId", "invalid lease URI")
    owner = validate_principal(lease.get("owner"), "/lease/owner", findings)
    if owner and owner.get("uri") != subject_uri:
        add_finding(findings, IDENTITY, "/lease/owner", "lease owner must equal grant subject")
    epoch = lease.get("epoch")
    if not is_strict_int(epoch) or epoch < 1:
        add_finding(findings, LEASE, "/lease/epoch", "must be a positive fencing epoch")
    lease_start = parse_rfc3339(lease.get("acquiredAt"), "/lease/acquiredAt", findings)
    lease_end = parse_rfc3339(lease.get("expiresAt"), "/lease/expiresAt", findings)
    if lease_start and lease_end and lease_start >= lease_end:
        add_finding(findings, LEASE, "/lease", "lease acquisition must precede expiry")
    if not_before and lease_start and lease_start < not_before:
        add_finding(findings, LEASE, "/lease/acquiredAt", "lease starts before the grant")
    if expires_at and lease_end and lease_end > expires_at:
        add_finding(findings, LEASE, "/lease/expiresAt", "lease outlives the grant")
    return lease_start, lease_end


def principal_uri(principal: dict[str, Any] | None) -> str | None:
    if isinstance(principal, dict) and isinstance(principal.get("uri"), str):
        return principal["uri"]
    return None


def validate_history(
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
        if (
            not isinstance(reason, str)
            or _has_surrogate(reason)
            or _has_control_chars(reason, allow_newlines=False)
            or len(reason.strip()) < 3
            or len(reason) > 240
        ):
            add_finding(findings, SYNTAX, f"{path}/reason", "reason must be 3..240 non-blank chars")
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
