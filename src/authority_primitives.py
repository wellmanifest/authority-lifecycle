"""Core diagnostic codes, URI/timestamp patterns, and strict JSON primitives for authority v1."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

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

DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
PRINCIPAL_URI = re.compile(r"^authority://principal/[a-z0-9][a-z0-9._/-]*$")
GRANT_URI = re.compile(r"^authority://grant/[a-z0-9][a-z0-9._/-]*$")
RECEIPT_URI = re.compile(r"^authority://receipt/[a-z0-9][a-z0-9._/-]*$")
LEASE_URI = re.compile(r"^authority://lease/[a-z0-9][a-z0-9._/-]*$")
PROFILE_URI = re.compile(r"^authority://profile/[a-z0-9][a-z0-9._/-]*$")
CAPABILITY_URI = re.compile(r"^subactor://capability/[a-z0-9][a-z0-9._/-]*$")
PROCESS_URI = re.compile(r"^subactor://process/[a-z0-9][a-z0-9._/-]*$")
RESOURCE_URI = re.compile(r"^[a-z][a-z0-9+.-]*://[^\s\x00-\x1f\x7f]+$")
EFFECT_NAME = re.compile(r"^[a-z][a-z0-9.-]+$")
SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
RUNTIME_OWNER = re.compile(r"^(?:subactor|semcod)/[a-z0-9][a-z0-9._/-]*$")
ADOPTED_STANDARD = re.compile(r"^wellmanifest/[a-z0-9][a-z0-9._/-]*$")
RFC3339 = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,9})?(?:Z|[+-][0-9]{2}:[0-9]{2})$"
)

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


class DuplicateKeyError(ValueError):
    """Raised when a JSON object contains duplicate member names."""


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
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        return False
    tail = value.split("://", 1)[1] if "://" in value else value
    segments = tail.split("/")
    if len(segments) <= slash_prefix_parts:
        return False
    return all(seg not in {"", ".", ".."} for seg in segments)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, val in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate JSON object key {key!r}")
        result[key] = val
    return result


def loads_strict_json(raw: str) -> Any:
    return json.loads(raw, object_pairs_hook=_reject_duplicate_keys)


def load_strict_json(path: Path) -> Any:
    return loads_strict_json(path.read_text(encoding="utf-8"))


def parse_rfc3339(value: Any, path: str, findings: list[Finding]) -> datetime | None:
    if not isinstance(value, str) or RFC3339.fullmatch(value) is None:
        add_finding(findings, SYNTAX, path, "must be an RFC3339 timestamp")
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
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
    missing = sorted(required - set(value))
    unknown = sorted(set(value) - allowed)
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
    if principal.get("kind") not in {"protected-authority", "agent", "service", "human"}:
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
    denied = ("token", "secret", "password", "credential", "privatekey", "apikey")
    if isinstance(value, dict):
        for key, nested in value.items():
            normalized = re.sub(r"[^a-z]", "", str(key).lower())
            if any(part in normalized for part in denied):
                add_finding(findings, SECRET, f"{path}/{key}", "secret-bearing field is forbidden")
            scan_secrets(nested, f"{path}/{key}", findings)
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            scan_secrets(nested, f"{path}/{index}", findings)
    elif isinstance(value, str) and re.search(r"(?i)\bbearer\s+[a-z0-9._-]+", value):
        add_finding(findings, SECRET, path, "credential-like value is forbidden")


def pointer_parent(document: Any, pointer: str) -> tuple[Any, str]:
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        raise ValueError("mutation path must be an absolute JSON Pointer")
    parts = [part.replace("~1", "/").replace("~0", "~") for part in pointer[1:].split("/")]
    current = document
    for part in parts[:-1]:
        current = current[int(part)] if isinstance(current, list) else current[part]
    return current, parts[-1]


def validate_delegation(
    grant: dict[str, Any], subject_uri: str | None, findings: list[Finding]
) -> None:
    if "delegation" not in grant:
        return
    fields = {
        "mode", "parentGrantId", "parentGrantDigest", "delegator", "depth",
        "maxDepth", "scopePolicy", "budgetPolicy", "validityPolicy",
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
    if delegator and delegator.get("uri") == subject_uri:
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

