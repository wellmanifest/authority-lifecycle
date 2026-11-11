"""Core diagnostic codes, URI/timestamp patterns, and strict JSON primitives for authority v1."""

from __future__ import annotations

import errno
import json
import math
import os
import re
import stat
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

MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_JSON_DEPTH = 64

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
ARRAY_INDEX = re.compile(r"^(?:0|[1-9][0-9]*)$")
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


def _reject_json_constant(token: str) -> Any:
    raise ValueError(f"non-finite JSON constant {token!r} is forbidden")


def _parse_finite_float(token: str) -> float:
    parsed = float(token)
    if not math.isfinite(parsed):
        raise ValueError(f"non-finite JSON float {token!r} is forbidden")
    return parsed


def _enforce_json_depth(value: Any, max_depth: int = MAX_JSON_DEPTH) -> None:
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        if depth > max_depth:
            raise ValueError("JSON nesting depth exceeds maximum bound")
        if isinstance(current, dict):
            for key, child in current.items():
                if not isinstance(key, str):
                    raise ValueError("JSON object keys must be strings")
                stack.append((child, depth + 1))
        elif isinstance(current, list):
            for child in current:
                stack.append((child, depth + 1))
        elif isinstance(current, float) and not math.isfinite(current):
            raise ValueError("non-finite JSON float is forbidden")


def read_regular_file_bytes(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise OSError(errno.EINVAL, "not a regular file", str(path))
        if st.st_size > MAX_FILE_BYTES:
            raise OSError(errno.EFBIG, "file exceeds maximum byte bound", str(path))
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_FILE_BYTES:
                raise OSError(errno.EFBIG, "file exceeds maximum byte bound", str(path))
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def loads_strict_json(raw: str) -> Any:
    if len(raw.encode("utf-8", errors="strict")) > MAX_FILE_BYTES:
        raise ValueError("JSON payload exceeds maximum byte bound")
    try:
        parsed = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
            parse_float=_parse_finite_float,
        )
    except RecursionError as exc:
        raise ValueError("JSON nesting depth exceeds maximum bound") from exc
    _enforce_json_depth(parsed)
    return parsed


def load_strict_json(path: Path) -> Any:
    raw = read_regular_file_bytes(path).decode("utf-8", errors="strict")
    return loads_strict_json(raw)


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
    non_str = [key for key in value if not isinstance(key, str)]
    if non_str:
        add_finding(findings, SYNTAX, path, "non-string object keys forbidden")
    str_keys = {key for key in value if isinstance(key, str)}
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
    denied = ("token", "secret", "password", "credential", "privatekey", "apikey")
    stack: list[tuple[Any, str]] = [(value, path)]
    while stack:
        current, cur_path = stack.pop()
        if isinstance(current, dict):
            for key, nested in reversed(list(current.items())):
                normalized = re.sub(r"[^a-z]", "", str(key).lower())
                if any(part in normalized for part in denied):
                    add_finding(
                        findings, SECRET, f"{cur_path}/{key}", "secret-bearing field is forbidden"
                    )
                stack.append((nested, f"{cur_path}/{key}"))
        elif isinstance(current, list):
            for index in range(len(current) - 1, -1, -1):
                stack.append((current[index], f"{cur_path}/{index}"))
        elif isinstance(current, str) and re.search(r"(?i)\bbearer\s+[a-z0-9._-]+", current):
            add_finding(findings, SECRET, cur_path, "credential-like value is forbidden")


def parse_array_index(token: str, length: int) -> int:
    if not isinstance(token, str) or ARRAY_INDEX.fullmatch(token) is None:
        raise ValueError(f"invalid RFC 6901 array index {token!r}")
    index = int(token)
    if index >= length:
        raise IndexError(f"array index {index} out of range")
    return index


def pointer_parent(document: Any, pointer: str) -> tuple[Any, str]:
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        raise ValueError("mutation path must be an absolute JSON Pointer")
    parts = [part.replace("~1", "/").replace("~0", "~") for part in pointer[1:].split("/")]
    current = document
    for part in parts[:-1]:
        if isinstance(current, list):
            current = current[parse_array_index(part, len(current))]
        elif isinstance(current, dict):
            current = current[part]
        else:
            raise TypeError("cannot traverse scalar value")
    if not isinstance(current, (dict, list)):
        raise TypeError("mutation parent must be a container")
    return current, parts[-1]


def resolve_within_examples(base_raw: Any, case_path: Path, examples_root: Path) -> Path:
    if not isinstance(base_raw, str) or not base_raw or "\x00" in base_raw or "\\" in base_raw:
        raise ValueError("base must be a non-empty relative path")
    candidate = case_path.parent / base_raw
    probe = candidate
    while True:
        if probe.is_symlink():
            raise ValueError("symlink base path forbidden")
        if probe == examples_root or probe.parent == probe:
            break
        probe = probe.parent
    resolved = candidate.resolve(strict=True)
    resolved.relative_to(examples_root)
    return resolved


def iter_json_paths(target: Path) -> list[Path]:
    if target.is_symlink():
        raise OSError(errno.ELOOP, "symlink target is forbidden", str(target))
    if not target.is_dir():
        return [target]
    collected: list[Path] = []
    for root, dirs, files in os.walk(target, followlinks=False):
        root_path = Path(root)
        dirs.sort()
        for dirname in dirs:
            if (root_path / dirname).is_symlink():
                raise OSError(
                    errno.ELOOP, "symlink directory is forbidden", str(root_path / dirname)
                )
        for filename in sorted(files):
            if filename.endswith(".json"):
                candidate = root_path / filename
                if candidate.is_symlink():
                    raise OSError(errno.ELOOP, "symlink file is forbidden", str(candidate))
                collected.append(candidate)
    if not collected:
        raise ValueError(f"directory contains no JSON documents: {target}")
    return sorted(collected)


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
