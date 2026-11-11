"""Bounded regular-file I/O, strict JSON loading, symlink guards, and secret scanning."""

from __future__ import annotations

import errno
import json
import math
import os
import re
import stat
from pathlib import Path
from typing import Any

MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_JSON_DEPTH = 64
ARRAY_INDEX = re.compile(r"\A(?:0|[1-9][0-9]*)\Z")

SECRET_MATERIAL = re.compile(
    r"(?i)\bbearer\s+[a-z0-9._~+/=-]{8,}|"
    r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b|"
    r"\bgithub_pat_[A-Za-z0-9_]{20,}\b|"
    r"\bsk-[A-Za-z0-9_-]{16,}\b|"
    r"\bAK"
    r"IA[0-9A-Z]{16}\b|"
    r"-----BEGIN [A-Z0-9 ]*PRI"
    r"VATE KEY-----"
)
DENIED_SECRET_KEYS = ("token", "secret", "password", "credential", "privatekey", "apikey")

__all__ = [
    "ARRAY_INDEX",
    "DENIED_SECRET_KEYS",
    "DuplicateKeyError",
    "MAX_FILE_BYTES",
    "MAX_JSON_DEPTH",
    "SECRET_MATERIAL",
    "_check_no_symlink_ancestors",
    "_enforce_json_depth",
    "_has_control_chars",
    "_has_surrogate",
    "iter_json_paths",
    "load_strict_json",
    "loads_strict_json",
    "parse_array_index",
    "pointer_parent",
    "read_regular_file_bytes",
    "resolve_within_examples",
]


class DuplicateKeyError(ValueError):
    """Raised when a JSON object contains duplicate member names."""


def _has_surrogate(value: str) -> bool:
    return any(0xD800 <= ord(ch) <= 0xDFFF for ch in value)


def _has_control_chars(value: str, *, allow_newlines: bool = False) -> bool:
    for ch in value:
        code = ord(ch)
        if code == 0x7F:
            return True
        if code < 0x20:
            if allow_newlines and ch in {"\n", "\t"}:
                continue
            return True
    return False


def _check_utf8_str(value: str) -> None:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("lone UTF-16 surrogate in JSON string is forbidden") from exc


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


def _parse_finite_int(token: str) -> int:
    digits = token[1:] if token.startswith("-") else token
    if len(digits) > 309:
        raise ValueError("JSON integer magnitude exceeds finite range")
    parsed = int(token)
    try:
        ok = math.isfinite(float(parsed))
    except OverflowError:
        ok = False
    if not ok:
        raise ValueError("JSON integer magnitude exceeds finite range")
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
                _check_utf8_str(key)
                stack.append((child, depth + 1))
        elif isinstance(current, list):
            for child in current:
                stack.append((child, depth + 1))
        elif isinstance(current, str):
            _check_utf8_str(current)
        elif type(current) is int:
            try:
                ok = math.isfinite(float(current))
            except OverflowError:
                ok = False
            if not ok:
                raise ValueError("JSON integer magnitude exceeds finite range")
        elif isinstance(current, float) and not math.isfinite(current):
            raise ValueError("non-finite JSON float is forbidden")


def _check_no_symlink_ancestors(path: Path, *, include_self: bool = False) -> None:
    if include_self and path.is_symlink():
        raise OSError(errno.ELOOP, "symlink target is forbidden", str(path))
    parts = path.parts if include_self else path.parts[:-1]
    if not path.is_absolute():
        cur = Path()
        for part in parts:
            cur = cur / part
            if cur.is_symlink():
                msg = (
                    "symlink target is forbidden"
                    if cur == path
                    else "symlink ancestor is forbidden"
                )
                raise OSError(errno.ELOOP, msg, str(cur))
        cwd = Path.cwd()
        for anc in (cwd, *cwd.parents):
            if len(anc.parts) <= 2:
                break
            if anc.is_symlink():
                raise OSError(errno.ELOOP, "symlink ancestor is forbidden", str(anc))
        return
    if not parts:
        return
    cur = Path(parts[0])
    for idx, part in enumerate(parts[1:], start=2):
        cur = cur / part
        if idx <= 2 and not (include_self and idx == len(parts)):
            continue
        if cur.is_symlink():
            raise OSError(errno.ELOOP, "symlink ancestor is forbidden", str(cur))


def read_regular_file_bytes(path: Path, max_bytes: int = MAX_FILE_BYTES) -> bytes:
    if type(max_bytes) is not int or max_bytes < 1:
        raise ValueError("max_bytes must be a positive integer")
    _check_no_symlink_ancestors(path, include_self=False)
    lst = os.lstat(path)
    if stat.S_ISLNK(lst.st_mode):
        raise OSError(errno.ELOOP, "symlink file is forbidden", str(path))
    if not stat.S_ISREG(lst.st_mode):
        raise OSError(errno.EINVAL, "not a regular file", str(path))
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise OSError(errno.EINVAL, "not a regular file", str(path))
        if (st.st_dev, st.st_ino) != (lst.st_dev, lst.st_ino):
            raise OSError(errno.ELOOP, "file inode changed during open", str(path))
        if st.st_size > max_bytes:
            raise OSError(errno.EFBIG, "file exceeds maximum byte bound", str(path))
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(65536, max_bytes + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise OSError(errno.EFBIG, "file exceeds maximum byte bound", str(path))
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def loads_strict_json(raw: str) -> Any:
    if not isinstance(raw, str):
        raise ValueError("JSON payload must be a string")
    _check_utf8_str(raw)
    if len(raw.encode("utf-8", errors="strict")) > MAX_FILE_BYTES:
        raise ValueError("JSON payload exceeds maximum byte bound")
    try:
        parsed = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
            parse_float=_parse_finite_float,
            parse_int=_parse_finite_int,
        )
    except RecursionError as exc:
        raise ValueError("JSON nesting depth exceeds maximum bound") from exc
    _enforce_json_depth(parsed)
    return parsed


def load_strict_json(path: Path) -> Any:
    raw = read_regular_file_bytes(path).decode("utf-8", errors="strict")
    return loads_strict_json(raw)


def parse_array_index(token: str, length: int) -> int:
    if not isinstance(token, str) or ARRAY_INDEX.fullmatch(token) is None:
        raise ValueError(f"invalid RFC 6901 array index {token!r}")
    if length <= 0 or len(token) > len(str(length)):
        raise IndexError(f"array index {token!r} out of range")
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
    if (
        not isinstance(base_raw, str)
        or not base_raw.strip()
        or _has_surrogate(base_raw)
        or _has_control_chars(base_raw, allow_newlines=False)
        or "\\" in base_raw
        or Path(base_raw).is_absolute()
    ):
        raise ValueError("base must be a non-empty relative path")
    candidate = case_path.parent / base_raw
    try:
        _check_no_symlink_ancestors(candidate, include_self=True)
    except OSError as exc:
        raise ValueError("symlink base path forbidden") from exc
    resolved = candidate.resolve(strict=True)
    resolved.relative_to(examples_root)
    return resolved


def iter_json_paths(target: Path) -> list[Path]:
    _check_no_symlink_ancestors(target, include_self=True)
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
