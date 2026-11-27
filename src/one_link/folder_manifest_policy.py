"""Folder-sync manifest wire contract: canonical paths, bounds and admission.

Everything here is a pure function of its inputs (plus a read-only local
manifest view for the two pre-merge checks). It owns the rules a peer's
``MANIFEST_PUSH`` must satisfy before any CRDT merge, pending-offer
persistence or blob admission happens:

* protocol-canonical relative paths (no traversal, drive/UNC/device names,
  control characters, trailing dots/spaces or Windows-reserved leaves);
* exact entry schema, size/hash/timestamp/vector-clock bounds, a total
  materialized-byte ceiling shared with durable verification, and portable
  path-collision refusal (NFC + casefold, file vs. descendant);
* causality: a peer may only advance its own vector-clock component, and only
  by a bounded step;
* a digest that binds every manifest field, not just content Merkle leaves;
* a non-reusable binding for one authenticated channel.

Failures raise ``RuntimeError`` with the historical messages; callers map them
onto wire refusals exactly as before extraction.
"""

from __future__ import annotations

import json
import secrets
import unicodedata
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional, Protocol

import blake3

# Folder blobs use the streaming CAS and reservation ledger rather than the UI
# single-file upload path. Keep the production admission ceiling aligned with
# TransferAdmissionPolicy (16 TiB) so large datasets are supported without an
# unbounded integer/disk promise.
FOLDER_BLOB_MAX_BYTES = 16 * 1024 * 1024 * 1024 * 1024
# One wire path must remain representable as an archive member name.
FOLDER_ARCHIVE_MAX_MEMBER_NAME_BYTES = 1024
FOLDER_SYNC_MANIFEST_MAX_ENTRIES = 65_536
FOLDER_SYNC_MANIFEST_MAX_CLOCK_NODES = 256
FOLDER_SYNC_MANIFEST_MAX_CLOCK_NODE_BYTES = 128
FOLDER_SYNC_MANIFEST_MAX_COUNTER = (1 << 63) - 1
FOLDER_SYNC_MAX_CLOCK_ADVANCE = 10_000_000
# Admission and final durable verification share one byte ceiling. Accepting a
# 16 TiB blob and failing only after transfer at the old 128 GiB verification
# cap was a deterministic post-transfer failure.
FOLDER_SYNC_VERIFY_MAX_BYTES = FOLDER_BLOB_MAX_BYTES

MANIFEST_DIGEST_DOMAIN = b"one-link-folder-manifest-v1\0"
MANIFEST_WIRE_KEYS = frozenset({"file_path", "blob_hash", "size", "mtime_ms", "vclock"})
MAX_PATH_COMPONENTS = 64
MAX_COMPONENT_BYTES = 255

_WINDOWS_RESERVED = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        "CLOCK$",
        "CONIN$",
        "CONOUT$",
        *(f"COM{i}" for i in range(10)),
        *(f"LPT{i}" for i in range(10)),
        *(f"COM{i}" for i in "¹²³"),
        *(f"LPT{i}" for i in "¹²³"),
    }
)


class LocalManifestView(Protocol):
    """The read-only state-store surface the pre-merge checks consult."""

    def get_manifest_entry(self, folder_name: str, file_path: str) -> Mapping[str, Any] | None: ...

    def list_manifest(self, folder_name: str) -> Iterable[Mapping[str, Any]]: ...


def is_blob_hex(blob: str) -> bool:
    """Lowercase 64-hex content address (same contract as the daemon's)."""

    if len(blob) != 64 or blob != blob.lower():
        return False
    try:
        int(blob, 16)
        return True
    except ValueError:
        return False


def canonical_folder_wire_path(value: object) -> str | None:
    """Return the protocol-canonical relative path or ``None``.

    Folder manifests are cross-platform. Requiring forward-slash,
    component-canonical paths closes aliases such as ``a/./b``, UNC and drive
    paths, Windows device names, normalization/case collisions and traversal
    before either pending-offer persistence or CRDT mutation.
    """

    if not isinstance(value, str) or not value or "\\" in value:
        return None
    if value.startswith("/") or (len(value) > 1 and value[1] == ":"):
        return None
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        return None
    try:
        encoded = value.encode("utf-8")
    except UnicodeError:
        return None
    if len(encoded) > FOLDER_ARCHIVE_MAX_MEMBER_NAME_BYTES:
        return None
    parts = value.split("/")
    if len(parts) > MAX_PATH_COMPONENTS or any(part in {"", ".", ".."} for part in parts):
        return None
    for part in parts:
        try:
            if len(part.encode("utf-8")) > MAX_COMPONENT_BYTES:
                return None
        except UnicodeError:
            return None
        if (
            part != part.rstrip(". ")
            or any(char in '<>:"|?*' for char in part)
            or part.split(".", 1)[0].upper() in _WINDOWS_RESERVED
        ):
            return None
    return value


def safe_folder_offer_name(value: object) -> str | None:
    """Validate a peer-controlled folder name as one portable leaf."""

    if not isinstance(value, str):
        return None
    if (
        not value
        or value != value.strip()
        or value in {".", ".."}
        or len(value) > 255
        or value.endswith((".", " "))
        or any(ord(char) < 0x20 or ord(char) == 0x7F for char in value)
        or any(char in '<>:"/\\|?*' for char in value)
        or Path(value).name != value
        or Path(value).is_absolute()
    ):
        return None
    if value.split(".", 1)[0].upper() in _WINDOWS_RESERVED:
        return None
    return value


def folder_sync_paths(entries: Iterable[dict]) -> tuple[str, ...]:
    """Distinct non-empty ``file_path`` values in first-seen order."""

    paths: list[str] = []
    seen: set[str] = set()
    for entry in entries:
        path = entry.get("file_path") if isinstance(entry, dict) else None
        if not isinstance(path, str) or not path or path in seen:
            continue
        seen.add(path)
        paths.append(path)
    return tuple(paths)


def folder_manifest_digest(entries: Iterable[dict]) -> str:
    """Bind every manifest field, not only its content Merkle leaves."""

    encoded = json.dumps(
        list(entries),
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return blake3.blake3(MANIFEST_DIGEST_DOMAIN + encoded).hexdigest()


def folder_channel_binding(channel: Any) -> str:
    """Return a non-reusable binding for one authenticated channel.

    The channel's transcript hash is the binding when it is a canonical
    lowercase 64-hex string. Otherwise a random binding is minted once and
    pinned on the channel object, so it is stable for that channel's life and
    never shared with another channel.
    """

    transcript = getattr(channel, "transcript_hex", None)
    if isinstance(transcript, str) and len(transcript) == 64 and transcript == transcript.lower():
        try:
            int(transcript, 16)
        except ValueError:
            pass
        else:
            return transcript
    fallback = getattr(channel, "_one_link_folder_binding", None)
    if not isinstance(fallback, str) or len(fallback) != 64:
        fallback = secrets.token_hex(32)
        setattr(channel, "_one_link_folder_binding", fallback)
    return fallback


def _portable_key(path: str) -> str:
    return unicodedata.normalize("NFC", path).casefold()


def _parent_keys(key: str) -> set[str]:
    parts = key.split("/")
    return {"/".join(parts[:index]) for index in range(1, len(parts))}


def validate_folder_manifest_entries(entries: list[dict]) -> None:
    """Fail closed on ambiguous or resource-hostile manifest rows."""

    if len(entries) > FOLDER_SYNC_MANIFEST_MAX_ENTRIES:
        raise RuntimeError("folder manifest entry count exceeds limit")
    path_keys: set[str] = set()
    path_parent_keys: set[str] = set()
    hash_sizes: dict[str, int] = {}
    total_materialized_bytes = 0
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != MANIFEST_WIRE_KEYS:
            raise RuntimeError("folder manifest has a non-canonical entry schema")
        file_path = canonical_folder_wire_path(entry.get("file_path"))
        if file_path is None:
            raise RuntimeError("folder manifest contains an unsafe path")
        if any(
            part.startswith(".one-link-") and part.endswith(".tmp") for part in file_path.split("/")
        ):
            raise RuntimeError("folder manifest uses a reserved internal path")
        collision_key = _portable_key(file_path)
        collision_parents = _parent_keys(collision_key)
        if (
            collision_key in path_keys
            or collision_key in path_parent_keys
            or any(parent in path_keys for parent in collision_parents)
        ):
            raise RuntimeError("folder manifest contains a path collision")
        path_keys.add(collision_key)
        path_parent_keys.update(collision_parents)

        blob_hash = entry.get("blob_hash")
        size = entry.get("size")
        if blob_hash is None:
            if size is not None and not (type(size) is int and size == 0):
                raise RuntimeError("folder tombstone declares live content size")
        elif (
            not isinstance(blob_hash, str)
            or blob_hash != blob_hash.lower()
            or not is_blob_hex(blob_hash)
            or type(size) is not int
            or size < 0
            or size > FOLDER_BLOB_MAX_BYTES
        ):
            raise RuntimeError("folder manifest contains invalid content metadata")
        else:
            prior_size = hash_sizes.setdefault(blob_hash, size)
            if prior_size != size:
                raise RuntimeError("folder manifest assigns conflicting sizes to one hash")
            total_materialized_bytes += size
            if total_materialized_bytes > FOLDER_SYNC_VERIFY_MAX_BYTES:
                raise RuntimeError("folder manifest exceeds durable verification byte limit")

        mtime_ms = entry.get("mtime_ms")
        if mtime_ms is not None and (
            type(mtime_ms) is not int or mtime_ms < 0 or mtime_ms > FOLDER_SYNC_MANIFEST_MAX_COUNTER
        ):
            raise RuntimeError("folder manifest contains invalid timestamp metadata")

        clock = entry.get("vclock")
        if not isinstance(clock, dict) or len(clock) > FOLDER_SYNC_MANIFEST_MAX_CLOCK_NODES:
            raise RuntimeError("folder manifest contains an invalid vector clock")
        for node, counter in clock.items():
            try:
                node_bytes = node.encode("utf-8") if isinstance(node, str) else b""
            except UnicodeError:
                node_bytes = b""
            if (
                not node_bytes
                or len(node_bytes) > FOLDER_SYNC_MANIFEST_MAX_CLOCK_NODE_BYTES
                or any(byte < 0x20 or byte == 0x7F for byte in node_bytes)
                or type(counter) is not int
                or counter <= 0
                or counter > FOLDER_SYNC_MANIFEST_MAX_COUNTER
            ):
                raise RuntimeError("folder manifest contains an invalid vector clock")


def validate_folder_manifest_causality(
    *,
    folder_name: str,
    entries: Iterable[dict],
    peer_fp: str,
    local: Optional[LocalManifestView],
) -> None:
    """Prevent an authenticated peer from forging other devices' clocks.

    Until manifest operations carry independent device signatures, a peer may
    advance only its own vector-clock component (by a bounded step). Every
    other component must already be present locally at an equal-or-newer
    counter. This preserves direct multi-device convergence without giving one
    compromised peer a permanent causal-dominance primitive.
    """

    if local is None:
        raise RuntimeError("folder state is unavailable")
    for entry in entries:
        file_path = str(entry["file_path"])
        row = local.get_manifest_entry(folder_name, file_path)
        local_clock = dict(row.get("vclock") or {}) if row else {}
        for node, counter in dict(entry.get("vclock") or {}).items():
            local_counter = int(local_clock.get(node, 0) or 0)
            if node == peer_fp:
                if counter > local_counter + FOLDER_SYNC_MAX_CLOCK_ADVANCE:
                    raise RuntimeError("folder manifest vector clock jump exceeds policy")
            elif counter > local_counter:
                raise RuntimeError("folder manifest advances an unauthenticated clock node")


def validate_folder_manifest_against_local_paths(
    *,
    folder_name: str,
    entries: Iterable[dict],
    local: Optional[LocalManifestView],
) -> None:
    """Reject portable aliases and file/descendant collisions before merge."""

    if local is None:
        raise RuntimeError("folder state is unavailable")
    local_keys: dict[str, str] = {}
    local_parent_keys: set[str] = set()
    for row in local.list_manifest(folder_name):
        local_path = canonical_folder_wire_path(row.get("file_path"))
        if local_path is None:
            raise RuntimeError("local folder manifest contains an unsafe path")
        key = _portable_key(local_path)
        prior = local_keys.setdefault(key, local_path)
        if prior != local_path:
            raise RuntimeError("local folder manifest has a portable path collision")
        local_parent_keys.update(_parent_keys(key))

    for entry in entries:
        remote_path = str(entry["file_path"])
        key = _portable_key(remote_path)
        local_path = local_keys.get(key)
        if local_path is not None and local_path != remote_path:
            raise RuntimeError("remote folder path aliases an existing local path")
        if any(parent in local_keys for parent in _parent_keys(key)):
            raise RuntimeError("remote folder path descends from an existing local file")
        if key in local_parent_keys:
            raise RuntimeError("remote folder file collides with an existing local descendant")
