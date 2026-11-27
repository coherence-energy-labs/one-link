"""Receiver-side file transfer resume across disconnects.

Background. The CDC chunk-store protocol is naturally idempotent:
each FILE_OFFER carries a manifest of (index, hash, size) entries,
and the receiver answers with FILE_WANTS containing only the indices
whose hashes aren't already in the local chunk cache. Chunks live in
the global cache keyed by BLAKE3 hash, so the cache survives a
peer disconnect, a daemon restart, and an OS reboot.

What was missing pre-resume:

  1. The receiver's IncomingFile entry (the in-memory state tying
     a blob_hex to an out_path and a CDC manifest) was lost on
     daemon restart. After a restart the next FILE_OFFER landed
     fresh — same chunks would be re-checked against the cache,
     but the new transfer wrote to a different unique out_path,
     leaving the previous partial output orphaned on disk and
     producing a duplicate filename for the user.

  2. Within a single daemon lifetime, a sender's retry FILE_OFFER
     also overwrote the existing IncomingFile (same blob, but new
     `out_path` from `_unique_inbox_path`). The in-flight handle's
     output file became orphaned; chunks already in the
     ``cdc_parts`` dict were thrown away (the cache still had
     them, so reassembly worked, but the bookkeeping was wasteful).

This module fixes both by persisting a small JSON sidecar per
in-progress CDC offer. The sidecar carries everything needed to
restore the IncomingFile state from disk — the original FILE_OFFER
metadata (peer_fp, blob_hex, name, size, cdc_chunks) plus the
chosen out_path. The actual chunk bytes don't need to live in the
sidecar; they're already in the chunk cache.

Lifecycle:

  * On FILE_OFFER arrival (CDC mode), the receiver writes the
    sidecar before opening the output file handle. Subsequent
    chunk-write events bump ``updated_ms`` but don't rewrite
    the immutable manifest.

  * On clean completion (``_finish_cdc_file`` succeeds) the
    sidecar is deleted.

  * On abort (capability revoke mid-stream, chunk integrity
    failure, peer revoke) the sidecar is deleted along with the
    partial out_path.

  * On daemon startup, the private data directory is scanned for resume
    sidecars. Validated entries are
    registered in an in-memory ``ResumeRegistry`` that the
    FILE_OFFER handler consults before creating fresh state.

Security model.

  * Production sidecar files live outside the remotely writable inbox, under
    the daemon-owned private data directory.  A validated legacy
    ``inbox/.resume`` record may be migrated once, but its acceptance decision
    is reset so inbox content can never manufacture consent.

  * The sidecar's authority is bounded: it can resurrect a
    pending offer's *manifest* and *out_path*, but every chunk
    that lands afterward still goes through the normal
    per-chunk hash check (the existing
    ``cdc_chunk_integrity_failure`` rejection). A poisoned
    sidecar can only redirect the output filename, not inject
    bytes — the actual chunk bytes are content-addressed.

  * On load, ``peer_fp`` from the sidecar must match the peer
    who eventually sends the corresponding FILE_OFFER. A sidecar
    for peer A cannot be activated by a FILE_OFFER from peer B,
    even if the blob_hex matches.

  * ``out_path`` is validated to live under the active inbox root
    on load; a sidecar that points outside is dropped.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, cast

from one_link.namespace_durability import replace_path

try:
    from blake3 import blake3 as _blake3
except ImportError:  # pragma: no cover - optional dep
    _blake3 = None  # type: ignore[assignment,misc]  # optional dep: rebind imported name to None

log = logging.getLogger(__name__)


# Schema version. Bumped only when the on-disk JSON shape changes
# in a way that's incompatible with the previous loader.
SCHEMA_VERSION = 1

# Resume manifests are attacker-influenced protocol metadata.  Bound their
# persisted representation before ``json.loads`` can turn a hostile file into
# an unbounded allocation, and mirror the daemon's manifest cardinality cap.
MAX_SIDECAR_BYTES = 64 * 1024 * 1024
MAX_SIDECAR_CHUNKS = 262_144
MAX_RESUME_FILE_BYTES = 16 * 1024**4

# Sidecars live under <inbox>/.resume/. The dot prefix keeps them
# out of any UI inbox listing that filters dotfiles.
SIDECAR_SUBDIR = ".resume"


@dataclass
class ResumeSidecar:
    """One in-progress CDC inbound transfer's persistent state.

    Fields mirror the FILE_OFFER payload plus the chosen out_path.
    Everything else (which chunks have already landed) is recovered
    on resume by re-checking the global chunk cache — so it stays
    out of the sidecar.
    """

    blob_hex: str
    peer_fp: str
    name: str
    size: int
    out_path: str
    cdc_chunks: list[dict[str, Any]]
    created_ms: int = field(default_factory=lambda: int(time.time() * 1000))
    updated_ms: int = field(default_factory=lambda: int(time.time() * 1000))
    schema_version: int = SCHEMA_VERSION
    # True only after the receiver's acceptance gate has been cleared
    # (explicit user acceptance, a trusted conversational attachment, or
    # the per-session "accept all" rule).  Persisting this decision prevents
    # a reconnect/restart from turning an already-authorized transfer back
    # into a fresh prompt.  Legacy sidecars default to False (fail closed).
    acceptance_granted: bool = False
    # FILE_COMMIT-capable peers identify a logical delivery independently of
    # its content hash. Optional defaults keep pre-upgrade sidecars readable;
    # those legacy records remain blob/peer-scoped and cannot manufacture a
    # modern confirmed receipt.
    delivery_id: str = ""
    delivery_name: str = ""
    delivery_rel_path: str = ""
    delivery_kind: str = "file"
    final_path: str = ""
    # Integrity tag over the canonical JSON of every OTHER field.
    # Lets the loader distinguish "disk corrupted this file" (we'll
    # log + drop, and let the chunk cache + sender retry rebuild the
    # transfer) from "user intentionally deleted it" (which is the
    # same end result but a cleaner mental model in logs).
    #
    # Empty string when written by a pre-Wave-1e daemon — the loader
    # treats absent/empty digest as "legacy sidecar, skip integrity
    # check". New sidecars always carry one.
    digest: str = ""

    def touch(self) -> None:
        self.updated_ms = int(time.time() * 1000)

    def _to_signing_dict(self) -> dict[str, Any]:
        """Dict shape used for the integrity digest: every field
        EXCEPT ``digest`` itself, with a deterministic key ordering
        so the same content always produces the same hash."""
        d = asdict(self)
        d.pop("digest", None)
        return d

    def _compute_digest(self) -> str:
        """BLAKE3 of the canonical signing JSON. Returns empty when
        the blake3 module isn't importable — caller treats that as
        "skip integrity tagging on this install"."""
        if _blake3 is None:
            return ""
        canon = json.dumps(
            self._to_signing_dict(),
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return _blake3(canon).hexdigest()

    def to_json(self) -> str:
        # Recompute the digest at every persist so debounced
        # ``touch()`` rewrites (which bump updated_ms) produce a
        # matching tag. The digest covers updated_ms, so a stale
        # digest from a prior write would fail the load check.
        self.digest = self._compute_digest()
        return json.dumps(asdict(self), separators=(",", ":"))

    @classmethod
    def from_json(cls, text: str) -> "ResumeSidecar":
        if len(text.encode("utf-8")) > MAX_SIDECAR_BYTES:
            raise ValueError("resume sidecar exceeds the metadata size limit")
        raw = json.loads(text)
        if not isinstance(raw, dict):
            raise ValueError("resume sidecar root must be an object")
        # Drop unknown keys defensively (forward-compat with older
        # schemas that wrote extra fields) rather than failing the
        # whole load. Required keys are enforced below.
        known = {f for f in cls.__dataclass_fields__}
        filtered = {k: v for k, v in raw.items() if k in known}
        if filtered.get("schema_version", SCHEMA_VERSION) != SCHEMA_VERSION:
            raise ValueError(
                f"resume sidecar schema {filtered.get('schema_version')} "
                f"unsupported (this daemon understands {SCHEMA_VERSION})"
            )
        sc = cls(**filtered)
        sc._validate_untrusted_fields()
        # Integrity check. A pre-Wave-1e sidecar without a digest
        # field passes through (digest=""); a newer sidecar whose
        # digest doesn't match its content raises ValueError so the
        # caller can log + drop it instead of acting on tampered
        # state.
        if sc.digest:
            # Verify exactly the fields that were present on disk.  This is
            # important for backward compatibility: adding a new optional
            # dataclass field must not invalidate the digest of an older
            # sidecar that was written before that field existed.
            signing_raw = dict(raw)
            signing_raw.pop("digest", None)
            expected = ""
            if _blake3 is not None:
                canon = json.dumps(
                    signing_raw,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8")
                expected = _blake3(canon).hexdigest()
            if expected != sc.digest:
                raise ValueError(
                    f"resume sidecar digest mismatch for blob "
                    f"{sc.blob_hex[:8]}: expected {expected[:16]}, "
                    f"got {sc.digest[:16]}"
                )
        return sc

    def _validate_untrusted_fields(self) -> None:
        """Validate every persisted field before it reaches daemon state.

        A sidecar is recovery metadata, never authority.  Treating its JSON as
        a dataclass without validating nested values previously allowed arrays,
        booleans-as-integers, enormous manifests, and malformed chunk ranges to
        survive startup and fail much later in the transfer hot path.
        """
        if (
            not isinstance(self.blob_hex, str)
            or len(self.blob_hex) != 64
            or any(c not in "0123456789abcdef" for c in self.blob_hex)
        ):
            raise ValueError("resume blob id must be 64 lowercase hex characters")
        if not isinstance(self.peer_fp, str) or not (1 <= len(self.peer_fp) <= 512):
            raise ValueError("resume peer fingerprint is invalid")
        if not isinstance(self.name, str) or not (1 <= len(self.name) <= 1024):
            raise ValueError("resume filename is invalid")
        if "\x00" in self.name:
            raise ValueError("resume filename contains NUL")
        if not isinstance(self.out_path, str) or not (1 <= len(self.out_path) <= 32_768):
            raise ValueError("resume output path is invalid")
        if "\x00" in self.out_path:
            raise ValueError("resume output path contains NUL")
        if (
            isinstance(self.size, bool)
            or not isinstance(self.size, int)
            or not (0 <= self.size <= MAX_RESUME_FILE_BYTES)
        ):
            raise ValueError("resume file size is invalid")
        for label, numeric_value in (
            ("created_ms", self.created_ms),
            ("updated_ms", self.updated_ms),
            ("schema_version", self.schema_version),
        ):
            if (
                isinstance(numeric_value, bool)
                or not isinstance(numeric_value, int)
                or numeric_value < 0
            ):
                raise ValueError(f"resume {label} is invalid")
        if not isinstance(self.acceptance_granted, bool):
            raise ValueError("resume acceptance flag must be boolean")
        if self.delivery_id and (
            not isinstance(self.delivery_id, str)
            or len(self.delivery_id) != 32
            or any(c not in "0123456789abcdef" for c in self.delivery_id)
        ):
            raise ValueError("resume delivery id is invalid")
        for label, text_value, limit in (
            ("delivery name", self.delivery_name, 1024),
            ("delivery relative path", self.delivery_rel_path, 32_768),
            ("final path", self.final_path, 32_768),
        ):
            if (
                not isinstance(text_value, str)
                or len(text_value) > limit
                or "\x00" in text_value
            ):
                raise ValueError(f"resume {label} is invalid")
        if self.delivery_kind not in {"file", "folder_archive"}:
            raise ValueError("resume delivery kind is invalid")
        if not isinstance(self.digest, str) or (
            self.digest
            and (
                len(self.digest) != 64
                or any(c not in "0123456789abcdef" for c in self.digest)
            )
        ):
            raise ValueError("resume digest is invalid")
        if not isinstance(self.cdc_chunks, list):
            raise ValueError("resume CDC manifest must be an array")
        if len(self.cdc_chunks) > MAX_SIDECAR_CHUNKS:
            raise ValueError("resume CDC manifest has too many chunks")

        cursor = 0
        for expected_index, item in enumerate(self.cdc_chunks):
            if not isinstance(item, dict):
                raise ValueError("resume CDC chunk must be an object")
            index = item.get("index")
            size = item.get("size")
            start = item.get("start")
            end = item.get("end")
            chunk_hash = item.get("hash")
            ints = (index, size, start, end)
            if any(isinstance(v, bool) or not isinstance(v, int) for v in ints):
                raise ValueError("resume CDC chunk ranges must be integers")
            index = cast(int, index)
            size = cast(int, size)
            start = cast(int, start)
            end = cast(int, end)
            if index != expected_index or start != cursor:
                raise ValueError("resume CDC manifest is not an exact partition")
            if size <= 0 or end <= start or end - start != size:
                raise ValueError("resume CDC chunk range is invalid")
            if end > self.size:
                raise ValueError("resume CDC chunk exceeds declared file size")
            if (
                not isinstance(chunk_hash, str)
                or len(chunk_hash) != 64
                or any(c not in "0123456789abcdef" for c in chunk_hash)
            ):
                raise ValueError("resume CDC chunk hash is invalid")
            cursor = end
        if cursor != self.size:
            raise ValueError("resume CDC manifest does not cover the declared file")


def sidecar_dir(inbox_root: Path, *, metadata_root: Path | None = None) -> Path:
    """Return the daemon-private sidecar directory.

    ``metadata_root`` lets production keep recovery authority outside the
    remotely writable inbox.  The legacy inbox-local default is retained for
    library/API compatibility and migration tests; the daemon always supplies
    its private data-directory location.
    """
    return Path(metadata_root) if metadata_root is not None else Path(inbox_root) / SIDECAR_SUBDIR


def sidecar_path(
    inbox_root: Path,
    blob_hex: str,
    *,
    metadata_root: Path | None = None,
) -> Path:
    return sidecar_dir(inbox_root, metadata_root=metadata_root) / f"{blob_hex}.json"


def persist_sidecar(
    inbox_root: Path,
    sidecar: ResumeSidecar,
    *,
    metadata_root: Path | None = None,
) -> None:
    """Atomically write a sidecar to disk.

    The write goes through a same-directory temporary and an atomic replace,
    so a daemon crash cannot leave torn JSON. Windows uses a write-through
    rename for the namespace commit; POSIX fsyncs the parent directory.
    """
    target = sidecar_path(inbox_root, sidecar.blob_hex, metadata_root=metadata_root)
    target.parent.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        with _suppress_oserror():
            os.chmod(target.parent, 0o700)
    tmp = target.parent / f".{os.getpid()}_{secrets.token_hex(8)}.tmp"
    payload = sidecar.to_json()
    sidecar._validate_untrusted_fields()
    try:
        with tmp.open("x", encoding="utf-8", newline="") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        # On Windows the actual replacement is issued with
        # MOVEFILE_WRITE_THROUGH. POSIX still requires the parent fsync below.
        replace_path(tmp, target)
        if os.name != "nt":
            dir_fd = os.open(target.parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
    finally:
        with _suppress_oserror():
            tmp.unlink()


def delete_sidecar(
    inbox_root: Path,
    blob_hex: str,
    *,
    metadata_root: Path | None = None,
) -> bool:
    """Remove a sidecar, reporting whether it is absent after the attempt.

    Missing files are an idempotent success. Existing best-effort cleanup
    callers may ignore the result; explicit owner cancellation must not.
    """
    try:
        sidecar_path(inbox_root, blob_hex, metadata_root=metadata_root).unlink()
    except FileNotFoundError:
        return True
    except OSError as e:
        log.warning("could not delete resume sidecar for %s: %s", blob_hex[:8], e)
        return False
    return True


def load_sidecar(
    inbox_root: Path,
    blob_hex: str,
    *,
    metadata_root: Path | None = None,
) -> ResumeSidecar | None:
    """Read a single sidecar. Returns None on absent / unreadable /
    malformed. Never raises — a corrupted sidecar must not crash the
    daemon."""
    p = sidecar_path(inbox_root, blob_hex, metadata_root=metadata_root)
    if p.is_symlink():
        log.warning("refusing symlink resume sidecar at %s", p)
        return None
    try:
        if p.stat().st_size > MAX_SIDECAR_BYTES:
            log.warning("resume sidecar exceeds size limit at %s", p)
            return None
        text = p.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    try:
        return ResumeSidecar.from_json(text)
    except (ValueError, json.JSONDecodeError, TypeError) as e:
        log.warning("malformed resume sidecar at %s: %s", p, e)
        return None


def scan_inbox(
    inbox_root: Path,
    *,
    metadata_root: Path | None = None,
) -> list[ResumeSidecar]:
    """Walk the sidecar directory and return every loadable entry.

    Sidecars whose ``out_path`` no longer exists (the user cleaned
    their inbox manually, or the partial was unlinked but the
    sidecar wasn't) are dropped on the floor — there's no partial
    to resume into. The orphaned sidecar is also deleted so a fresh
    transfer for the same blob can land cleanly.
    """
    out: list[ResumeSidecar] = []
    d = sidecar_dir(inbox_root, metadata_root=metadata_root)
    if not d.is_dir():
        return out
    try:
        names = list(d.iterdir())
    except OSError as e:
        log.warning("could not scan resume sidecars in %s: %s", d, e)
        return out
    inbox_resolved = Path(inbox_root).resolve()
    for entry in names:
        if entry.is_symlink() or not entry.is_file() or entry.suffix != ".json":
            continue
        try:
            if entry.stat().st_size > MAX_SIDECAR_BYTES:
                raise ValueError("resume sidecar exceeds metadata size limit")
            sc = ResumeSidecar.from_json(entry.read_text(encoding="utf-8"))
        except (ValueError, json.JSONDecodeError, TypeError, OSError) as e:
            log.warning("dropping malformed sidecar %s: %s", entry, e)
            with _suppress_oserror():
                entry.unlink()
            continue
        # Path-traversal guard: a sidecar that points outside the
        # inbox is hostile or corrupted. Resolve both sides + check
        # the partial sits under the resolved inbox root.
        try:
            op = Path(sc.out_path).resolve()
        except (OSError, RuntimeError):
            log.warning("dropping sidecar with unresolvable out_path: %s", entry)
            with _suppress_oserror():
                entry.unlink()
            continue
        try:
            op.relative_to(inbox_resolved)
            if sc.final_path:
                Path(sc.final_path).resolve().relative_to(inbox_resolved)
        except ValueError:
            log.warning(
                "dropping sidecar pointing outside inbox: %s -> %s",
                entry, op,
            )
            with _suppress_oserror():
                entry.unlink()
            continue
        if not op.is_file():
            log.info(
                "resume sidecar %s has no partial at %s; cleaning up",
                sc.blob_hex[:8], op,
            )
            with _suppress_oserror():
                entry.unlink()
            continue
        out.append(sc)
    return out


# A sidecar that hasn't been touched in this many days is treated
# as abandoned and pruned at daemon startup. 30 days is enough to
# cover "user laptop sat in a drawer over vacation" without letting
# inboxes accumulate orphan manifests for blobs the sender will
# never come back for.
SIDECAR_TTL_DAYS_DEFAULT = 30


class ResumeRegistry:
    """In-memory index of resumable inbound transfers, keyed by
    ``(peer_fp, blob_hex)``.

    The daemon populates this once at startup via :meth:`load_from_inbox`,
    then consults :meth:`pop_match` in the FILE_OFFER handler before
    creating a fresh IncomingFile. A matched entry returns the
    original out_path + manifest so the resumed transfer reuses the
    same disk location.
    """

    def __init__(self, inbox_root: Path, *, metadata_root: Path | None = None) -> None:
        self.inbox_root = Path(inbox_root)
        self.metadata_root = Path(metadata_root) if metadata_root is not None else None
        self._by_key: dict[tuple[str, str], ResumeSidecar] = {}

    def load_from_inbox(
        self,
        *,
        ttl_days: int = SIDECAR_TTL_DAYS_DEFAULT,
    ) -> int:
        """Scan the inbox + populate the registry. Sidecars whose
        ``updated_ms`` is older than ``ttl_days`` (default 30) are
        pruned along with their partial out_path before the rest are
        registered. Returns the number of entries kept."""
        self._by_key.clear()
        prune_before_ms = int((time.time() - ttl_days * 86400) * 1000)
        pruned = 0
        recovered = scan_inbox(self.inbox_root, metadata_root=self.metadata_root)
        if self.metadata_root is not None:
            # One-time fail-closed migration from the historical inbox-local
            # layout.  An archive or folder sync could write that directory,
            # so never inherit its persisted consent bit.  Strict schema,
            # manifest and out-path validation has already run in scan_inbox.
            private_keys = {(sc.peer_fp, sc.blob_hex) for sc in recovered}
            for legacy in scan_inbox(self.inbox_root):
                key = (legacy.peer_fp, legacy.blob_hex)
                if key not in private_keys:
                    legacy.acceptance_granted = False
                    persist_sidecar(
                        self.inbox_root,
                        legacy,
                        metadata_root=self.metadata_root,
                    )
                    recovered.append(legacy)
                    private_keys.add(key)
                delete_sidecar(self.inbox_root, legacy.blob_hex)

        for sc in recovered:
            if sc.updated_ms < prune_before_ms:
                try:
                    Path(sc.out_path).unlink()
                except OSError:
                    pass
                delete_sidecar(
                    self.inbox_root,
                    sc.blob_hex,
                    metadata_root=self.metadata_root,
                )
                pruned += 1
                continue
            self._by_key[(sc.peer_fp, sc.blob_hex)] = sc
        if self._by_key:
            log.info(
                "resume registry: loaded %d in-progress inbound transfer(s)%s",
                len(self._by_key),
                f" (pruned {pruned} stale)" if pruned else "",
            )
        elif pruned:
            log.info("resume registry: pruned %d stale entry(ies)", pruned)
        return len(self._by_key)

    def snapshot(
        self,
        *,
        cache_check_fn=None,
    ) -> list[dict]:
        """JSON-shaped list of current entries for the status API.

        Each entry is a small dict; the full CDC manifest
        (potentially thousands of entries) is replaced with a count
        so the snapshot stays bounded for the UI / control plane.

        If ``cache_check_fn`` is provided, it's called once per
        entry with the entry's full list of chunk hashes and must
        return the SUBSET that's currently present in the local
        chunk cache. The snapshot enriches each entry with:

          - ``cdc_chunks_cached``: count of chunks already on disk
          - ``cached_bytes``: byte total of those chunks
          - ``progress_ratio``: cached_bytes / size, 0..1, lets the
            UI render "67 % already on disk" before the sender
            even reconnects.
        """
        out: list[dict] = []
        for (peer_fp, blob), sc in sorted(self._by_key.items()):
            entry: dict = {
                "blob": blob,
                "peer_fp": peer_fp,
                "name": sc.name,
                "size": sc.size,
                "out_path": sc.out_path,
                "cdc_chunks_total": len(sc.cdc_chunks),
                "created_ms": sc.created_ms,
                "updated_ms": sc.updated_ms,
            }
            if cache_check_fn is not None and sc.cdc_chunks:
                try:
                    hashes = [str(c["hash"]) for c in sc.cdc_chunks if "hash" in c]
                    present = set(cache_check_fn(hashes))
                    cached_count = 0
                    cached_bytes = 0
                    for c in sc.cdc_chunks:
                        h = str(c.get("hash", ""))
                        if h in present:
                            cached_count += 1
                            try:
                                cached_bytes += int(c.get("size", 0))
                            except (TypeError, ValueError):
                                pass
                    entry["cdc_chunks_cached"] = cached_count
                    entry["cached_bytes"] = cached_bytes
                    entry["progress_ratio"] = (
                        round(cached_bytes / sc.size, 4) if sc.size > 0 else 0.0
                    )
                except (MemoryError, RecursionError):
                    # Resource exhaustion is process health, not a cache miss.
                    # Propagating it prevents a critically unhealthy daemon
                    # from advertising a misleading zero/unknown resume state.
                    raise
                except Exception as e:
                    # ``cache_check_fn`` is an injected subsystem boundary
                    # (the daemon currently backs it with cache + database
                    # lookups), so its concrete exception taxonomy is not
                    # owned by this module. Keep the status endpoint alive,
                    # but surface the operational failure at warning level.
                    log.warning(
                        "resume cache progress lookup failed for %s: %s",
                        blob[:8],
                        e,
                        exc_info=True,
                    )
            out.append(entry)
        return out

    def pop_match(
        self,
        peer_fp: str,
        blob_hex: str,
        *,
        delivery_id: str = "",
    ) -> ResumeSidecar | None:
        """Return + remove a matching entry. The receiver hands
        ownership of the partial back to the freshly-created
        IncomingFile, so the registry shouldn't hold onto it."""
        key = (peer_fp, blob_hex)
        candidate = self._by_key.get(key)
        if candidate is None:
            return None
        if delivery_id:
            if candidate.delivery_id != delivery_id:
                # Same content under a new logical delivery is not a resume.
                # Preserve the original partial; the protocol layer rejects
                # the conflicting offer instead of destroying resumable data.
                return None
        elif candidate.delivery_id:
            # A legacy offer may not claim a modern delivery's partial.
            return None
        return self._by_key.pop(key, None)

    def has_delivery_conflict(
        self,
        peer_fp: str,
        blob_hex: str,
        *,
        delivery_id: str,
        size: int,
        delivery_name: str,
        delivery_rel_path: str,
        delivery_kind: str,
    ) -> bool:
        """Refuse to consume a parked partial under a changed delivery contract.

        This is an independent guard even when the durable transfer ledger
        row is absent. A content hash and delivery nonce alone cannot convey
        consent for a different declared size or destination.
        """
        candidate = self._by_key.get((peer_fp, blob_hex))
        return candidate is not None and (
            candidate.delivery_id != delivery_id
            or candidate.size != size
            or (candidate.delivery_name or candidate.name) != delivery_name
            or candidate.delivery_rel_path != delivery_rel_path
            or candidate.delivery_kind != delivery_kind
        )

    def discard_blob(self, blob_hex: str) -> list[ResumeSidecar]:
        """Remove all parked records for an explicit local owner cancellation.

        Unlike pop_match, this is not a peer-offer adoption operation, so a
        modern delivery nonce must not prevent removal. Only the authenticated
        local cancel command may use this blob-scoped operation.
        """
        keys = [key for key in self._by_key if key[1] == blob_hex]
        return [self._by_key.pop(key) for key in keys]

    def register(self, sidecar: ResumeSidecar) -> None:
        """Add (or replace) an entry. Called by the FILE_OFFER
        handler when a brand-new transfer starts, so a later crash
        + restart can pick it back up."""
        self._by_key[(sidecar.peer_fp, sidecar.blob_hex)] = sidecar

    def keys(self) -> Iterable[tuple[str, str]]:
        return self._by_key.keys()

    def __len__(self) -> int:
        return len(self._by_key)


class _suppress_oserror:
    """Context manager twin for ``contextlib.suppress(OSError)`` —
    inlined to avoid pulling contextlib into this module's import
    surface for a single use."""

    def __enter__(self) -> "_suppress_oserror":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return exc_type is not None and issubclass(exc_type, OSError)
