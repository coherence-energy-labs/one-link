"""Encrypted backup bundles — your chat history + groups + settings,
sealed with a key only you can derive.

The "for the people" recovery story has two layers:

  1. **Identity recovery** (Bundle 23, mnemonic.py + master_seed.py):
     24 words on paper restore your Ed25519 identity + at-rest
     keys on a new device. Peers continue to recognize you.

  2. **Data recovery** (this module, Bundle 24): an encrypted
     ``.olbak`` bundle holds your sqlite state — chat history,
     group memberships, peer trust state, settings — encrypted
     under a key that ONLY the master seed can derive. Drop the
     bundle on any portable medium (USB stick, cloud-storage,
     the email-yourself trick, a printed QR for the truly
     paranoid). Without the seed it is ciphertext indistinguishable
     from random; with the seed (= the 24 words) anyone restoring
     to a new device gets the full daemon state back.

Wire format
-----------
``.olbak`` v1 layout (binary):

    [0..8)        magic         b"OLBAK\\x01\\x00\\x00"   (8 bytes)
    [8..16)       length-prefix u64 big-endian             (size of plaintext)
    [16..28)      AES-GCM nonce 12 bytes (random per export)
    [28..36)      created_ms    u64 big-endian (clock-of-export timestamp)
    [36..)        ciphertext + 16-byte AEAD tag

The plaintext is a deflate-compressed tar archive of the daemon's
data dir, with a strict allowlist of files included (state.db,
master.seed, settings, NO inbox content by default — that's
opt-in via ``--include-files`` because inboxes can be huge).

The AAD on the AEAD covers magic + length + nonce + created_ms,
so any tamper of the header invalidates the tag.

Sovereignty notes
-----------------
- The bundle key derives from the master seed via HKDF with a
  distinct domain-separation tag (``OL/master/backup-bundle|v1``).
  A leak of the bundle key cannot be used to decrypt the running
  daemon's at-rest data (which uses a different derived subkey).
- No third-party service ever sees the bundle plaintext. The
  user can post-process (encrypt-again, split via Shamir, hide in
  a tarball of cat photos) without affecting the recovery path.
- Restore explicitly requires possession of the 24-word phrase OR
  an existing master seed file. There is no "lost the words and
  the file? click here" recovery — that path doesn't exist by
  design, and every user-visible message in the CLI says so.
"""
from __future__ import annotations

import contextlib
import gzip
import io
import logging
import os
import secrets
import shutil
import stat
import struct
import tarfile
import tempfile
import unicodedata
import zlib
from array import array
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from typing import Any, BinaryIO, Iterable, Mapping, cast

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

log = logging.getLogger("one_link.backup_bundle")

BUNDLE_MAGIC = b"OLBAK\x01\x00\x00"
NONCE_LEN = 12
HEADER_LEN = len(BUNDLE_MAGIC) + 8 + NONCE_LEN + 8  # magic + len + nonce + ts
PLAINTEXT_VERSION = 1

# Recovery archives are authenticated, but authentication does not make their
# resource declarations trustworthy.  A copied backup may have been produced
# by compromised software which also knew the recovery seed.  Keep every
# dimension finite before allowing gzip/tar metadata to drive memory or disk
# work.  These limits are part of the v1 restore policy:
#
# * the encrypted gzip payload is at most 256 MiB (the same cap as the UI),
# * at most 100,000 tar members and 1,024 UTF-8 bytes per member path,
# * at most 16 GiB for one file and 16 GiB across all regular-file payloads,
# * no more than 200x compressed expansion, with a 64 MiB allowance for small
#   legitimate archives, and
# * at most 64 MiB of tar headers, padding, and extended metadata beyond the
#   declared regular-file payload budget.
#
# The streaming reader below enforces the expansion/metadata budget on actual
# decompressed bytes as well as checking the sizes declared in tar headers.
MAX_BUNDLE_COMPRESSED_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 100_000
MAX_ARCHIVE_MEMBER_NAME_BYTES = 1024
MAX_ARCHIVE_PATH_DEPTH = 64
MAX_ARCHIVE_MEMBER_METADATA_BYTES = 64 * 1024
MAX_ARCHIVE_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_FILE_BYTES = 16 * 1024 * 1024 * 1024
MAX_ARCHIVE_TOTAL_FILE_BYTES = 16 * 1024 * 1024 * 1024
MAX_ARCHIVE_EXPANSION_RATIO = 200
MIN_ARCHIVE_EXPANSION_ALLOWANCE_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_METADATA_ALLOWANCE_BYTES = 64 * 1024 * 1024
BUNDLE_RESTORE_MIN_FREE_RESERVE_BYTES = 256 * 1024 * 1024
BUNDLE_RESTORE_FREE_RESERVE_RATIO = 0.02
_ARCHIVE_COPY_CHUNK_BYTES = 1024 * 1024
_GZIP_INPUT_CHUNK_BYTES = 64 * 1024

_WINDOWS_RESERVED_BASENAMES = frozenset({
    "CON", "PRN", "AUX", "NUL", "CLOCK$",
    *(f"COM{i}" for i in range(10)),
    *(f"LPT{i}" for i in range(10)),
    "COM¹", "COM²", "COM³", "LPT¹", "LPT²", "LPT³",
})
_BIDI_CONTROL_CHARACTERS = frozenset(
    "\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e"
    "\u2066\u2067\u2068\u2069"
)


class BundleArchiveError(ValueError):
    """The decrypted archive violates the finite v1 restore policy."""


class _BoundedTarInfo(tarfile.TarInfo):
    """TarInfo parser that bounds hidden PAX/GNU metadata before reading it.

    ``TarFile`` resolves extension records before yielding the resulting member
    to callers.  Merely checking ``TarInfo.pax_headers`` after iteration is too
    late: the standard parser may already have allocated the attacker-declared
    extension size.  These hooks reject oversized records before the read and
    account all extension records, including ones hidden from iteration.
    """

    def _account_extension(self, archive: Any) -> None:
        size = int(self.size)
        if size < 0 or size > MAX_ARCHIVE_MEMBER_METADATA_BYTES:
            raise BundleArchiveError("backup archive extension metadata is too large")
        block_size = ((size + tarfile.BLOCKSIZE - 1) // tarfile.BLOCKSIZE) * tarfile.BLOCKSIZE
        used = int(getattr(archive, "_one_link_extension_bytes", 0)) + block_size
        count = int(getattr(archive, "_one_link_extension_count", 0)) + 1
        if (
            used > MAX_ARCHIVE_METADATA_ALLOWANCE_BYTES
            or count > MAX_ARCHIVE_MEMBERS
        ):
            raise BundleArchiveError("backup archive extension metadata limit exceeded")
        setattr(archive, "_one_link_extension_bytes", used)
        setattr(archive, "_one_link_extension_count", count)

    def _proc_pax(self, archive: Any) -> tarfile.TarInfo:
        self._account_extension(archive)
        processor = getattr(super(), "_proc_pax")
        return processor(archive)

    def _proc_gnulong(self, archive: Any) -> tarfile.TarInfo:
        self._account_extension(archive)
        processor = getattr(super(), "_proc_gnulong")
        return processor(archive)

    def _proc_sparse(self, archive: Any) -> tarfile.TarInfo:
        raise BundleArchiveError("sparse backup archive members are not supported")

    def _proc_gnusparse_00(self, *args: Any, **kwargs: Any) -> None:
        raise BundleArchiveError("sparse backup archive members are not supported")

    def _proc_gnusparse_01(self, *args: Any, **kwargs: Any) -> None:
        raise BundleArchiveError("sparse backup archive members are not supported")

    def _proc_gnusparse_10(self, *args: Any, **kwargs: Any) -> None:
        raise BundleArchiveError("sparse backup archive members are not supported")


class _StrictGzipReader(io.RawIOBase):
    """Single-member gzip reader with a hard decompressed-byte ceiling.

    ``gzip.GzipFile`` deliberately accepts concatenated streams and may read
    far beyond a tar end marker.  Recovery accepts exactly one gzip member and
    no trailing bytes, so a second hidden stream cannot create an alternate
    interpretation for another implementation.
    """

    def __init__(self, compressed: bytes, *, max_output_bytes: int) -> None:
        super().__init__()
        self._compressed = memoryview(compressed)
        self._compressed_pos = 0
        self._pending_input = b""
        self._decoded = bytearray()
        self._decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        self._max_output_bytes = int(max_output_bytes)
        self._total_output_bytes = 0
        self._finished = False

    @property
    def total_output_bytes(self) -> int:
        return self._total_output_bytes

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return False

    def _append_output(self, decoded: bytes) -> None:
        if not decoded:
            return
        new_total = self._total_output_bytes + len(decoded)
        if new_total > self._max_output_bytes:
            raise BundleArchiveError(
                "backup archive exceeds the decompressed/metadata limit"
            )
        self._decoded.extend(decoded)
        self._total_output_bytes = new_total

    def _pump(self, wanted: int) -> None:
        while len(self._decoded) < wanted and not self._finished:
            if self._pending_input:
                encoded: bytes | memoryview = self._pending_input
                self._pending_input = b""
            elif self._compressed_pos < len(self._compressed):
                end = min(
                    len(self._compressed),
                    self._compressed_pos + _GZIP_INPUT_CHUNK_BYTES,
                )
                encoded = self._compressed[self._compressed_pos:end]
                self._compressed_pos = end
            else:
                if not self._decoder.eof:
                    raise BundleArchiveError(
                        "backup archive gzip stream is truncated"
                    )
                self._finished = True
                break

            output_room = max(_GZIP_INPUT_CHUNK_BYTES, wanted - len(self._decoded))
            try:
                decoded = self._decoder.decompress(encoded, output_room)
            except zlib.error as exc:
                raise BundleArchiveError(
                    "backup archive is not a valid gzip stream"
                ) from exc
            self._append_output(decoded)
            if self._decoder.unconsumed_tail:
                self._pending_input = bytes(self._decoder.unconsumed_tail)
            if self._decoder.eof:
                trailing = len(self._decoder.unused_data) + len(self._pending_input)
                trailing += len(self._compressed) - self._compressed_pos
                if trailing:
                    raise BundleArchiveError(
                        "backup archive has trailing or concatenated gzip data"
                    )
                self._finished = True

    def readinto(self, buffer: Any) -> int:
        if self.closed:
            raise ValueError("I/O operation on closed gzip reader")
        view = memoryview(buffer).cast("B")
        if not view:
            return 0
        self._pump(len(view))
        count = min(len(view), len(self._decoded))
        if count:
            view[:count] = self._decoded[:count]
            del self._decoded[:count]
        return count

    def close(self) -> None:
        if not self.closed:
            self._compressed.release()
        super().close()


@dataclass
class _ArchiveBudget:
    compressed_bytes: int
    expanded_payload_limit: int
    member_count: int = 0
    total_file_bytes: int = 0
    actual_file_bytes: int = 0
    nodes: dict[str, int] | None = None

    def __post_init__(self) -> None:
        self.nodes = {}


_NODE_FILE = 0
_NODE_IMPLICIT_DIRECTORY = 1
_NODE_EXPLICIT_DIRECTORY = 2


def _expanded_payload_limit(compressed_bytes: int) -> int:
    ratio_limit = max(
        MIN_ARCHIVE_EXPANSION_ALLOWANCE_BYTES,
        compressed_bytes * MAX_ARCHIVE_EXPANSION_RATIO,
    )
    return min(MAX_ARCHIVE_TOTAL_FILE_BYTES, ratio_limit)


def _validate_archive_path(name: str, *, directory: bool) -> tuple[str, str]:
    if not isinstance(name, str):
        raise BundleArchiveError("backup archive member name must be text")
    if not name or "\\" in name or name.startswith("/"):
        raise BundleArchiveError(f"unsafe archive entry path: {name!r}")
    normalized = unicodedata.normalize("NFC", name)
    clean = normalized[:-1] if directory and normalized.endswith("/") else normalized
    if not clean or (not directory and normalized.endswith("/")):
        raise BundleArchiveError(f"unsafe archive entry path: {name!r}")
    try:
        encoded = clean.encode("utf-8", "strict")
    except UnicodeError as exc:
        raise BundleArchiveError(
            f"unsafe archive entry path: {name!r}"
        ) from exc
    parts = clean.split("/")
    if (
        len(encoded) > MAX_ARCHIVE_MEMBER_NAME_BYTES
        or len(parts) > MAX_ARCHIVE_PATH_DEPTH
        or any(not part for part in parts)
    ):
        raise BundleArchiveError(f"unsafe archive entry path: {name!r}")
    for part in parts:
        stem = part.split(".", 1)[0].upper()
        if (
            part in {".", ".."}
            or part[-1:] in {" ", "."}
            or len(part.encode("utf-8")) > 255
            or any(ord(char) < 0x20 or ord(char) == 0x7F for char in part)
            or any(char in '<>:"|?*' for char in part)
            or any(char in _BIDI_CONTROL_CHARACTERS for char in part)
            or stem in _WINDOWS_RESERVED_BASENAMES
        ):
            raise BundleArchiveError(f"unsafe archive entry path: {name!r}")
    return "/".join(parts), "/".join(part.casefold() for part in parts)


def _member_metadata_bytes(member: tarfile.TarInfo) -> int:
    fields = (member.name, member.linkname, member.uname, member.gname)
    total = sum(len(str(value).encode("utf-8", errors="surrogatepass")) for value in fields)
    total += sum(
        len(str(key).encode("utf-8", errors="surrogatepass"))
        + len(str(value).encode("utf-8", errors="surrogatepass"))
        for key, value in member.pax_headers.items()
    )
    return total


def _validate_archive_member(
    member: tarfile.TarInfo,
    budget: _ArchiveBudget,
) -> tuple[str, str]:
    budget.member_count += 1
    if budget.member_count > MAX_ARCHIVE_MEMBERS:
        raise BundleArchiveError("backup archive contains too many members")
    if _member_metadata_bytes(member) > MAX_ARCHIVE_MEMBER_METADATA_BYTES:
        raise BundleArchiveError("backup archive member metadata is too large")
    if member.sparse is not None or any(
        str(key).startswith(("GNU.sparse", "SCHILY.realsize"))
        for key in member.pax_headers
    ):
        raise BundleArchiveError("sparse backup archive members are not supported")
    directory = member.isdir()
    if not directory and not member.isfile():
        raise BundleArchiveError(
            f"unsupported archive entry type for {member.name!r}"
        )
    normalized, key = _validate_archive_path(member.name, directory=directory)
    if directory and int(member.size) != 0:
        raise BundleArchiveError("backup archive directory has a non-zero size")
    nodes = budget.nodes
    assert nodes is not None
    key_parts = key.split("/")
    for index in range(1, len(key_parts)):
        prefix = "/".join(key_parts[:index])
        existing_prefix = nodes.get(prefix)
        if existing_prefix == _NODE_FILE:
            raise BundleArchiveError("backup archive has a file/directory collision")
        if existing_prefix is None:
            nodes[prefix] = _NODE_IMPLICIT_DIRECTORY
    existing = nodes.get(key)
    if directory:
        if existing == _NODE_FILE:
            raise BundleArchiveError("backup archive has a file/directory collision")
        if existing == _NODE_EXPLICIT_DIRECTORY:
            raise BundleArchiveError("backup archive contains a duplicate path")
        nodes[key] = _NODE_EXPLICIT_DIRECTORY
        kind = "dir"
    else:
        if existing == _NODE_FILE:
            raise BundleArchiveError("backup archive contains a duplicate path")
        if existing is not None:
            raise BundleArchiveError("backup archive has a file/directory collision")
        nodes[key] = _NODE_FILE
        kind = "file"
    if not directory:
        size = int(member.size)
        if size < 0 or size > MAX_ARCHIVE_FILE_BYTES:
            raise BundleArchiveError("backup archive member exceeds the per-file limit")
        budget.total_file_bytes += size
        if budget.total_file_bytes > MAX_ARCHIVE_TOTAL_FILE_BYTES:
            raise BundleArchiveError("backup archive exceeds the aggregate file limit")
        if budget.total_file_bytes > budget.expanded_payload_limit:
            raise BundleArchiveError("backup archive exceeds the expansion-ratio limit")
    return normalized, kind


# Files inside the daemon data_dir that we INCLUDE in the default
# bundle. Inbox + chunk-cache are large and not load-bearing for
# identity / chat / groups, so they're opt-in via include_files.
#
# ``state.db-wal`` / ``state.db-shm`` are deliberately ABSENT: they are a
# running SQLite's volatile shared state, not backup content. Both the
# encrypted and unencrypted paths archive a coherent online snapshot whose
# main file stands alone, so a restore can never depend on a sidecar — and
# nothing reads a live mmap-backed ``-shm`` out from under a writer.
DEFAULT_INCLUDE = {
    "state.db",
    "master.seed",
    "data-root-key.bin",
    "lockbox.salt",
    "lockbox.dek-envelope-v1",
    "ui.token",
}


@dataclass(frozen=True)
class BundleHeader:
    magic: bytes
    plaintext_len: int
    nonce: bytes
    created_ms: int

    def encode(self) -> bytes:
        return (
            self.magic
            + struct.pack(">Q", self.plaintext_len)
            + self.nonce
            + struct.pack(">Q", self.created_ms)
        )

    @classmethod
    def decode(cls, raw: bytes) -> "BundleHeader":
        if len(raw) < HEADER_LEN:
            raise ValueError(
                f"bundle header truncated: {len(raw)} < {HEADER_LEN}"
            )
        magic = raw[:8]
        if magic != BUNDLE_MAGIC:
            raise ValueError(
                f"not a One Link backup bundle (bad magic: {magic!r})"
            )
        plaintext_len = struct.unpack(">Q", raw[8:16])[0]
        nonce = raw[16:28]
        created_ms = struct.unpack(">Q", raw[28:36])[0]
        return cls(
            magic=magic,
            plaintext_len=plaintext_len,
            nonce=nonce,
            created_ms=created_ms,
        )


def _now_ms() -> int:
    import time
    return int(time.time() * 1000)


def _walk_data_dir(
    data_dir: Path,
    *,
    include_files: bool,
    extra_allowlist: Iterable[str] = (),
) -> list[tuple[Path, str]]:
    """Return list of (absolute_path, archive_name) tuples to include.

    archive_name is the path within the bundle, with forward slashes
    regardless of host OS. Symlinks, junctions/reparse points, and special
    files are excluded: a recovery export must never escape the explicitly
    selected data directory through a filesystem alias.
    """
    data_dir = Path(data_dir).resolve()
    allowed = set(DEFAULT_INCLUDE) | set(extra_allowlist)
    out: list[tuple[Path, str]] = []
    def linklike(path: Path) -> bool:
        if path.is_symlink():
            return True
        is_junction = getattr(path, "is_junction", None)
        return bool(callable(is_junction) and is_junction())

    def regular_inside(path: Path) -> bool:
        try:
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                return False
            path.resolve(strict=True).relative_to(data_dir)
            return True
        except (OSError, ValueError):
            return False

    # Top-level allowlisted files first.
    for name in sorted(allowed):
        p = data_dir / name
        if regular_inside(p):
            out.append((p, name))
    if include_files:
        # Inbox subtree: include user-received files + the chunk
        # cache. NOT recursive into other subtrees we don't ship.
        inbox = data_dir / "inbox"
        if inbox.is_dir() and not linklike(inbox):
            for current_raw, dirnames, filenames in os.walk(
                inbox,
                topdown=True,
                followlinks=False,
            ):
                current = Path(current_raw)
                safe_dirs: list[str] = []
                for dirname in sorted(dirnames):
                    child = current / dirname
                    try:
                        child.resolve(strict=True).relative_to(inbox)
                    except (OSError, ValueError):
                        continue
                    if not linklike(child):
                        safe_dirs.append(dirname)
                dirnames[:] = safe_dirs
                for filename in sorted(filenames):
                    entry = current / filename
                    if regular_inside(entry):
                        rel = entry.relative_to(data_dir).as_posix()
                        out.append((entry, rel))
    return out


def _build_plaintext_archive(
    data_dir: Path,
    *,
    include_files: bool,
    extra_allowlist: Iterable[str] = (),
    member_overrides: Mapping[str, Path] | None = None,
    excluded_names: Iterable[str] = (),
) -> bytes:
    """Compose the gzip-compressed tar plaintext."""
    members = _walk_data_dir(
        data_dir,
        include_files=include_files,
        extra_allowlist=extra_allowlist,
    )
    excluded = set(excluded_names)
    overrides = {
        str(name): Path(path)
        for name, path in (member_overrides or {}).items()
    }
    selected: dict[str, Path] = {
        archive_name: overrides.get(archive_name, path)
        for path, archive_name in members
        if archive_name not in excluded
    }
    # Trusted, caller-created virtual members (the coherent state snapshot and
    # its seed-wrapped key) need not exist in the live data directory.  They
    # still pass exactly the same archive-path, lstat, no-follow open, size,
    # and read-stability gates as ordinary members below.
    for archive_name, path in overrides.items():
        if archive_name not in excluded:
            selected[archive_name] = path
    members = [(path, name) for name, path in sorted(selected.items())]
    buf = BytesIO()
    member_evidence: list[tuple[Path, str, os.stat_result]] = []
    build_budget = _ArchiveBudget(
        compressed_bytes=0,
        expanded_payload_limit=MAX_ARCHIVE_TOTAL_FILE_BYTES,
    )
    # The metadata member is always first.  Pre-account it for the member
    # ceiling and reserve its portable path in the collision map.
    manifest_probe = tarfile.TarInfo(name="MANIFEST")
    _validate_archive_member(manifest_probe, build_budget)
    for p, archive_name in members:
        info = p.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise OSError(f"backup member changed type: {archive_name}")
        normalized_name, _kind = _validate_archive_member(
            tarfile.TarInfo(name=archive_name),
            build_budget,
        )
        # TarInfo defaults to size zero, so account the observed file size
        # before any archive bytes are produced.
        if info.st_size < 0 or info.st_size > MAX_ARCHIVE_FILE_BYTES:
            raise ValueError(
                f"backup member exceeds the per-file limit: {archive_name}"
            )
        build_budget.total_file_bytes += int(info.st_size)
        if build_budget.total_file_bytes > MAX_ARCHIVE_TOTAL_FILE_BYTES:
            raise ValueError("backup payload exceeds the aggregate file limit")
        member_evidence.append((p, normalized_name, info))
    # mtime=0 + uname/gname empty makes the tar deterministic
    # given the same input set; useful for any future
    # reproducible-bundle property tests.
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode="w") as tf:
            # Manifest first so a partial-decode reader can still
            # discover what's in the bundle.
            manifest_text = "\n".join(
                f"{archive_name}\t{info.st_size}"
                for _p, archive_name, info in member_evidence
            ) + "\n"
            manifest_bytes = manifest_text.encode("utf-8")
            if len(manifest_bytes) > MAX_ARCHIVE_MANIFEST_BYTES:
                raise ValueError("backup manifest exceeds the metadata limit")
            declared_archive_bytes = build_budget.total_file_bytes + len(manifest_bytes)
            if declared_archive_bytes > MAX_ARCHIVE_TOTAL_FILE_BYTES:
                raise ValueError("backup payload exceeds the aggregate file limit")
            manifest = tarfile.TarInfo(name="MANIFEST")
            manifest.size = len(manifest_bytes)
            manifest.mtime = 0
            tf.addfile(manifest, BytesIO(manifest_bytes))
            for p, archive_name, expected in member_evidence:
                ti = tarfile.TarInfo(name=archive_name)
                ti.size = expected.st_size
                ti.mtime = 0
                ti.uid = 0
                ti.gid = 0
                ti.uname = ""
                ti.gname = ""
                flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
                flags |= int(getattr(os, "O_NOFOLLOW", 0))
                fd = os.open(p, flags)
                try:
                    opened = os.fstat(fd)
                except BaseException:
                    os.close(fd)
                    raise
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or opened.st_dev != expected.st_dev
                    or opened.st_ino != expected.st_ino
                    or opened.st_size != expected.st_size
                    or opened.st_mtime_ns != expected.st_mtime_ns
                ):
                    os.close(fd)
                    raise OSError(f"backup member changed while opening: {archive_name}")
                with os.fdopen(fd, "rb", closefd=True) as fh:
                    tf.addfile(ti, fh)
                    after = os.fstat(fh.fileno())
                    if (
                        after.st_size != opened.st_size
                        or after.st_mtime_ns != opened.st_mtime_ns
                    ):
                        raise OSError(
                            f"backup member changed while reading: {archive_name}"
                        )
    plaintext = buf.getvalue()
    if len(plaintext) > MAX_BUNDLE_COMPRESSED_BYTES:
        raise ValueError(
            "backup compressed payload exceeds the 256 MiB restore limit"
        )
    if declared_archive_bytes > _expanded_payload_limit(len(plaintext)):
        raise ValueError("backup payload exceeds the restore expansion-ratio limit")
    return plaintext


def create_bundle(
    *,
    seed: bytes,
    data_dir: Path,
    include_files: bool = False,
    extra_allowlist: Iterable[str] = (),
    state_passphrase: str | None = None,
) -> bytes:
    """Encode a portable encrypted backup; see ``_create_bundle_in_transaction``.

    The whole export runs inside the LockBox envelope transaction: the bundle
    archives the recovery envelope, the data-root key and state.db together,
    so no data-key change (a passphrase migration, a first passphrase boot)
    may interleave with it.  Other holders wait for it, boundedly.
    """
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    resolved = Path(data_dir).resolve()
    if not resolved.is_dir():
        raise FileNotFoundError(f"data_dir does not exist: {resolved}")
    from one_link import lockbox

    with lockbox.envelope_transaction(resolved, purpose="backup export"):
        return _create_bundle_in_transaction(
            seed=seed,
            data_dir=resolved,
            include_files=include_files,
            extra_allowlist=extra_allowlist,
            state_passphrase=state_passphrase,
        )


def _create_bundle_in_transaction(
    *,
    seed: bytes,
    data_dir: Path,
    include_files: bool = False,
    extra_allowlist: Iterable[str] = (),
    state_passphrase: str | None = None,
) -> bytes:
    """Encode a portable encrypted backup of the daemon's state.

    Args:
      seed: the 32-byte master seed (e.g. from
        master_seed.load_seed). The bundle key is derived from
        this; the seed itself never appears in the bundle output.
      data_dir: the daemon's config / data dir to back up.
      include_files: when True also archive everything under
        ``inbox/``. Default False because inboxes can be GB-sized;
        identity + chat history + groups are in state.db which is
        always included.
      extra_allowlist: additional top-level filenames in data_dir
        to include. Used when callers add new persistent state
        files that aren't in the canonical DEFAULT_INCLUDE set.
      state_passphrase: optional explicit SQLCipher authority. Production
        callers normally omit it; the active env/keyring/private-local
        authority is discovered fail-closed. It exists for offline tooling
        whose source data directory is not the active ``ONE_LINK_HOME``.

    Returns the encoded ``.olbak`` bytes ready to write to disk.
    """
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    data_dir = Path(data_dir).resolve()
    if not data_dir.is_dir():
        raise FileNotFoundError(f"data_dir does not exist: {data_dir}")

    # Before walking the archive, atomically migrate legacy direct-scrypt
    # application keys to the portable dual-wrapped DEK envelope.  This keeps
    # existing ciphertext byte-identical while proving the bundle seed can
    # recover it.  Silent-DRK installs return False and create no artifact.
    from one_link import lockbox

    lockbox.ensure_recovery_envelope_for_backup(data_dir, seed=bytes(seed))

    # A SQLCipher main file copied beside independently changing WAL/SHM files
    # is not a database snapshot.  Build a coherent online snapshot instead,
    # encrypt its passphrase under a seed-domain-separated key, and archive no
    # WAL sidecars.  The plaintext ``state.key`` is deliberately neither in
    # DEFAULT_INCLUDE nor any generated member.
    overrides: dict[str, Path] = {}
    excluded: set[str] = set()
    extra_names: set[str] = set(extra_allowlist)
    temporary_owner: tempfile.TemporaryDirectory[str] | None = None
    try:
        state_path = data_dir / "state.db"
        if state_path.exists():
            from one_link import keychain, state_encryption

            db_state = state_encryption.detect_db_state(state_path)
            explicit_key = state_passphrase is not None
            portable_required = db_state == "encrypted" and (
                explicit_key or not keychain._disabled()
            )
            if portable_required:
                active_key = state_passphrase
                if active_key is None:
                    active_key = keychain.get_passphrase()
                if not isinstance(active_key, str) or not active_key:
                    raise ValueError(
                        "encrypted state.db has no recoverable SQLCipher authority; "
                        "refusing to create an unusable backup"
                    )
                observed = state_path.lstat()
                if state_path.is_symlink() or not stat.S_ISREG(observed.st_mode):
                    raise ValueError(
                        "encrypted state.db must be a regular non-symlink file"
                    )
                try:
                    state_path.resolve(strict=True).relative_to(data_dir)
                except (OSError, ValueError) as exc:
                    raise ValueError("encrypted state.db escapes its data directory") from exc

                temporary_owner = tempfile.TemporaryDirectory(
                    prefix=".olbak-state-",
                    dir=str(data_dir.parent),
                )
                temporary_root = Path(temporary_owner.name)
                with contextlib.suppress(OSError):
                    os.chmod(temporary_root, 0o700)
                snapshot_path = temporary_root / "state.db"
                state_encryption.create_encrypted_snapshot(
                    source_path=state_path,
                    source_passphrase=active_key,
                    destination_path=snapshot_path,
                )
                artifact_path = temporary_root / keychain.RECOVERY_KEY_FILENAME
                artifact = keychain.seal_state_passphrase_for_recovery(
                    seed=bytes(seed),
                    passphrase=active_key,
                )
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                flags |= int(getattr(os, "O_BINARY", 0))
                flags |= int(getattr(os, "O_NOFOLLOW", 0))
                fd = os.open(str(artifact_path), flags, 0o600)
                try:
                    view = memoryview(artifact)
                    written = 0
                    while written < len(view):
                        count = os.write(fd, view[written:])
                        if count <= 0:
                            raise OSError("short write while staging recovery key")
                        written += count
                    os.fsync(fd)
                finally:
                    os.close(fd)
                if os.name != "nt":
                    os.chmod(artifact_path, 0o600)
                overrides = {
                    "state.db": snapshot_path,
                    keychain.RECOVERY_KEY_FILENAME: artifact_path,
                }
                excluded = {"state.db-wal", "state.db-shm"}
            elif db_state == "plaintext":
                # An unencrypted database earns the SAME coherence guarantee:
                # a main file archived beside its independently changing
                # sidecars can restore torn state. The online-backup snapshot
                # is self-contained, so no sidecar is archived at all.
                temporary_owner = tempfile.TemporaryDirectory(
                    prefix=".olbak-state-",
                    dir=str(data_dir.parent),
                )
                temporary_root = Path(temporary_owner.name)
                with contextlib.suppress(OSError):
                    os.chmod(temporary_root, 0o700)
                snapshot_path = temporary_root / "state.db"
                try:
                    state_encryption.create_plaintext_snapshot(
                        source_path=state_path,
                        destination_path=snapshot_path,
                    )
                except Exception as exc:
                    # A file can carry SQLite's header magic and still be
                    # unopenable: a truncated or corrupted database, or a
                    # fixture. Refusing to back up then would withhold the
                    # user's identity, seed, and keys over a damaged database
                    # -- the moment a backup matters most. Preserve the raw
                    # bytes (sidecars included, so nothing committed is lost)
                    # and let restore/forensics deal with the damage.
                    log.warning(
                        "state.db could not be snapshotted (%s: %s); archiving "
                        "the raw database and its sidecars instead",
                        type(exc).__name__,
                        exc,
                    )
                    temporary_owner.cleanup()
                    temporary_owner = None
                    extra_names = set(extra_names) | {
                        "state.db-wal",
                        "state.db-shm",
                    }
                else:
                    overrides = {"state.db": snapshot_path}
                    excluded = {"state.db-wal", "state.db-shm"}
            else:
                # Encrypted with no recoverable authority (keyring disabled and
                # no explicit key): a coherent snapshot is impossible without
                # the key, and dropping the WAL would silently discard
                # committed transactions that were never checkpointed. Archive
                # the sidecars alongside the main file, exactly as before, and
                # let the restore path reassemble them.
                extra_names = set(extra_names) | {"state.db-wal", "state.db-shm"}

        plaintext = _build_plaintext_archive(
            data_dir,
            include_files=include_files,
            extra_allowlist=extra_names,
            member_overrides=overrides,
            excluded_names=excluded,
        )
    finally:
        if temporary_owner is not None:
            temporary_owner.cleanup()

    from one_link.master_seed import derive_backup_key
    key = derive_backup_key(bytes(seed))
    nonce = secrets.token_bytes(NONCE_LEN)
    header = BundleHeader(
        magic=BUNDLE_MAGIC,
        plaintext_len=len(plaintext),
        nonce=nonce,
        created_ms=_now_ms(),
    )
    aead = AESGCM(key)
    aad = header.encode()
    ct_with_tag = aead.encrypt(nonce, plaintext, aad)
    return aad + ct_with_tag


def open_bundle(
    *,
    seed: bytes,
    bundle_bytes: bytes | bytearray | memoryview,
) -> tuple[BundleHeader, bytes]:
    """Decrypt a bundle, return (header, plaintext archive bytes).

    Raises ValueError on header tamper, AEAD-tag mismatch, or
    truncated input. The plaintext is the gzip-tar archive; pass
    to ``extract_bundle_to_dir`` to write it out.
    """
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    if not isinstance(bundle_bytes, (bytes, bytearray, memoryview)):
        raise ValueError("bundle_bytes must be a byte buffer")
    if len(bundle_bytes) < HEADER_LEN + 16:  # +16 for AEAD tag
        raise ValueError("bundle too short to be valid")
    max_encoded_bytes = HEADER_LEN + MAX_BUNDLE_COMPRESSED_BYTES + 16
    if len(bundle_bytes) > max_encoded_bytes:
        raise ValueError("bundle exceeds the 256 MiB compressed-payload limit")
    bundle_view = memoryview(bundle_bytes)
    header = BundleHeader.decode(bytes(bundle_view[:HEADER_LEN]))
    if header.plaintext_len > MAX_BUNDLE_COMPRESSED_BYTES:
        bundle_view.release()
        raise ValueError("bundle compressed payload exceeds the 256 MiB limit")
    ciphertext_len = len(bundle_view) - HEADER_LEN - 16
    if header.plaintext_len != ciphertext_len:
        raise ValueError(
            "plaintext-length header does not match ciphertext length"
        )
    aad = header.encode()
    # Keep the ciphertext as a zero-copy view. For a 256 MiB upload, slicing a
    # bytes/bytearray here used to allocate another 256 MiB immediately before
    # AES-GCM allocated the plaintext, multiplying peak restore memory.
    ct_with_tag = bundle_view[HEADER_LEN:]
    from one_link.master_seed import derive_backup_key
    key = derive_backup_key(bytes(seed))
    aead = AESGCM(key)
    try:
        plaintext = aead.decrypt(header.nonce, ct_with_tag, aad)
    except Exception as e:
        raise ValueError(
            f"bundle decrypt failed (wrong seed or tampered file): {e}"
        ) from None
    finally:
        ct_with_tag.release()
        bundle_view.release()
    if len(plaintext) != header.plaintext_len:
        raise ValueError(
            f"plaintext-length header lies: claimed "
            f"{header.plaintext_len}, got {len(plaintext)}"
        )
    return header, plaintext


def _new_archive_budget(plaintext: bytes) -> _ArchiveBudget:
    if not isinstance(plaintext, bytes):
        raise BundleArchiveError("backup archive plaintext must be bytes")
    if not plaintext.startswith(b"\x1f\x8b"):
        raise BundleArchiveError("backup archive is not gzip-compressed")
    if len(plaintext) > MAX_BUNDLE_COMPRESSED_BYTES:
        raise BundleArchiveError(
            "backup archive exceeds the 256 MiB compressed-payload limit"
        )
    return _ArchiveBudget(
        compressed_bytes=len(plaintext),
        expanded_payload_limit=_expanded_payload_limit(len(plaintext)),
    )


def _copy_archive_member(
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
    *,
    destination: BinaryIO | None,
    budget: _ArchiveBudget,
) -> bytes | None:
    source = archive.extractfile(member)
    if source is None:
        raise BundleArchiveError(
            f"failed to read archive entry {member.name!r}"
        )
    capture = BytesIO() if destination is None and member.name == "MANIFEST" else None
    remaining = int(member.size)
    copied = 0
    try:
        while remaining:
            chunk = source.read(min(_ARCHIVE_COPY_CHUNK_BYTES, remaining))
            if not chunk:
                raise BundleArchiveError(
                    f"archive entry is truncated: {member.name!r}"
                )
            copied += len(chunk)
            remaining -= len(chunk)
            budget.actual_file_bytes += len(chunk)
            if budget.actual_file_bytes > budget.total_file_bytes:
                raise BundleArchiveError(
                    "backup archive emitted more bytes than its declarations"
                )
            if destination is not None:
                destination.write(chunk)
            elif capture is not None:
                capture.write(chunk)
        if source.read(1):
            raise BundleArchiveError(
                f"archive entry exceeds its declared size: {member.name!r}"
            )
    finally:
        source.close()
    if copied != int(member.size):
        raise BundleArchiveError(
            f"archive entry size mismatch: {member.name!r}"
        )
    return capture.getvalue() if capture is not None else None


def _parse_manifest(payload: bytes) -> tuple[list[str], array]:
    if len(payload) > MAX_ARCHIVE_MANIFEST_BYTES:
        raise BundleArchiveError("backup manifest exceeds the metadata limit")
    try:
        text = payload.decode("utf-8", "strict")
    except UnicodeError as exc:
        raise BundleArchiveError("backup manifest is not valid UTF-8") from exc
    if "\r" in text or (text and not text.endswith("\n")):
        raise BundleArchiveError("backup manifest has an ambiguous line encoding")
    names: list[str] = []
    sizes = array("Q")
    seen: set[str] = set()
    for line in text.split("\n"):
        if not line:
            continue
        if line.count("\t") != 1:
            raise BundleArchiveError("backup manifest row is malformed")
        raw_name, raw_size = line.split("\t", 1)
        if not raw_size.isascii() or not raw_size.isdecimal():
            raise BundleArchiveError("backup manifest size is malformed")
        normalized, key = _validate_archive_path(raw_name, directory=False)
        if key == "manifest" or key in seen:
            raise BundleArchiveError("backup manifest contains a duplicate path")
        size = int(raw_size)
        if size > MAX_ARCHIVE_FILE_BYTES:
            raise BundleArchiveError("backup manifest member exceeds the per-file limit")
        seen.add(key)
        names.append(normalized)
        sizes.append(size)
        if len(names) >= MAX_ARCHIVE_MEMBERS:
            raise BundleArchiveError("backup manifest contains too many rows")
    return names, sizes


def _process_plaintext_archive(
    *,
    plaintext: bytes,
    staging: Path | None,
    initial_free_bytes: int | None,
    disk_reserve_bytes: int,
) -> list[str]:
    """Validate one archive and optionally stream its files into staging."""

    budget = _new_archive_budget(plaintext)
    stream_limit = (
        budget.expanded_payload_limit + MAX_ARCHIVE_METADATA_ALLOWANCE_BYTES
    )
    raw = _StrictGzipReader(plaintext, max_output_bytes=stream_limit)
    expected_names: list[str] | None = None
    expected_sizes: array | None = None
    expected_index = 0
    try:
        with io.BufferedReader(raw, buffer_size=_GZIP_INPUT_CHUNK_BYTES) as expanded:
            try:
                with tarfile.open(
                    fileobj=expanded,
                    mode="r|",
                    bufsize=tarfile.BLOCKSIZE,
                    tarinfo=_BoundedTarInfo,
                ) as archive:
                    while True:
                        member = archive.next()
                        if member is None:
                            break
                        try:
                            normalized, kind = _validate_archive_member(member, budget)
                            is_manifest = normalized == "MANIFEST"
                            if budget.member_count == 1 and (
                                not is_manifest or kind != "file"
                            ):
                                raise BundleArchiveError(
                                    "backup archive must begin with a regular MANIFEST"
                                )
                            if is_manifest and budget.member_count != 1:
                                raise BundleArchiveError(
                                    "backup archive contains an ambiguous MANIFEST"
                                )
                            if kind == "dir":
                                if staging is not None:
                                    (staging / normalized).mkdir(
                                        mode=0o700,
                                        parents=True,
                                        exist_ok=True,
                                    )
                                continue
                            if initial_free_bytes is not None and (
                                budget.total_file_bytes
                                > max(0, initial_free_bytes - disk_reserve_bytes)
                            ):
                                raise BundleArchiveError(
                                    "insufficient free space for backup restore policy"
                                )
                            if is_manifest:
                                if int(member.size) > MAX_ARCHIVE_MANIFEST_BYTES:
                                    raise BundleArchiveError(
                                        "backup manifest exceeds the metadata limit"
                                    )
                                manifest_payload = _copy_archive_member(
                                    archive,
                                    member,
                                    destination=None,
                                    budget=budget,
                                )
                                assert manifest_payload is not None
                                expected_names, expected_sizes = _parse_manifest(
                                    manifest_payload
                                )
                                continue
                            if expected_names is None or expected_sizes is None:
                                raise BundleArchiveError("backup archive has no MANIFEST")
                            if (
                                expected_index >= len(expected_names)
                                or normalized != expected_names[expected_index]
                                or int(member.size) != expected_sizes[expected_index]
                            ):
                                raise BundleArchiveError(
                                    "backup archive contents do not match its MANIFEST"
                                )
                            destination: BinaryIO | None = None
                            try:
                                if staging is not None:
                                    out_path = staging / normalized
                                    out_path.parent.mkdir(
                                        mode=0o700,
                                        parents=True,
                                        exist_ok=True,
                                    )
                                    destination = out_path.open("xb")
                                _copy_archive_member(
                                    archive,
                                    member,
                                    destination=destination,
                                    budget=budget,
                                )
                            finally:
                                if destination is not None:
                                    destination.close()
                            expected_index += 1
                        finally:
                            # ``TarFile.next()`` retains every TarInfo in
                            # ``members`` even in stream mode.  At the 100k
                            # policy ceiling that hidden cache alone can exceed
                            # hundreds of MiB.  The current member remains live
                            # in this local variable, so discarding the cache
                            # after each fully processed record is safe.
                            cast(Any, archive).members.clear()
                # Tar stops at its logical end marker. Drain the bounded gzip
                # stream to verify its footer and reject hidden tar payload.
                while True:
                    trailing = expanded.read(_ARCHIVE_COPY_CHUNK_BYTES)
                    if not trailing:
                        break
                    if any(trailing):
                        raise BundleArchiveError(
                            "backup archive has non-zero data after the tar end marker"
                        )
            except BundleArchiveError:
                raise
            except (EOFError, tarfile.TarError, zlib.error) as exc:
                raise BundleArchiveError("backup archive is malformed") from exc
    finally:
        raw.close()
    if expected_names is None or expected_sizes is None:
        raise BundleArchiveError("backup archive has no MANIFEST")
    if expected_index != len(expected_names):
        raise BundleArchiveError(
            "backup archive contents do not match its MANIFEST"
        )
    if budget.actual_file_bytes != budget.total_file_bytes:
        raise BundleArchiveError(
            "backup archive streamed byte count does not match its declarations"
        )
    return expected_names


def inspect_bundle_archive(*, plaintext: bytes) -> list[str]:
    """Fully validate a decrypted archive without writing to disk."""

    return _process_plaintext_archive(
        plaintext=plaintext,
        staging=None,
        initial_free_bytes=None,
        disk_reserve_bytes=0,
    )


def _sync_regular_file(path: Path) -> None:
    # Windows requires a writable descriptor for ``FlushFileBuffers`` through
    # ``os.fsync``; these are newly restored files owned by this process.
    with path.open("r+b") as handle:
        os.fsync(handle.fileno())


def _sync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    flags = os.O_RDONLY | int(getattr(os, "O_DIRECTORY", 0))
    fd = os.open(path, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _same_file_identity(current: os.stat_result, expected: os.stat_result) -> bool:
    return (
        stat.S_ISREG(current.st_mode)
        and current.st_dev == expected.st_dev
        and current.st_ino == expected.st_ino
        and current.st_size == expected.st_size
        and current.st_mtime_ns == expected.st_mtime_ns
    )


def _promote_staged_files(
    *,
    staging: Path,
    target_dir: Path,
    written: list[str],
    overwrite: bool,
) -> None:
    """Promote staged files with rollback for every observable failure.

    Each rename/link is atomic, but a multi-file filesystem transaction does
    not exist portably.  Existing files therefore move into a private rollback
    tree first.  If any later operation fails, newly promoted files are removed
    by verified inode identity and originals are restored before the error is
    returned.  This is process-failure atomic; abrupt power loss between
    renames remains a filesystem-level recovery boundary.
    """

    plan: list[
        tuple[Path, Path, os.stat_result, os.stat_result | None]
    ] = []
    for name in written:
        relative = Path(*name.split("/"))
        source = staging / relative
        source_info = source.lstat()
        if source.is_symlink() or not stat.S_ISREG(source_info.st_mode):
            raise BundleArchiveError(f"unsafe staged backup member: {name!r}")
        try:
            source.resolve(strict=True).relative_to(staging)
        except (OSError, ValueError) as exc:
            raise BundleArchiveError(f"staged backup member escaped: {name!r}") from exc
        destination = target_dir / relative
        parent = target_dir
        for part in relative.parts[:-1]:
            parent /= part
            if os.path.lexists(parent):
                if parent.is_symlink() or not parent.is_dir():
                    raise BundleArchiveError(
                        f"unsafe restore target ancestor: {parent}"
                    )
                try:
                    parent.resolve(strict=True).relative_to(target_dir)
                except (OSError, ValueError) as exc:
                    raise BundleArchiveError(
                        f"restore target ancestor escapes data dir: {parent}"
                    ) from exc
        existing: os.stat_result | None = None
        if os.path.lexists(destination):
            existing = destination.lstat()
            if destination.is_symlink() or not stat.S_ISREG(existing.st_mode):
                raise BundleArchiveError(
                    f"unsafe existing restore target: {destination}"
                )
            if not overwrite:
                raise FileExistsError(
                    f"target file already exists: {destination}"
                )
        plan.append((source, destination, source_info, existing))

    rollback = target_dir / f".bundle-rollback.{secrets.token_hex(16)}"
    rollback.mkdir(mode=0o700, parents=False, exist_ok=False)
    backed_up: list[tuple[Path, Path, os.stat_result]] = []
    promoted: list[tuple[Path, os.stat_result]] = []
    created_dirs: list[Path] = []
    failure: BaseException | None = None
    rollback_failures: list[str] = []
    try:
        for _source, destination, _source_info, existing in plan:
            if existing is None:
                continue
            backup = rollback / destination.relative_to(target_dir)
            backup.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.replace(destination, backup)
            backed_up.append((destination, backup, existing))
            moved = backup.lstat()
            if not _same_file_identity(moved, existing):
                raise BundleArchiveError(
                    f"restore target changed while entering rollback: {destination}"
                )
            backed_up[-1] = (destination, backup, moved)

        for source, destination, expected_source, _existing in plan:
            parent = target_dir
            for part in destination.relative_to(target_dir).parts[:-1]:
                parent /= part
                if not os.path.lexists(parent):
                    parent.mkdir(mode=0o700)
                    created_dirs.append(parent)
            if os.path.lexists(destination):
                raise BundleArchiveError(
                    f"restore target appeared during promotion: {destination}"
                )
            if not _same_file_identity(source.lstat(), expected_source):
                raise BundleArchiveError(
                    f"staged backup member changed before promotion: {source}"
                )
            # A hard link is an atomic O_EXCL-like publish primitive on the
            # same filesystem. It prevents both modes from clobbering a target
            # which races into existence after the check above.
            os.link(source, destination, follow_symlinks=False)
            promoted.append((destination, expected_source))
            promoted_info = destination.lstat()
            if not _same_file_identity(promoted_info, expected_source):
                raise BundleArchiveError(
                    f"promoted backup member identity mismatch: {destination}"
                )
            promoted[-1] = (destination, promoted_info)
            _sync_regular_file(destination)
            source.unlink()
        for directory in {
            destination.parent
            for _source, destination, _source_info, _existing in plan
        }:
            _sync_directory(directory)
        _sync_directory(target_dir)
    except BaseException as exc:
        failure = exc
        for destination, expected in reversed(promoted):
            try:
                current = destination.lstat()
                if not _same_file_identity(current, expected):
                    raise OSError("promoted target identity changed")
                destination.unlink()
            except FileNotFoundError:
                pass
            except OSError as rollback_exc:
                rollback_failures.append(f"remove {destination}: {rollback_exc}")
        for destination, backup, expected in reversed(backed_up):
            try:
                if os.path.lexists(destination):
                    raise OSError("destination occupied during rollback")
                current = backup.lstat()
                if not _same_file_identity(current, expected):
                    raise OSError("rollback source identity changed")
                destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                os.replace(backup, destination)
            except OSError as rollback_exc:
                rollback_failures.append(f"restore {destination}: {rollback_exc}")
        for directory in reversed(created_dirs):
            try:
                directory.rmdir()
            except OSError:
                pass
        with contextlib.suppress(OSError):
            _sync_directory(target_dir)
    finally:
        # Never delete the only surviving original when rollback itself failed.
        # The private tree is intentionally retained and its path is surfaced
        # below for operator recovery. A clean rollback or successful commit
        # has no live data left that must be preserved.
        if not rollback_failures:
            shutil.rmtree(rollback, ignore_errors=True)
    if failure is not None:
        if rollback_failures:
            detail = "; ".join(rollback_failures[:3])
            raise BundleArchiveError(
                "backup promotion failed and rollback was incomplete; "
                f"preserved originals under {rollback}: {detail}"
            ) from failure
        raise failure


def extract_bundle_to_dir(
    *,
    plaintext: bytes,
    target_dir: Path,
    overwrite: bool = False,
) -> list[str]:
    """Unpack a decrypted bundle's plaintext archive into target_dir.

    Returns the list of archive names that were written. Refuses to overwrite
    existing files unless ``overwrite=True`` and validates everything in a
    private staging directory before promotion.

    Path and resource safety are fail-closed: paths must be portable and
    collision-free; links, special files, duplicate/case aliases, sparse
    members, malformed/trailing gzip or tar data, oversized metadata, and
    archives outside the finite policy documented above are rejected. File
    contents stream in bounded chunks rather than being read into memory.
    """
    target_dir = Path(target_dir).resolve()
    target_dir.mkdir(parents=True, exist_ok=True)
    usage = shutil.disk_usage(target_dir)
    disk_reserve = max(
        BUNDLE_RESTORE_MIN_FREE_RESERVE_BYTES,
        int(usage.total * BUNDLE_RESTORE_FREE_RESERVE_RATIO),
    )
    # Stage to a sibling temp dir so a partial extract on error
    # doesn't poison the daemon's existing data.
    staging = target_dir / f".bundle-import.{secrets.token_hex(16)}"
    staging.mkdir(mode=0o700, parents=True, exist_ok=False)
    try:
        written = _process_plaintext_archive(
            plaintext=plaintext,
            staging=staging,
            initial_free_bytes=int(usage.free),
            disk_reserve_bytes=disk_reserve,
        )
        _promote_staged_files(
            staging=staging,
            target_dir=target_dir,
            written=written,
            overwrite=overwrite,
        )
    finally:
        # Clean up any partial-staging files; if extraction
        # succeeded, the os.replace calls above moved everything
        # out, leaving an empty tree to remove.
        shutil.rmtree(staging, ignore_errors=True)
    return written


# ── Convenience: round-trip via base64 / file ────────────────────────


def read_bundle_file_bounded(bundle_path: Path) -> bytes:
    """Read a regular bundle after pre-open and post-read identity checks."""

    path = Path(bundle_path)
    try:
        before = path.lstat()
    except OSError as exc:
        raise ValueError(f"cannot stat backup bundle: {exc}") from exc
    if path.is_symlink() or not stat.S_ISREG(before.st_mode):
        raise ValueError("backup bundle path must be a regular non-symlink file")
    max_encoded = HEADER_LEN + MAX_BUNDLE_COMPRESSED_BYTES + 16
    if before.st_size > max_encoded:
        raise ValueError("bundle exceeds the 256 MiB compressed-payload limit")
    flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"cannot open backup bundle safely: {exc}") from exc
    try:
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != before.st_dev
            or opened.st_ino != before.st_ino
            or opened.st_size != before.st_size
        ):
            raise ValueError("backup bundle changed identity while opening")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            # Read only the size established by the opened descriptor, plus
            # one byte to detect a concurrent append.  Passing the global
            # 256 MiB ceiling to BufferedReader.read() made even a tiny bundle
            # transiently reserve a 256 MiB native buffer on Windows.
            payload = handle.read(int(opened.st_size) + 1)
        after = os.fstat(fd)
        if len(payload) > max_encoded:
            raise ValueError("bundle exceeds the 256 MiB compressed-payload limit")
        if len(payload) != opened.st_size or (
            after.st_dev != opened.st_dev
            or after.st_ino != opened.st_ino
            or after.st_size != opened.st_size
            or after.st_mtime_ns != opened.st_mtime_ns
        ):
            raise ValueError("backup bundle changed while it was being read")
        return payload
    finally:
        os.close(fd)


def create_bundle_to_file(
    *,
    seed: bytes,
    data_dir: Path,
    out_path: Path,
    include_files: bool = False,
    state_passphrase: str | None = None,
) -> int:
    """Create a bundle + write to disk. Returns bytes written."""
    bundle = create_bundle(
        seed=seed,
        data_dir=data_dir,
        include_files=include_files,
        state_passphrase=state_passphrase,
    )
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bundle)
    return len(bundle)


def restore_bundle_from_file(
    *,
    seed: bytes,
    bundle_path: Path,
    target_dir: Path,
    overwrite: bool = False,
) -> tuple[BundleHeader, list[str]]:
    """Read + decrypt + extract a .olbak file."""
    bundle_bytes = read_bundle_file_bounded(Path(bundle_path))
    header, plaintext = open_bundle(
        seed=seed, bundle_bytes=bundle_bytes,
    )
    written = extract_bundle_to_dir(
        plaintext=plaintext,
        target_dir=Path(target_dir),
        overwrite=overwrite,
    )
    return header, written
