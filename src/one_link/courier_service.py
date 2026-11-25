"""Offline courier use cases through explicit cache, index and identity ports.

This service owns export/import/assembly ordering. It has no HTTP dependency,
does not discover drives, and cannot connect to a peer or mutate daemon state.
The caller chooses authorization and translates typed failures to its transport.
"""

from __future__ import annotations

import contextlib
import os
import secrets
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Protocol, TypedDict

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.courier_bundle import (
    CourierBundleError,
    assemble_courier_chunks,
    decode_bundle_b64,
    encode_bundle_b64,
    export_courier_bundle,
    import_courier_bundle,
)
from one_link.courier_files import CourierDestinationRejected, CourierFileCatalog
from one_link.courier_ledger import CourierReplayLedger


class CourierFailure(Enum):
    INVALID = "invalid"
    MISSING = "missing"
    CONFLICT = "conflict"
    UNAVAILABLE = "unavailable"
    FAILED = "failed"


class CourierOperationError(Exception):
    def __init__(
        self,
        kind: CourierFailure,
        code: str,
        message: str,
        **details: object,
    ) -> None:
        super().__init__(message)
        self.kind = kind
        self.code = code
        self.details = details


class CourierTransfer(Protocol):
    @property
    def blob_hash(self) -> str | None: ...

    @property
    def name(self) -> str: ...


class CourierChunkIndex(Protocol):
    """The two read-only state queries courier export and assembly need."""

    def get_transfer(self, id: str) -> CourierTransfer | None: ...

    def list_chunks_for_blob(self, blob_hash: str) -> list[dict]: ...


class StoreCourierChunk(Protocol):
    def __call__(
        self,
        chunk_hash: str,
        data: bytes,
        *,
        blob_hash: str | None = None,
        chunk_index: int | None = None,
    ) -> None: ...


@dataclass(frozen=True)
class CourierIdentity:
    fingerprint: str
    signing_key: Ed25519PrivateKey


class CourierExportPayload(TypedDict):
    bundle_b64: str
    key_token: str
    manifest: dict[str, object]
    bundle_bytes: int
    chunk_count: object
    total_bytes: object


class CourierImportPayload(TypedDict):
    manifest: dict[str, object]
    stored_chunks: int
    chunk_count: object
    total_bytes: object


class CourierStagedPayload(TypedDict):
    path: str
    name: str
    outbox_dir: str
    key_token: str
    manifest: dict[str, object]
    bundle_bytes: int


class CourierAssemblyPayload(TypedDict):
    path: str
    name: str
    blob_hash: str
    bytes: int
    chunks: int


class CourierService:
    def __init__(
        self,
        *,
        ledger: CourierReplayLedger,
        files: CourierFileCatalog,
        identity: CourierIdentity,
        index: CourierChunkIndex | None,
        read_chunk: Callable[[str], bytes | None],
        store_chunk: StoreCourierChunk,
        valid_hash: Callable[[str], bool],
        safe_name: Callable[[object], str],
        inbox_path: Callable[[str, str], Path],
    ) -> None:
        self.ledger = ledger
        self.files = files
        self.identity = identity
        self.index = index
        self.read_chunk = read_chunk
        self.store_chunk = store_chunk
        self.valid_hash = valid_hash
        self.safe_name = safe_name
        self.inbox_path = inbox_path

    def export(self, data: Mapping[str, Any]) -> CourierExportPayload:
        raw_chunks = data.get("chunks")
        blob_hash = str(data.get("blob_hash") or "").strip().lower()
        name = str(data.get("name") or "").strip() or None
        if (not isinstance(raw_chunks, list) or not raw_chunks) and self.index is not None:
            transfer_id = str(data.get("transfer_id") or "").strip()
            if transfer_id:
                record = self.index.get_transfer(transfer_id)
                if record is not None:
                    blob_hash = str(record.blob_hash or "").strip().lower()
                    name = record.name or name
            if blob_hash and self.valid_hash(blob_hash):
                raw_chunks = [
                    str(c.get("chunk_hash") or "")
                    for c in self.index.list_chunks_for_blob(blob_hash)
                ]
        if not isinstance(raw_chunks, list) or not raw_chunks:
            raise CourierOperationError(
                CourierFailure.INVALID,
                "missing_chunks",
                "Choose a cached transfer or at least one cached chunk to courier.",
            )
        chunks: list[tuple[str, bytes]] = []
        missing: list[str] = []
        for raw_hash in raw_chunks:
            chunk_hash = str(raw_hash or "").strip().lower()
            if not self.valid_hash(chunk_hash):
                raise CourierOperationError(
                    CourierFailure.INVALID,
                    "invalid_chunk_hash",
                    "Courier export received a malformed chunk hash.",
                )
            payload = self.read_chunk(chunk_hash)
            if payload is None:
                missing.append(chunk_hash)
            else:
                chunks.append((chunk_hash, payload))
        if missing:
            raise CourierOperationError(
                CourierFailure.CONFLICT,
                "missing_cached_chunks",
                "One Link has not cached every requested chunk yet.",
                missing=missing[:64],
                missing_count=len(missing),
            )
        try:
            ttl_s = int(data.get("ttl_s") or 24 * 60 * 60)
        except (TypeError, ValueError, OverflowError):
            ttl_s = 24 * 60 * 60
        try:
            exported = export_courier_bundle(
                chunks,
                sender_fp=self.identity.fingerprint,
                recipient_fp=data.get("recipient_fp") or None,
                blob_hash=blob_hash if blob_hash else None,
                name=name,
                ttl_s=ttl_s,
                signing_key=self.identity.signing_key,
            )
        except CourierBundleError as exc:
            raise CourierOperationError(
                CourierFailure.INVALID,
                "courier_export_rejected",
                str(exc),
            ) from exc
        except Exception as exc:
            raise CourierOperationError(
                CourierFailure.FAILED,
                "courier_export_failed",
                str(exc),
            ) from exc
        # Export history is best effort; only import admission is replay
        # authority. An unavailable event log cannot invalidate the bundle.
        with contextlib.suppress(Exception):
            self.ledger.record_event("export", exported.manifest, bundle_bytes=len(exported.bundle))
        return {
            "bundle_b64": encode_bundle_b64(exported.bundle),
            "key_token": exported.key_token,
            "manifest": dict(exported.manifest),
            "bundle_bytes": len(exported.bundle),
            "chunk_count": exported.manifest.get("chunk_count"),
            "total_bytes": exported.manifest.get("total_bytes"),
        }

    def export_file(self, data: Mapping[str, Any]) -> CourierStagedPayload:
        payload = self.export(data)
        manifest = payload["manifest"]
        bundle_id = str(manifest.get("bundle_id") or secrets.token_hex(16))
        name = self.safe_name(manifest.get("name") or f"{bundle_id}.olcb.json")
        try:
            path = self.files.stage_export(payload["bundle_b64"], manifest, name=name)
        except Exception as exc:
            raise CourierOperationError(
                CourierFailure.FAILED,
                "courier_export_file_failed",
                str(exc),
            ) from exc
        return {
            "path": str(path),
            "name": path.name,
            "outbox_dir": str(self.files.outbox_directory()),
            "key_token": payload["key_token"],
            "manifest": manifest,
            "bundle_bytes": payload["bundle_bytes"],
        }

    def import_payload(self, data: Mapping[str, Any]) -> CourierImportPayload:
        if self.ledger.error is not None:
            raise CourierOperationError(
                CourierFailure.UNAVAILABLE,
                "courier_replay_ledger_unavailable",
                "Courier import is blocked because its durable replay ledger is unreadable "
                "or invalid. Preserve the ledger and restore it from a trusted backup before importing.",
            )
        bundle_text = data.get("bundle_b64") or data.get("bundle")
        key_token = str(data.get("key_token") or "").strip()
        if not bundle_text or not key_token:
            raise CourierOperationError(
                CourierFailure.INVALID,
                "missing_courier_fields",
                "Courier import needs both the encrypted bundle and its unlock token.",
            )
        expected_recipient = data.get("expected_recipient_fp")
        if expected_recipient is None and data.get("enforce_recipient", True):
            expected_recipient = self.identity.fingerprint
        try:
            bundle = decode_bundle_b64(str(bundle_text))
            imported = import_courier_bundle(
                bundle,
                key_token,
                expected_recipient_fp=expected_recipient,
                expected_sender_fp=data.get("expected_sender_fp") or None,
                require_sender_signature=bool(data.get("require_sender_signature", False)),
            )
            bundle_id = str(imported.manifest.get("bundle_id") or "").strip().lower()
            if bundle_id in self.ledger.seen_bundle_ids:
                raise CourierBundleError("courier bundle was already imported")
            # No chunk side effect may precede successful durable admission.
            self.ledger.mark_imported(imported.manifest)
            stored = 0
            blob_hash = imported.manifest.get("blob_hash")
            for chunk_hash, chunk_data in imported.chunks:
                self.store_chunk(
                    chunk_hash,
                    chunk_data,
                    blob_hash=blob_hash if isinstance(blob_hash, str) else None,
                    chunk_index=stored if isinstance(blob_hash, str) else None,
                )
                stored += 1
            self.ledger.record_event(
                "import",
                imported.manifest,
                bundle_bytes=len(bundle),
                stored_chunks=stored,
            )
        except CourierBundleError as exc:
            raise CourierOperationError(
                CourierFailure.INVALID,
                "courier_import_rejected",
                str(exc),
            ) from exc
        except Exception as exc:
            raise CourierOperationError(
                CourierFailure.FAILED,
                "courier_import_failed",
                str(exc),
            ) from exc
        return {
            "manifest": dict(imported.manifest),
            "stored_chunks": stored,
            "chunk_count": imported.manifest.get("chunk_count"),
            "total_bytes": imported.manifest.get("total_bytes"),
        }

    def import_file(self, data: Mapping[str, Any]) -> CourierImportPayload:
        path = self.files.resolve_drop(str(data.get("file_id") or ""))
        if path is None:
            raise CourierOperationError(
                CourierFailure.MISSING,
                "courier_file_not_found",
                "That courier file is not in the drop folder anymore.",
            )
        try:
            bundle_b64 = self.files.read_bundle(path)
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            raise CourierOperationError(
                CourierFailure.INVALID,
                "courier_file_unreadable",
                str(exc),
            ) from exc
        return self.import_payload(
            {
                "bundle_b64": bundle_b64,
                "key_token": data.get("key_token"),
                "expected_recipient_fp": data.get("expected_recipient_fp"),
                "enforce_recipient": data.get("enforce_recipient", True),
            }
        )

    def copy_to_removable(self, source: Path, target_path: Path) -> Path:
        try:
            return self.files.copy_to_removable(source, target_path)
        except CourierDestinationRejected as exc:
            raise CourierOperationError(
                CourierFailure.INVALID,
                "removable_target_rejected",
                str(exc),
            ) from exc
        except Exception as exc:
            raise CourierOperationError(
                CourierFailure.FAILED,
                "courier_removable_copy_failed",
                str(exc),
            ) from exc

    def copy_from_removable(self, file_id: str, target_path: Path) -> Path:
        source = self.files.resolve_removable(target_path, file_id)
        if source is None:
            raise CourierOperationError(
                CourierFailure.MISSING,
                "removable_courier_file_not_found",
                "That courier file is not available on the removable target.",
            )
        try:
            return self.files.copy_to_drop(source)
        except Exception as exc:
            raise CourierOperationError(
                CourierFailure.FAILED,
                "courier_removable_copy_failed",
                str(exc),
            ) from exc

    def assemble(self, data: Mapping[str, Any]) -> CourierAssemblyPayload:
        blob_hash = str(data.get("blob_hash") or "").strip().lower()
        if not self.valid_hash(blob_hash):
            raise CourierOperationError(
                CourierFailure.INVALID,
                "invalid_blob_hash",
                "Courier assemble received a malformed blob hash.",
            )
        if self.index is None:
            raise CourierOperationError(
                CourierFailure.UNAVAILABLE,
                "state_unavailable",
                "Chunk index is not available yet.",
            )
        rows = self.index.list_chunks_for_blob(blob_hash)
        if not rows:
            raise CourierOperationError(
                CourierFailure.MISSING,
                "missing_chunk_index",
                "No chunk index is known for this courier blob.",
            )
        name = self.safe_name(data.get("name") or f"{blob_hash[:12]}.bin")
        out_path = self.inbox_path(blob_hash, name)

        def cached_chunks() -> Iterator[tuple[str, bytes]]:
            for row in rows:
                chunk_hash = str(row.get("chunk_hash") or "").strip().lower()
                if not self.valid_hash(chunk_hash):
                    raise CourierBundleError("courier chunk index contains an invalid hash")
                chunk_data = self.read_chunk(chunk_hash)
                if chunk_data is None:
                    raise KeyError(chunk_hash)
                yield chunk_hash, chunk_data

        created = False
        try:
            with open(out_path, "xb") as handle:
                created = True
                written = assemble_courier_chunks(
                    cached_chunks(), handle, expected_blob_hash=blob_hash
                )
                handle.flush()
                os.fsync(handle.fileno())
        except (KeyError, CourierBundleError, OSError) as exc:
            # Exclusive-create failure does not own an existing destination.
            # Only an output created by this operation may be rolled back.
            if created:
                with contextlib.suppress(OSError):
                    out_path.unlink()
            if isinstance(exc, KeyError):
                missing_hash = str(exc.args[0]) if exc.args else ""
                raise CourierOperationError(
                    CourierFailure.CONFLICT,
                    "missing_cached_chunks",
                    "Courier import has not received every chunk for this file yet.",
                    missing_count=1,
                    missing=[missing_hash] if missing_hash else [],
                ) from exc
            if isinstance(exc, CourierBundleError):
                raise CourierOperationError(
                    CourierFailure.CONFLICT,
                    "courier_assemble_rejected",
                    str(exc),
                ) from exc
            raise CourierOperationError(
                CourierFailure.FAILED,
                "courier_assemble_failed",
                str(exc),
            ) from exc
        if os.name != "nt":
            with contextlib.suppress(OSError):
                directory_fd = os.open(out_path.parent, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
        return {
            "path": str(out_path),
            "name": out_path.name,
            "blob_hash": blob_hash,
            "bytes": written,
            "chunks": len(rows),
        }
