"""Durable replay authority for offline courier imports.

The ledger owns its state and publication boundary. It does not know about
HTTP, daemon lifecycle, identities, or the chunk cache. Importers must call
``mark_imported`` successfully before admitting any payload bytes.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import secrets
import stat
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

COURIER_LEDGER_FILE = "courier_ledger.json"
COURIER_LEDGER_MAX_EVENTS = 512
COURIER_LEDGER_MAX_BYTES = 8 * 1024 * 1024


class CourierLedgerUnavailable(RuntimeError):
    """The durable courier replay authority cannot be trusted."""


class CourierReplayLedger:
    """One process's replay authority, loaded from one explicit file.

    A failed persistence attempt retains conservative in-memory admission:
    the current process must not retry payload side effects after uncertainty.
    Corrupt existing files are preserved and block import, never reset.
    """

    def __init__(
        self,
        path: Path,
        *,
        max_events: int = COURIER_LEDGER_MAX_EVENTS,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if max_events <= 0:
            raise ValueError("courier event bound must be positive")
        self.path = Path(path)
        self.max_events = max_events
        self.clock = clock
        self.seen_bundle_ids: set[str] = set()
        self.events: list[dict[str, Any]] = []
        self.error: str | None = None
        self.load()

    @staticmethod
    def valid_bundle_id(value: object) -> bool:
        text = str(value or "").strip().lower()
        return len(text) == 32 and all(c in "0123456789abcdef" for c in text)

    def load(self) -> None:
        try:
            info = self.path.lstat()
        except FileNotFoundError:
            self.seen_bundle_ids = set()
            self.events = []
            self.error = None
            return
        except OSError as exc:
            self.seen_bundle_ids = set()
            self.events = []
            self.error = "unreadable"
            log.error("courier replay ledger metadata is unreadable: %s", exc)
            return

        try:
            if not stat.S_ISREG(info.st_mode) or info.st_size > COURIER_LEDGER_MAX_BYTES:
                raise CourierLedgerUnavailable("ledger is not a bounded regular file")
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict) or set(raw) != {
                "version",
                "seen_bundle_ids",
                "events",
            }:
                raise CourierLedgerUnavailable("ledger schema is invalid")
            if raw.get("version") != 1:
                raise CourierLedgerUnavailable("ledger version is unsupported")
            seen = raw.get("seen_bundle_ids")
            events = raw.get("events")
            if not isinstance(seen, list) or not isinstance(events, list):
                raise CourierLedgerUnavailable("ledger collections are invalid")
            if len(events) > self.max_events:
                raise CourierLedgerUnavailable("ledger event count exceeds its bound")
            if any(not self.valid_bundle_id(value) for value in seen):
                raise CourierLedgerUnavailable("ledger contains an invalid replay id")
            if any(
                not isinstance(event, dict) or not self.valid_bundle_id(event.get("bundle_id"))
                for event in events
            ):
                raise CourierLedgerUnavailable("ledger contains an invalid event")
        except (
            OSError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            CourierLedgerUnavailable,
        ) as exc:
            self.seen_bundle_ids = set()
            self.events = []
            self.error = "invalid_or_unreadable"
            log.error("courier replay ledger cannot be trusted: %s", exc)
            return

        self.seen_bundle_ids = {str(value).strip().lower() for value in seen}
        self.events = list(events)
        self.error = None

    def save(self) -> None:
        if self.error is not None:
            raise CourierLedgerUnavailable(
                "refusing to overwrite an unreadable courier replay ledger"
            )
        path = self.path
        path.parent.mkdir(parents=True, exist_ok=True)
        encoded = json.dumps(
            {
                "version": 1,
                "seen_bundle_ids": sorted(self.seen_bundle_ids),
                "events": self.events[-self.max_events :],
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        tmp = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        descriptor: int | None = None
        try:
            descriptor = os.open(tmp, flags, 0o600)
            view = memoryview(encoded)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("short write while persisting courier ledger")
                view = view[written:]
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
            if os.name == "nt":
                from one_link.identity import _restrict_windows_acl

                _restrict_windows_acl(tmp)
            else:
                os.chmod(tmp, 0o600)
            if tmp.read_bytes() != encoded:
                raise OSError("courier ledger read-back mismatch")
            from one_link.namespace_durability import replace_path

            replace_path(tmp, path)
            if os.name != "nt":
                directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            if path.read_bytes() != encoded:
                raise OSError("published courier ledger read-back mismatch")
        finally:
            if descriptor is not None:
                os.close(descriptor)
            with contextlib.suppress(FileNotFoundError):
                tmp.unlink()

    def record_event(
        self,
        kind: str,
        manifest: Mapping[str, object],
        *,
        bundle_bytes: int | None = None,
        stored_chunks: int | None = None,
    ) -> None:
        bundle_id = str(manifest.get("bundle_id") or "").strip().lower()
        if not self.valid_bundle_id(bundle_id):
            return
        event: dict[str, Any] = {
            "kind": kind,
            "bundle_id": bundle_id,
            "ts_ms": int(self.clock() * 1000),
            "sender_fp": manifest.get("sender_fp"),
            "recipient_fp": manifest.get("recipient_fp"),
            "chunk_count": manifest.get("chunk_count"),
            "total_bytes": manifest.get("total_bytes"),
            "expires_ms": manifest.get("expires_ms"),
        }
        if bundle_bytes is not None:
            event["bundle_bytes"] = int(bundle_bytes)
        if stored_chunks is not None:
            event["stored_chunks"] = int(stored_chunks)
        self.events.append(event)
        self.events = self.events[-self.max_events :]
        self.save()

    def mark_imported(self, manifest: Mapping[str, object]) -> None:
        bundle_id = str(manifest.get("bundle_id") or "").strip().lower()
        if not self.valid_bundle_id(bundle_id):
            raise ValueError("invalid courier bundle id")
        self.seen_bundle_ids.add(bundle_id)
        self.save()
