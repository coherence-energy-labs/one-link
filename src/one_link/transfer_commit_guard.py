"""Durable retry decisions after an outbound offer may have reached a peer.

The service reads only the transfer ledger and its private marker directory.
It cannot send, broadcast, change trust, inspect sessions, or update arbitrary
state. Missing/malformed accounting remains a blocked retry, and publication
uses explicitly supplied durable filesystem operations.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import secrets
import time
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Protocol

from one_link.namespace_durability import replace_path

if TYPE_CHECKING:
    from one_link.state import TransferRecord


class TransferCommitLedger(Protocol):
    @property
    def db_path(self) -> Path: ...

    def get_transfer(self, id: str) -> TransferRecord | None: ...


class RemoteCommitGuard:
    """Own replay admissibility and the durable remote-outcome marker."""

    def __init__(
        self,
        ledger: TransferCommitLedger | None,
        *,
        sync_parent: Callable[[Path], None],
        replace: Callable[[Path, Path], None] = replace_path,
    ) -> None:
        self.ledger = ledger
        self._sync_parent = sync_parent
        self._replace = replace

    @staticmethod
    def ledger_boundary_decision(rec: TransferRecord | None, transfer_id: str) -> bool | None:
        """True=blocked, False=stable modern retry, None=no boundary."""

        if rec is None or rec.direction != "out":
            return True
        metadata = dict(rec.metadata or {})
        committed = metadata.get("offer_boundary_committed")
        if committed is not True:
            # An explicit but malformed/false boundary flag is not a
            # safe retry grant. Absence is expected for a pristine row
            # that has never approached the wire.
            return True if "offer_boundary_committed" in metadata else None
        contract = metadata.get("offer_boundary_contract")
        if not isinstance(contract, dict):
            return True
        contract_size = contract.get("size")
        receipt_capable = metadata.get("receipt_capable")
        if type(contract_size) is not int or type(receipt_capable) is not bool:
            return True
        if contract.get("receipt_capable") is not receipt_capable:
            return True
        if contract.get("schema") != 1:
            return True
        if contract.get("transfer_id") != transfer_id:
            return True
        if contract.get("delivery_id") != metadata.get("delivery_id"):
            return True
        if contract.get("peer_fp") != rec.peer_fp:
            return True
        if contract.get("blob") != rec.blob_hash:
            return True
        if contract_size != int(rec.size):
            return True
        if contract.get("name") != rec.name:
            return True
        if contract.get("name") != metadata.get("delivery_name"):
            return True
        if str(contract.get("rel_path") or "") != str(metadata.get("delivery_rel_path") or ""):
            return True
        if str(contract.get("kind") or "file") != str(metadata.get("delivery_kind") or "file"):
            return True
        if contract.get("mode") not in {"cdc", "stream"}:
            return True
        # A stable delivery nonce is useful only when the receiver can
        # attest and replay the durable commit. Legacy ACK-only peers
        # can have already materialized a second path, so they stop.
        return not receipt_capable

    def path(self, transfer_id: str) -> Path:
        if self.ledger is None:
            raise OSError("transfer state is unavailable")
        digest = hashlib.sha256(transfer_id.encode("utf-8")).hexdigest()
        return Path(self.ledger.db_path).parent / "transfer_commit_failstop" / f"{digest}.json"

    def write(
        self,
        transfer_id: str,
        *,
        receipt: dict | None = None,
        delivery: dict | None = None,
    ) -> None:
        """Durably prevent resend when remote commit outlives local SQLite."""

        target = self.path(transfer_id)
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if os.name != "nt":
            os.chmod(target.parent, 0o700)
        temp = target.parent / f".{target.name}.{secrets.token_hex(8)}.tmp"
        payload = {
            "schema": 1,
            "transfer_id": transfer_id,
            "recorded_ms": int(time.time() * 1000),
            "phase": "remote_committed" if receipt else "outcome_unknown",
            "receipt": receipt or {},
            "delivery": delivery or {},
        }
        try:
            with open(temp, "x", encoding="utf-8", newline="\n") as handle:
                json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            self._replace(temp, target)
            self._sync_parent(target)
        finally:
            with contextlib.suppress(OSError):
                temp.unlink()

    def is_failstopped(self, transfer_id: str) -> bool:
        """Return whether automatic resend could create an untracked duplicate.

        The FULL-synced SQLite offer boundary is authoritative even if the
        redundant sidecar was deleted. ``outcome_unknown`` is safe to retry
        only when that row carries a receipt-capable modern delivery and the
        exact nonce/content/presentation contract recorded before the offer.
        Legacy delivery, contract drift, proven receipt, or malformed sidecar
        always fails closed.
        """

        try:
            marker = self.path(transfer_id)
            rec = self.ledger.get_transfer(transfer_id) if self.ledger is not None else None

            if not marker.exists():
                ledger_decision = self.ledger_boundary_decision(rec, transfer_id)
                return bool(ledger_decision) if ledger_decision is not None else False
            if marker.is_symlink() or not marker.is_file():
                return True
            if marker.stat().st_size > 256 * 1024:
                return True
            payload = json.loads(marker.read_text(encoding="utf-8"))
            if (
                not isinstance(payload, dict)
                or payload.get("schema") != 1
                or payload.get("transfer_id") != transfer_id
            ):
                return True
            phase = payload.get("phase")
            if phase == "remote_committed":
                return True
            if phase != "outcome_unknown" or self.ledger is None:
                return True
            delivery = payload.get("delivery")
            if not isinstance(delivery, dict):
                return True
            delivery_size = delivery.get("size")
            if type(delivery_size) is not int:
                return True
            ledger_decision = self.ledger_boundary_decision(rec, transfer_id)
            if ledger_decision is not False:
                return True
            if rec is None:
                return True
            metadata = dict(rec.metadata or {})
            contract = metadata.get("offer_boundary_contract")
            if not isinstance(contract, dict):
                return True
            return not (
                rec.direction == "out"
                and rec.peer_fp == str(delivery.get("peer_fp") or "")
                and rec.blob_hash == str(delivery.get("blob") or "")
                and int(rec.size) == delivery_size
                and metadata.get("delivery_id") == delivery.get("delivery_id")
                and metadata.get("delivery_name") == delivery.get("name")
                and str(metadata.get("delivery_rel_path") or "")
                == str(delivery.get("rel_path") or "")
                and str(metadata.get("delivery_kind") or "file")
                == str(delivery.get("kind") or "file")
                and delivery.get("receipt_capable") is True
                and delivery.get("delivery_id") == contract.get("delivery_id")
                and delivery.get("peer_fp") == contract.get("peer_fp")
                and delivery.get("blob") == contract.get("blob")
                and delivery_size == contract.get("size")
                and delivery.get("name") == contract.get("name")
                and str(delivery.get("rel_path") or "") == str(contract.get("rel_path") or "")
                and str(delivery.get("kind") or "file") == str(contract.get("kind") or "file")
            )
        except Exception:
            # Unknown accounting state is never evidence that retry is safe.
            return True

    def clear(self, transfer_id: str) -> None:
        try:
            marker = self.path(transfer_id)
            marker.unlink(missing_ok=True)
            self._sync_parent(marker)
        except OSError:
            pass
