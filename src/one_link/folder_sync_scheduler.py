"""Folder-sync scheduling: which shared folder syncs with which peer, and when.

The scheduler decides; it never transfers. Each cycle walks the shared
folders, keeps only peers that are pinned (SAS-verified) and currently
discovered, and asks the daemon for one full-duplex background push per
(folder, peer). A failure for one pair is logged and never stops the cycle.
Local file changes are reported to the UI so the folder status indicator
updates immediately; the peer push itself waits for the next cycle.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Callable, Iterable, Mapping, Protocol

from one_link.fault_observability import report_best_effort_failure

_module_log = logging.getLogger(__name__)

FOLDER_SYNC_INITIAL_DELAY_S = 8.0
FOLDER_SYNC_INTERVAL_S = 30.0


class FolderSyncSchedulerPort(Protocol):
    """Exactly what scheduling needs from the daemon."""

    def sync_ready(self) -> bool: ...

    def list_folders(self) -> Iterable[Mapping[str, Any]]: ...

    def discovered_peers(self) -> Iterable[Any]: ...

    def peer_fp_from_peer(self, peer: Any) -> str | None: ...

    def is_pinned(self, peer_fp: str) -> bool: ...

    async def push_folder_to_peer(
        self, peer: Any, folder_name: str, *, bidirectional: bool, background: bool
    ) -> Any: ...

    def ui_broadcaster(self) -> Callable[[dict], Any] | None: ...


class FolderSyncScheduler:
    def __init__(
        self,
        port: FolderSyncSchedulerPort,
        *,
        logger: logging.Logger | None = None,
        sleep: Callable[[float], Any] | None = None,
    ) -> None:
        self.port = port
        self.log = logger if logger is not None else _module_log
        self._sleep = sleep if sleep is not None else asyncio.sleep

    def _find_peer(self, peer_fp: str) -> Any | None:
        for candidate in self.port.discovered_peers():
            if self.port.peer_fp_from_peer(candidate) == peer_fp:
                return candidate
        return None

    async def run_cycle(self) -> int:
        """Push every shared folder to each pinned, discovered peer once.

        Returns the number of pushes attempted (successful or not).
        """

        if not self.port.sync_ready():
            return 0
        folders = self.port.list_folders()
        if not folders:
            return 0
        attempted = 0
        for folder in folders:
            for peer_fp in folder["shared_with"]:
                if not self.port.is_pinned(peer_fp):
                    continue
                if not self.port.sync_ready():
                    # A push below awaited, and the daemon began shutting down
                    # meanwhile. Stop the cycle here: discovery and state are
                    # no longer there to ask.
                    return attempted
                peer = self._find_peer(peer_fp)
                if peer is None:
                    continue
                attempted += 1
                try:
                    # Full duplex: one connection syncs BOTH directions and
                    # falls back to half duplex against legacy peers that do
                    # not advertise FOLDER_SYNC_BIDI_V1.
                    await self.port.push_folder_to_peer(
                        peer,
                        folder["name"],
                        bidirectional=True,
                        background=True,
                    )
                except Exception as e:
                    self.log.info("folder sync to %s failed: %s", peer.short_id, e)
        return attempted

    async def run_forever(
        self,
        *,
        initial_delay_s: float = FOLDER_SYNC_INITIAL_DELAY_S,
        interval_s: float = FOLDER_SYNC_INTERVAL_S,
    ) -> None:
        """Settle, then run a cycle every ``interval_s`` until cancelled."""

        try:
            await self._sleep(initial_delay_s)
            while True:
                await self.run_cycle()
                await self._sleep(interval_s)
        except asyncio.CancelledError:
            pass

    async def on_local_change(self, folder_name: str, entry: Any) -> None:
        """Tell the UI a watched file was added, changed or deleted."""

        broadcast = self.port.ui_broadcaster()
        if broadcast is None:
            return
        try:
            broadcast({
                "type": "folder_change",
                "folder": folder_name,
                "file": entry.file_path,
                "deleted": entry.blob_hash is None,
            })
        except Exception as exc:
            report_best_effort_failure(
                self.log,
                "folder_change_broadcast",
                exc,
                level=logging.DEBUG,
            )
