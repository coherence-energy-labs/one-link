"""MNT-01 boundary contracts for the services extracted from Daemon/UIServer.

* no extracted module imports the daemon or the UI server;
* each daemon/server adapter implements its Protocol exactly (same members,
  same parameters, same sync/async kind, nothing public beyond it);
* every Protocol member is used by its service (no speculative port surface);
* legacy daemon attribute names read and replace the owning service's state.
"""

from __future__ import annotations

import ast
import inspect
import subprocess
import sys
from collections import OrderedDict
from pathlib import Path
from typing import Protocol

import pytest

from one_link import call_lifecycle, call_routes, folder_sync_receipts, folder_sync_scheduler

REPO = Path(__file__).resolve().parent.parent
EXTRACTED_MODULES = (
    "one_link.call_lifecycle",
    "one_link.call_routes",
    "one_link.fabric_snapshot",
    "one_link.folder_manifest_policy",
    "one_link.folder_sync_receipts",
    "one_link.folder_sync_scheduler",
    "one_link.held_offers",
    "one_link.off_loop_import",
    "one_link.owner_auth_note",
)


def test_extracted_modules_never_import_the_daemon_or_server() -> None:
    probe = (
        "import sys\n"
        f"for name in {EXTRACTED_MODULES!r}:\n"
        "    __import__(name)\n"
        "leaked = sorted(m for m in ('one_link.daemon', 'one_link.server') if m in sys.modules)\n"
        "print(','.join(leaked))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, timeout=120, check=True
    )
    assert result.stdout.strip() == ""


def _protocol_members(protocol: type) -> dict[str, object]:
    return {
        name: value
        for name, value in vars(protocol).items()
        if not name.startswith("_") and callable(value)
    }


def _public_methods(cls: type) -> dict[str, object]:
    return {
        name: value
        for name, value in vars(cls).items()
        if not name.startswith("_") and callable(value)
    }


def _adapter_pairs():
    from one_link import daemon, server

    return [
        (call_lifecycle.CallLifecyclePort, daemon._DaemonCallPort),
        (folder_sync_receipts.FolderSyncReceiptPort, daemon._DaemonFolderSyncPort),
        (folder_sync_scheduler.FolderSyncSchedulerPort, daemon._DaemonFolderSchedulerPort),
        (call_routes.CallRouteHost, server._ServerCallRouteHost),
    ]


@pytest.mark.parametrize("index", range(4))
def test_adapters_implement_their_protocol_exactly(index: int) -> None:
    protocol, adapter = _adapter_pairs()[index]
    assert issubclass(protocol, Protocol)  # type: ignore[arg-type]
    wanted = _protocol_members(protocol)
    provided = _public_methods(adapter)
    assert set(provided) == set(wanted), (adapter.__name__, set(provided) ^ set(wanted))
    for name, member in wanted.items():
        implementation = provided[name]
        assert inspect.iscoroutinefunction(implementation) == inspect.iscoroutinefunction(member), name
        want = list(inspect.signature(member).parameters)
        have = list(inspect.signature(implementation).parameters)
        assert have == want, (adapter.__name__, name, have, want)
    assert getattr(adapter, "__slots__", None), "adapters hold only their owner reference"


@pytest.mark.parametrize(
    "module,protocol,attribute",
    [
        (call_lifecycle, call_lifecycle.CallLifecyclePort, "port"),
        (folder_sync_receipts, folder_sync_receipts.FolderSyncReceiptPort, "port"),
        (folder_sync_scheduler, folder_sync_scheduler.FolderSyncSchedulerPort, "port"),
        (call_routes, call_routes.CallRouteHost, "host"),
    ],
)
def test_every_port_member_is_used_by_its_service(module, protocol, attribute) -> None:
    tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
    used = {
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Attribute)
        and node.value.attr == attribute
        and isinstance(node.value.value, ast.Name)
        and node.value.value.id == "self"
    }
    # The router also hands one bound host member to its audit log.
    used |= {
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "host"
    }
    assert set(_protocol_members(protocol)) <= used, set(_protocol_members(protocol)) - used


def test_legacy_daemon_attributes_alias_the_owning_service_state() -> None:
    from one_link.daemon import Daemon

    daemon = Daemon.__new__(Daemon)
    replacement = OrderedDict(k=1)
    daemon._folder_sync_inbound_receipts = replacement
    service = daemon._folder_sync_receipt_service()
    assert service.book.inbound is replacement
    assert daemon._folder_sync_inbound_receipts is replacement
    daemon._folder_sync_blob_progress = {}
    assert service.book.blob_progress is daemon._folder_sync_blob_progress

    daemon._call_sdp_backfill = {"c": {"sdp_offer": "v=0"}}
    calls = daemon._call_lifecycle_service()
    assert calls.backfill.sdp is daemon._call_sdp_backfill
    daemon._call_resume_enabled = False
    assert calls.ledger.enabled is False
    # One copy only: the class attribute is the alias, never instance state.
    assert "_call_sdp_backfill" not in vars(daemon)
    assert "_folder_sync_inbound_receipts" not in vars(daemon)


def test_daemon_builds_one_service_instance_per_domain() -> None:
    from one_link.daemon import Daemon

    daemon = Daemon.__new__(Daemon)
    assert daemon._call_lifecycle_service() is daemon._call_lifecycle_service()
    assert daemon._folder_sync_receipt_service() is daemon._folder_sync_receipt_service()
    assert daemon._folder_sync_scheduler() is daemon._folder_sync_scheduler()
