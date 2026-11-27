"""Courier behavior through narrow services, without daemon startup or HTTP."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import blake3
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.courier_files import CourierDirectoryMonitor, CourierFileCatalog
from one_link.courier_ledger import CourierLedgerUnavailable, CourierReplayLedger
from one_link.courier_service import (
    CourierFailure,
    CourierIdentity,
    CourierOperationError,
    CourierService,
)


@dataclass
class Transfer:
    blob_hash: str | None
    name: str


class ReadOnlyIndex:
    def __init__(self, chunks: list[tuple[str, bytes]], blob_hash: str) -> None:
        self.rows = [{"chunk_hash": digest} for digest, _ in chunks]
        self.transfer = Transfer(blob_hash, "transfer-name.bin")
        self.queries: list[tuple[str, str]] = []

    def get_transfer(self, id: str) -> Transfer | None:
        self.queries.append(("transfer", id))
        return self.transfer if id == "transfer-1" else None

    def list_chunks_for_blob(self, blob_hash: str) -> list[dict]:
        self.queries.append(("chunks", blob_hash))
        return self.rows if blob_hash == self.transfer.blob_hash else []


@pytest.fixture
def courier(tmp_path):
    chunks = [(blake3.blake3(payload).hexdigest(), payload) for payload in (b"first", b"second")]
    blob_hash = blake3.blake3(b"firstsecond").hexdigest()
    cache = dict(chunks)
    writes = []
    key = Ed25519PrivateKey.generate()
    identity = CourierIdentity(blake3.blake3(key.public_key().public_bytes_raw()).hexdigest(), key)
    index = ReadOnlyIndex(chunks, blob_hash)
    inbox = tmp_path / "inbox"
    inbox.mkdir()

    def store(chunk_hash, payload, *, blob_hash=None, chunk_index=None):
        writes.append((chunk_hash, payload, blob_hash, chunk_index))
        cache[chunk_hash] = payload

    def make(*, ledger=None, store_chunk=store):
        return CourierService(
            ledger=ledger or CourierReplayLedger(tmp_path / "ledger.json"),
            files=CourierFileCatalog(tmp_path / "courier"),
            identity=identity,
            index=index,
            read_chunk=cache.get,
            store_chunk=store_chunk,
            valid_hash=lambda value: (
                len(value) == 64 and all(c in "0123456789abcdef" for c in value)
            ),
            safe_name=lambda name: Path(str(name)).name,
            inbox_path=lambda _blob_hash, name: inbox / name,
        )

    return make(), make, chunks, blob_hash, cache, writes


def export_options(service, chunks, blob_hash):
    return {
        "chunks": [digest for digest, _ in chunks],
        "blob_hash": blob_hash,
        "recipient_fp": service.identity.fingerprint,
        "name": "example.bin",
    }


def test_courier_services_import_without_server_or_daemon():
    process = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; import one_link.courier_service; "
            "assert 'one_link.server' not in sys.modules; "
            "assert 'one_link.daemon' not in sys.modules; "
            "assert 'aiohttp' not in sys.modules",
        ],
        env=os.environ.copy(),
        capture_output=True,
        text=True,
    )
    assert process.returncode == 0, process.stderr


def test_transfer_export_uses_only_two_read_only_index_queries(courier):
    service, _, chunks, blob_hash, _, _ = courier
    exported = service.export({"transfer_id": "transfer-1"})
    assert service.index.queries == [("transfer", "transfer-1"), ("chunks", blob_hash)]
    assert exported["manifest"]["name"] == "transfer-name.bin"
    assert exported["manifest"]["chunk_count"] == len(chunks)
    assert exported["manifest"]["blob_hash"] == blob_hash


def test_staged_export_is_importable_without_persisting_its_unlock_token(courier):
    service, _, chunks, blob_hash, _, writes = courier
    staged = service.export_file(export_options(service, chunks, blob_hash))
    path = Path(staged["path"])
    text = path.read_text()
    assert staged["key_token"] not in text
    assert path.parent == service.files.outbox_directory()
    assert json.loads(text)["manifest"] == staged["manifest"]
    result = service.import_payload(
        {
            "bundle_b64": service.files.read_bundle(path),
            "key_token": staged["key_token"],
            "expected_sender_fp": service.identity.fingerprint,
            "require_sender_signature": True,
        }
    )
    assert result["stored_chunks"] == 2
    assert writes == [(digest, data, blob_hash, i) for i, (digest, data) in enumerate(chunks)]


def test_import_durably_admits_once_before_first_chunk_write(courier):
    service, make, chunks, blob_hash, _, _ = courier
    exported = service.export(export_options(service, chunks, blob_hash))
    bundle_id = exported["manifest"]["bundle_id"]
    admitted = []

    def store(chunk_hash, payload, **metadata):
        on_disk = json.loads(service.ledger.path.read_text())
        assert bundle_id in on_disk["seen_bundle_ids"]
        admitted.append((chunk_hash, payload))

    importer = make(store_chunk=store)
    assert importer.import_payload(exported)["stored_chunks"] == 2
    assert admitted == chunks
    restarted = make(store_chunk=store)
    with pytest.raises(CourierOperationError, match="already imported") as rejected:
        restarted.import_payload(exported)
    assert rejected.value.code == "courier_import_rejected"
    assert admitted == chunks


def test_failed_ledger_sync_admits_no_chunks_and_preserves_disk_authority(courier, monkeypatch):
    service, _, chunks, blob_hash, _, writes = courier
    exported = service.export(export_options(service, chunks, blob_hash))
    before = service.ledger.path.read_bytes()

    def fail_sync(_fd):
        raise OSError("test disk sync failure")

    monkeypatch.setattr(os, "fsync", fail_sync)
    with pytest.raises(CourierOperationError, match="test disk sync failure") as rejected:
        service.import_payload(exported)
    assert rejected.value.code == "courier_import_failed"
    assert writes == []
    assert service.ledger.path.read_bytes() == before
    assert not list(service.ledger.path.parent.glob(".ledger.json.*.tmp"))
    # Until restart, uncertain admission is conservative even if disk did not
    # publish. The importer cannot accidentally start payload side effects.
    assert exported["manifest"]["bundle_id"] in service.ledger.seen_bundle_ids


def test_cache_failure_does_not_erase_replay_admission(courier):
    service, make, chunks, blob_hash, _, _ = courier
    exported = service.export(export_options(service, chunks, blob_hash))
    attempted = []

    def failing_store(chunk_hash, payload, **metadata):
        attempted.append(chunk_hash)
        raise OSError("cache unavailable")

    importer = make(store_chunk=failing_store)
    with pytest.raises(CourierOperationError, match="cache unavailable"):
        importer.import_payload(exported)
    with pytest.raises(CourierOperationError, match="already imported"):
        make(store_chunk=failing_store).import_payload(exported)
    assert attempted == [chunks[0][0]]


def test_corrupt_ledger_is_preserved_and_blocks_even_an_incomplete_request(courier):
    service, make, _, _, _, writes = courier
    service.ledger.path.write_bytes(b"{interrupted")
    restarted = make()
    with pytest.raises(CourierOperationError) as rejected:
        restarted.import_payload({})
    assert rejected.value.kind is CourierFailure.UNAVAILABLE
    assert rejected.value.code == "courier_replay_ledger_unavailable"
    with pytest.raises(CourierLedgerUnavailable):
        restarted.ledger.save()
    assert service.ledger.path.read_bytes() == b"{interrupted"
    assert writes == []


def test_ledger_trims_events_without_forgetting_replay_ids(tmp_path):
    ledger = CourierReplayLedger(tmp_path / "ledger.json", max_events=2, clock=lambda: 17.5)
    for i in range(3):
        manifest = {"bundle_id": f"{i:032x}", "chunk_count": 1}
        ledger.mark_imported(manifest)
        ledger.record_event("import", manifest, stored_chunks=1)
    restarted = CourierReplayLedger(ledger.path, max_events=2)
    assert restarted.seen_bundle_ids == {f"{i:032x}" for i in range(3)}
    assert [e["bundle_id"] for e in restarted.events] == [f"{i:032x}" for i in (1, 2)]
    assert {e["ts_ms"] for e in restarted.events} == {17500}


@pytest.mark.parametrize("bundle_id", ["+" + "1" * 31, "-" + "1" * 31, "g" * 32])
def test_ledger_ids_are_hex_octets_not_signed_integer_literals(tmp_path, bundle_id):
    ledger = CourierReplayLedger(tmp_path / "ledger.json")
    with pytest.raises(ValueError, match="invalid courier bundle id"):
        ledger.mark_imported({"bundle_id": bundle_id})
    assert not ledger.path.exists()
    assert ledger.seen_bundle_ids == set()


def test_export_reports_bounded_missing_details_without_writes(courier):
    service, _, _, _, _, writes = courier
    with pytest.raises(CourierOperationError) as rejected:
        service.export({"chunks": [f"{i:064x}" for i in range(70)]})
    assert rejected.value.kind is CourierFailure.CONFLICT
    assert rejected.value.code == "missing_cached_chunks"
    assert rejected.value.details["missing_count"] == 70
    assert len(rejected.value.details["missing"]) == 64
    assert writes == []


def test_assembly_preserves_order_and_verifies_whole_file(courier):
    service, _, _, blob_hash, _, _ = courier
    result = service.assemble({"blob_hash": blob_hash, "name": "complete.bin"})
    assert Path(result["path"]).read_bytes() == b"firstsecond"
    assert result["bytes"] == 11
    assert result["chunks"] == 2


def test_partial_assembly_is_removed_if_a_later_chunk_is_missing(courier):
    service, _, chunks, blob_hash, cache, _ = courier
    cache.pop(chunks[1][0])
    with pytest.raises(CourierOperationError) as rejected:
        service.assemble({"blob_hash": blob_hash, "name": "partial.bin"})
    assert rejected.value.kind is CourierFailure.CONFLICT
    assert rejected.value.details["missing"] == [chunks[1][0]]
    assert not service.inbox_path(blob_hash, "partial.bin").exists()


def test_exclusive_create_failure_never_removes_someone_elses_file(courier):
    service, _, _, blob_hash, _, _ = courier
    path = service.inbox_path(blob_hash, "collision.bin")
    path.write_bytes(b"existing user's file")
    with pytest.raises(CourierOperationError) as rejected:
        service.assemble({"blob_hash": blob_hash, "name": "collision.bin"})
    assert rejected.value.kind is CourierFailure.FAILED
    assert rejected.value.code == "courier_assemble_failed"
    assert path.read_bytes() == b"existing user's file"


def test_whole_file_mismatch_removes_only_failed_assembly(courier):
    service, _, _, blob_hash, _, _ = courier
    service.index.rows.reverse()
    with pytest.raises(CourierOperationError) as rejected:
        service.assemble({"blob_hash": blob_hash, "name": "wrong-order.bin"})
    assert rejected.value.code == "courier_assemble_rejected"
    assert not service.inbox_path(blob_hash, "wrong-order.bin").exists()


def test_catalog_limits_are_independent_and_keep_only_newest_valid_files(tmp_path):
    files = CourierFileCatalog(tmp_path / "courier", list_limit=2, max_file_bytes=8)
    drop = files.drop_directory()
    for i in range(4):
        path = drop / f"{i}.olcb.json"
        path.write_bytes(b"ok")
        os.utime(path, (i + 1, i + 1))
    (drop / "too-big.json").write_bytes(b"x" * 9)
    (drop / "ignored.txt").write_text("ignore")
    listing = files.scan_drop()
    assert [f["name"] for f in listing] == ["3.olcb.json", "2.olcb.json"]
    assert files.resolve_drop(listing[0]["id"]) == drop / "3.olcb.json"
    assert files.resolve_outbox(listing[0]["id"]) is None
    assert files.scan_drop() == listing


def test_disappearing_drive_does_not_publish_partial_inventory(tmp_path, monkeypatch):
    files = CourierFileCatalog(tmp_path)

    def disappeared(_path):
        yield tmp_path / "first.json"
        raise OSError("drive removed while scanning")

    (tmp_path / "first.json").write_bytes(b"ok")
    monkeypatch.setattr(Path, "iterdir", disappeared)
    assert files.scan(tmp_path) == []


def test_copy_failure_removes_private_partial_file_and_preserves_source(tmp_path, monkeypatch):
    source = tmp_path / "source.olcb.json"
    source.write_bytes(b"original")
    files = CourierFileCatalog(tmp_path / "courier")

    def interrupted(src, dest):
        dest.write_bytes(src.read_bytes()[:3])
        raise OSError("drive removed while copying")

    monkeypatch.setattr("one_link.courier_files.shutil.copyfile", interrupted)
    with pytest.raises(OSError, match="drive removed"):
        files.copy_to_drop(source)
    assert source.read_bytes() == b"original"
    assert list(files.drop_directory().iterdir()) == []


def test_directory_monitors_own_independent_change_state(tmp_path):
    first = CourierDirectoryMonitor(CourierFileCatalog(tmp_path / "one"), clock=lambda: 1.25)
    other = CourierDirectoryMonitor(CourierFileCatalog(tmp_path / "two"), clock=lambda: 2.5)
    assert not first.poll().changed
    (first.catalog.drop_directory() / "new.json").write_bytes(b"encrypted")
    assert first.poll().changed
    assert not first.poll().changed
    assert not other.poll().changed
    assert first.events == 1
    assert other.events == 0
    assert first.last_scan_ms == 1250
    assert other.last_scan_ms == 2500


class JsonRequest:
    def __init__(self, value=None, *, error=False):
        self.value = value
        self.error = error

    async def json(self):
        if self.error:
            raise ValueError("invalid JSON")
        return self.value


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "method,payload,status,code",
    [
        ("api_courier_export", {}, 400, "missing_chunks"),
        ("api_courier_export", {"chunks": ["invalid"]}, 400, "invalid_chunk_hash"),
        ("api_courier_export", {"chunks": ["0" * 64]}, 409, "missing_cached_chunks"),
        ("api_courier_import", {}, 400, "missing_courier_fields"),
        ("api_courier_import_file", {"file_id": "0" * 24}, 404, "courier_file_not_found"),
        ("api_courier_assemble", {"blob_hash": "invalid"}, 400, "invalid_blob_hash"),
        ("api_courier_assemble", {"blob_hash": "0" * 64}, 404, "missing_chunk_index"),
    ],
)
async def test_http_adapters_preserve_original_domain_rejection_contract(
    courier,
    method,
    payload,
    status,
    code,
):
    from one_link.server import UIServer

    service, *_ = courier
    server = UIServer.__new__(UIServer)
    server._courier_service = lambda: service
    response = await getattr(server, method)(JsonRequest(payload))
    assert response.status == status
    body = json.loads(response.body)
    assert body["ok"] is False
    assert body["error"] == code
    assert isinstance(body["message"], str)


@pytest.mark.asyncio
async def test_http_adapter_preserves_ledger_unavailable_and_failed_assembly_statuses(courier):
    from one_link.server import UIServer

    service, _, _, blob_hash, _, _ = courier
    server = UIServer.__new__(UIServer)
    server._courier_service = lambda: service
    service.ledger.error = "invalid_or_unreadable"
    unavailable = await server.api_courier_import(JsonRequest({}))
    assert unavailable.status == 503
    assert json.loads(unavailable.body)["error"] == "courier_replay_ledger_unavailable"
    service.inbox_path(blob_hash, "existing.bin").write_bytes(b"keep")
    failed = await server.api_courier_assemble(
        JsonRequest(
            {
                "blob_hash": blob_hash,
                "name": "existing.bin",
            }
        )
    )
    assert failed.status == 500
    assert json.loads(failed.body)["error"] == "courier_assemble_failed"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "method",
    [
        "api_courier_export",
        "api_courier_export_file",
        "api_courier_import",
        "api_courier_import_file",
        "api_courier_assemble",
        "api_courier_copy_to_removable",
        "api_courier_copy_from_removable",
    ],
)
@pytest.mark.parametrize("malformed", [False, True])
async def test_bad_json_never_constructs_or_calls_a_courier_service(method, malformed):
    from one_link.server import UIServer

    server = UIServer.__new__(UIServer)

    def unexpected_service():
        pytest.fail("rejected HTTP input must not create courier side effects")

    server._courier_service = unexpected_service
    response = await getattr(server, method)(JsonRequest([], error=malformed))
    assert response.status == 400
    assert json.loads(response.body)["error"] == "bad_json"
