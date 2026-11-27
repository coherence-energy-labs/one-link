"""Bounded courier file catalog and staging operations.

All roots are explicit. Removable-drive discovery and user authorization
belong to the caller; this module receives the selected drive's path only.
"""

from __future__ import annotations

import contextlib
import hashlib
import heapq
import json
import os
import secrets
import shutil
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TypedDict

COURIER_FILE_MAX_BYTES = 768 * 1024 * 1024
COURIER_FILE_LIST_LIMIT = 64


class CourierFileInfo(TypedDict):
    id: str
    name: str
    bytes: int
    mtime_ms: int


class CourierDestinationRejected(ValueError):
    """A selected removable courier directory escaped its drive root."""


class CourierFileCatalog:
    """Own local drop/outbox roots and a fixed-size newest-file catalog."""

    def __init__(
        self,
        root: Path,
        *,
        max_file_bytes: int = COURIER_FILE_MAX_BYTES,
        list_limit: int = COURIER_FILE_LIST_LIMIT,
    ) -> None:
        if max_file_bytes <= 0 or list_limit <= 0:
            raise ValueError("courier catalog bounds must be positive")
        self.root = Path(root)
        self.max_file_bytes = max_file_bytes
        self.list_limit = list_limit

    def directory(self) -> Path:
        self.root.mkdir(parents=True, exist_ok=True)
        return self.root

    def drop_directory(self) -> Path:
        path = self.directory() / "drop"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def outbox_directory(self) -> Path:
        path = self.directory() / "outbox"
        path.mkdir(parents=True, exist_ok=True)
        return path

    @staticmethod
    def file_id_from_stat(name: str, size: int, mtime_ns: int) -> str:
        seed = f"{name}\0{int(size)}\0{int(mtime_ns)}".encode("utf-8", "surrogatepass")
        return hashlib.sha256(seed).hexdigest()[:24]

    @classmethod
    def file_id(cls, path: Path) -> str:
        st = path.stat()
        return cls.file_id_from_stat(path.name, int(st.st_size), int(st.st_mtime_ns))

    def scan(self, directory: Path) -> list[CourierFileInfo]:
        root = directory.resolve()
        if not root.is_dir():
            return []
        newest: list[tuple[int, Path, os.stat_result]] = []
        try:
            for path in root.iterdir():
                try:
                    if path.is_symlink():
                        continue
                    resolved = path.resolve()
                    if not resolved.is_file() or resolved.parent != root:
                        continue
                    if resolved.suffix.lower() not in {".json", ".olcb"}:
                        continue
                    st = resolved.stat()
                    if st.st_size <= 0 or st.st_size > self.max_file_bytes:
                        continue
                    item = (int(st.st_mtime_ns), resolved, st)
                    if len(newest) < self.list_limit:
                        heapq.heappush(newest, item)
                    elif item[0] > newest[0][0]:
                        heapq.heapreplace(newest, item)
                except OSError:
                    continue
        except OSError:
            # A drive can disappear while iterdir advances, not just when
            # creating the iterator. Publish no partial inventory then.
            return []
        return [
            {
                "id": self.file_id_from_stat(path.name, int(st.st_size), int(st.st_mtime_ns)),
                "name": path.name,
                "bytes": int(st.st_size),
                "mtime_ms": int(st.st_mtime * 1000),
            }
            for _, path, st in sorted(newest, key=lambda item: item[0], reverse=True)
        ]

    def scan_drop(self) -> list[CourierFileInfo]:
        return self.scan(self.drop_directory())

    def scan_outbox(self) -> list[CourierFileInfo]:
        return self.scan(self.outbox_directory())

    def resolve(self, directory: Path, file_id: str) -> Path | None:
        want = str(file_id or "").strip().lower()
        if len(want) != 24:
            return None
        root = directory.resolve()
        for item in self.scan(root):
            if item["id"] == want:
                path = (root / item["name"]).resolve()
                if path.parent == root and path.is_file():
                    return path
        return None

    def resolve_drop(self, file_id: str) -> Path | None:
        return self.resolve(self.drop_directory(), file_id)

    def resolve_outbox(self, file_id: str) -> Path | None:
        return self.resolve(self.outbox_directory(), file_id)

    @staticmethod
    def removable_directory(target_path: Path) -> Path:
        return (target_path / "One Link Courier").resolve()

    def _contained_removable_directory(self, target_path: Path) -> Path:
        root = self.removable_directory(target_path)
        if target_path.resolve() not in {root, *root.parents}:
            raise CourierDestinationRejected("Courier target resolved outside the removable drive.")
        return root

    def scan_removable(self, target_path: Path) -> list[CourierFileInfo]:
        try:
            root = self._contained_removable_directory(target_path)
        except CourierDestinationRejected:
            return []
        return self.scan(root)

    def resolve_removable(self, target_path: Path, file_id: str) -> Path | None:
        try:
            root = self._contained_removable_directory(target_path)
        except CourierDestinationRejected:
            return None
        return self.resolve(root, file_id)

    @staticmethod
    def extract_bundle_text(text: str) -> str:
        stripped = text.strip()
        if not stripped:
            raise ValueError("courier file is empty")
        try:
            parsed = json.loads(stripped)
            if isinstance(parsed, dict):
                bundle = parsed.get("bundle_b64") or parsed.get("bundle")
                if bundle:
                    return str(bundle).strip()
        except json.JSONDecodeError:
            pass
        return stripped

    def read_bundle(self, path: Path) -> str:
        if path.stat().st_size > self.max_file_bytes:
            raise ValueError("courier file exceeds the size limit")
        return self.extract_bundle_text(path.read_text(encoding="utf-8"))

    def stage_export(
        self,
        bundle_b64: str,
        manifest: Mapping[str, object],
        *,
        name: str,
    ) -> Path:
        bundle_id = str(manifest.get("bundle_id") or secrets.token_hex(16))
        if not name.lower().endswith(".olcb.json"):
            name = f"{Path(name).stem or bundle_id}.olcb.json"
        root = self.outbox_directory()
        out_path = (root / name).resolve()
        if out_path.parent != root.resolve():
            out_path = root / f"{bundle_id}.olcb.json"
        if out_path.exists():
            out_path = root / f"{out_path.stem}.{bundle_id[:8]}.olcb.json"
        body = json.dumps(
            {
                "type": "one-link-courier-bundle",
                "version": 1,
                "bundle_b64": bundle_b64,
                "manifest": dict(manifest),
            },
            ensure_ascii=False,
            indent=2,
        )
        tmp = out_path.with_name(f".{out_path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
        try:
            tmp.write_text(body, encoding="utf-8")
            os.replace(tmp, out_path)
        finally:
            with contextlib.suppress(FileNotFoundError):
                tmp.unlink()
        return out_path

    @staticmethod
    def _copy_into(source: Path, root: Path) -> Path:
        root = root.resolve()
        root.mkdir(parents=True, exist_ok=True)
        dest = (root / source.name).resolve()
        if dest.parent != root:
            raise ValueError("destination escaped courier folder")
        if dest.exists():
            dest = root / f"{source.stem}.{secrets.token_hex(4)}{source.suffix}"
        tmp = dest.with_name(f".{dest.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
        try:
            shutil.copyfile(source, tmp)
            os.replace(tmp, dest)
        finally:
            with contextlib.suppress(FileNotFoundError):
                tmp.unlink()
        return dest

    def copy_to_removable(self, source: Path, target_path: Path) -> Path:
        return self._copy_into(source, self._contained_removable_directory(target_path))

    def copy_to_drop(self, source: Path) -> Path:
        return self._copy_into(source, self.drop_directory())


@dataclass(frozen=True)
class CourierDirectorySnapshot:
    changed: bool
    drop_files: list[CourierFileInfo]
    outbox_files: list[CourierFileInfo]


class CourierDirectoryMonitor:
    """Catalog-change state; the caller owns scheduling and event delivery."""

    def __init__(
        self,
        catalog: CourierFileCatalog,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.catalog = catalog
        self.clock = clock
        self.drop_signature: tuple[str, ...] = ()
        self.outbox_signature: tuple[str, ...] = ()
        self.last_scan_ms = 0
        self.events = 0

    @staticmethod
    def signature(files: list[CourierFileInfo]) -> tuple[str, ...]:
        return tuple(f"{f['id']}:{f['bytes']}:{f['mtime_ms']}" for f in files)

    def poll(self) -> CourierDirectorySnapshot:
        drop = self.catalog.scan_drop()
        outbox = self.catalog.scan_outbox()
        drop_signature = self.signature(drop)
        outbox_signature = self.signature(outbox)
        changed = drop_signature != self.drop_signature or outbox_signature != self.outbox_signature
        self.drop_signature = drop_signature
        self.outbox_signature = outbox_signature
        self.last_scan_ms = int(self.clock() * 1000)
        if changed:
            self.events += 1
        return CourierDirectorySnapshot(changed, drop, outbox)
