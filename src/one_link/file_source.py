"""Descriptor-bound source identity and stable read lifetimes.

This module owns filesystem mechanics only. It has no daemon, peer, queue,
transport or database dependency; callers choose the opener and identity probe
explicitly when adapting a platform or testing failure behavior.
"""

from __future__ import annotations

import contextlib
import os
import stat
from pathlib import Path
from typing import Any, BinaryIO, Callable, ContextManager, Iterator, Protocol


def windows_open_file_identity(fd: int) -> tuple[str, int]:
    """Return ``(volume:file-id, NT-change-time-ns)`` for one CRT fd.

    ``Path.stat().st_ctime`` is creation time on Windows, not the NTFS change
    time. The latter is what invalidates a cached hash after an in-place,
    same-size rewrite whose last-write timestamp was restored.
    """

    if os.name != "nt":
        return "", 0
    try:
        import ctypes
        import msvcrt
        from ctypes import wintypes

        class _FileBasicInfo(ctypes.Structure):
            _fields_ = [
                ("creation_time", ctypes.c_longlong),
                ("last_access_time", ctypes.c_longlong),
                ("last_write_time", ctypes.c_longlong),
                ("change_time", ctypes.c_longlong),
                ("file_attributes", wintypes.DWORD),
            ]

        class _FileId128(ctypes.Structure):
            _fields_ = [("identifier", ctypes.c_ubyte * 16)]

        class _FileIdInfo(ctypes.Structure):
            _fields_ = [
                ("volume_serial_number", ctypes.c_ulonglong),
                ("file_id", _FileId128),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        get_info = kernel32.GetFileInformationByHandleEx
        get_info.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]
        get_info.restype = wintypes.BOOL
        os_handle = msvcrt.get_osfhandle(int(fd))
        if os_handle == -1:
            return "", 0
        basic = _FileBasicInfo()
        file_id = _FileIdInfo()
        if not get_info(
            wintypes.HANDLE(os_handle),
            0,  # FileBasicInfo
            ctypes.byref(basic),
            ctypes.sizeof(basic),
        ):
            return "", 0
        if not get_info(
            wintypes.HANDLE(os_handle),
            18,  # FileIdInfo
            ctypes.byref(file_id),
            ctypes.sizeof(file_id),
        ):
            return "", 0
        identifier = bytes(file_id.file_id.identifier).hex()
        stable_id = f"{int(file_id.volume_serial_number):016x}:{identifier}"
        # NT LARGE_INTEGER timestamps are 100-ns ticks since 1601. Keeping the
        # epoch is harmless; only exact equality is used.
        return stable_id, int(basic.change_time) * 100
    except (ImportError, OSError, TypeError, ValueError, AttributeError):
        return "", 0


@contextlib.contextmanager
def open_binary_file_no_follow(path: Path) -> Iterator[BinaryIO]:
    """Open one regular-file candidate without following its final link.

    Windows additionally denies write/delete sharing for the lifetime of the
    descriptor, so the identity proven before a scan/send cannot be renamed or
    modified underneath that operation. POSIX uses ``O_NOFOLLOW`` and the
    caller's before/after inode + ctime checks to detect mutation.
    """

    candidate = Path(path)
    if os.name != "nt":
        flags = os.O_RDONLY | int(getattr(os, "O_CLOEXEC", 0))
        flags |= int(getattr(os, "O_NOFOLLOW", 0))
        fd = os.open(candidate, flags)
    else:
        import ctypes
        import msvcrt
        from ctypes import wintypes

        create_file = ctypes.windll.kernel32.CreateFileW
        create_file.argtypes = (
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        )
        create_file.restype = wintypes.HANDLE
        handle = create_file(
            str(candidate),
            0x80000000,  # GENERIC_READ
            0x00000001,  # FILE_SHARE_READ (deny write/delete sharing)
            None,
            3,  # OPEN_EXISTING
            (
                0x00000080  # FILE_ATTRIBUTE_NORMAL
                | 0x00200000  # FILE_FLAG_OPEN_REPARSE_POINT
                | 0x08000000  # FILE_FLAG_SEQUENTIAL_SCAN
            ),
            None,
        )
        invalid_handle = ctypes.c_void_p(-1).value
        if handle == invalid_handle:
            raise ctypes.WinError()
        try:
            fd = msvcrt.open_osfhandle(
                int(handle),
                os.O_RDONLY | int(getattr(os, "O_BINARY", 0)),
            )
        except Exception:
            ctypes.windll.kernel32.CloseHandle(handle)
            raise
    file_handle = os.fdopen(fd, "rb")
    try:
        yield file_handle
    finally:
        file_handle.close()


class FileSource(Protocol):
    """The immutable-source operations required by manifest preparation."""

    def signature(self, path: Path) -> dict[str, Any]: ...

    def signature_is_strong(self, sig: dict[str, Any]) -> bool: ...

    def open_verified(self, path: Path, expected: dict[str, Any]) -> ContextManager[BinaryIO]: ...


class DescriptorFileSource:
    """Obtain identities and hold the exact indexed file through an operation."""

    def __init__(
        self,
        *,
        opener: Callable[[Path], ContextManager[BinaryIO]] = open_binary_file_no_follow,
        windows_identity: Callable[[int], tuple[str, int]] = windows_open_file_identity,
    ) -> None:
        self._open_file = opener
        self._windows_identity = windows_identity

    @staticmethod
    def signature_fields() -> tuple[str, ...]:
        return (
            "path",
            "size",
            "mtime_ns",
            "ctime_ns",
            "dev",
            "ino",
            "file_id",
            "change_ns",
        )

    def signature_from_handle(
        self,
        path: Path,
        handle: BinaryIO,
    ) -> dict[str, Any]:
        """Capture path + descriptor identity without trusting pathname stat."""

        canonical = Path(path).expanduser().resolve(strict=True)
        path_stat = canonical.lstat()
        opened_stat = os.fstat(handle.fileno())
        reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
        if (
            stat.S_ISLNK(path_stat.st_mode)
            or not stat.S_ISREG(path_stat.st_mode)
            or bool(int(getattr(path_stat, "st_file_attributes", 0) or 0) & reparse_flag)
            or not stat.S_ISREG(opened_stat.st_mode)
        ):
            raise ValueError("outbound source must be a regular non-reparse file")
        if any(
            int(getattr(path_stat, field, 0) or 0) != int(getattr(opened_stat, field, 0) or 0)
            for field in ("st_dev", "st_ino", "st_size")
        ):
            raise OSError("outbound source changed while opening")
        dev = int(getattr(opened_stat, "st_dev", 0) or 0)
        ino = int(getattr(opened_stat, "st_ino", 0) or 0)
        if os.name == "nt":
            file_id, change_ns = self._windows_identity(handle.fileno())
        else:
            file_id = f"{dev:x}:{ino:x}" if dev and ino else ""
            change_ns = int(opened_stat.st_ctime_ns)
        return {
            "path": str(canonical),
            "size": int(opened_stat.st_size),
            "mtime_ns": int(opened_stat.st_mtime_ns),
            "ctime_ns": int(opened_stat.st_ctime_ns),
            "dev": dev,
            "ino": ino,
            "file_id": file_id,
            "change_ns": f"{int(change_ns):x}" if int(change_ns) > 0 else "",
        }

    def signature(self, path: Path) -> dict[str, Any]:
        raw = Path(path).expanduser()
        with self._open_file(raw) as handle:
            canonical = raw.resolve(strict=True)
            return self.signature_from_handle(canonical, handle)

    @staticmethod
    def signature_is_strong(sig: dict[str, Any]) -> bool:
        if not sig.get("file_id") or not str(sig.get("change_ns") or ""):
            return False
        return bool(int(sig.get("dev") or 0) and int(sig.get("ino") or 0))

    def assert_signature(self, path: Path, expected: dict) -> None:
        """Fail closed if an outbound source changed after indexing.

        A content hash and CDC map describe one exact byte sequence.  Reading
        a mutable path later without revalidating its identity can send a
        mixture of revisions, cause endless receiver hash failures, or make a
        cached index address bytes it never hashed.  This check is repeated
        immediately before publication, before disk reads, and before marking
        completion.
        """
        try:
            current = self.signature(path)
        except (OSError, ValueError) as exc:
            raise RuntimeError("outbound source disappeared after indexing") from exc
        fields = self.signature_fields()
        if any(current.get(field) != expected.get(field) for field in fields):
            raise RuntimeError("outbound source changed after indexing; choose the file again")

    @contextlib.contextmanager
    def open_verified(
        self,
        path: Path,
        expected: dict[str, Any],
    ) -> Iterator[BinaryIO]:
        """Open the exact indexed file object and hold it through disk reads."""

        canonical = Path(str(expected.get("path") or path))
        with self._open_file(canonical) as handle:
            opened = self.signature_from_handle(canonical, handle)
            fields = self.signature_fields()
            if any(opened.get(field) != expected.get(field) for field in fields):
                raise RuntimeError("outbound source changed after indexing; choose the file again")
            yield handle
            final = self.signature_from_handle(canonical, handle)
            if any(final.get(field) != expected.get(field) for field in fields):
                raise RuntimeError("outbound source changed while sending; delivery aborted")
