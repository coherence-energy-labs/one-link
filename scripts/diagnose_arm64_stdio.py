"""Observe stdout around cryptography 50.0.0's setuptools include-dir probe.

This is an instrumented diagnostic, not a substitute for the exact inline
baseline in arm64_stdio_probe.rs. Imports, diagnostics, and the explicit flush
can change timing. Nothing here closes, replaces, or repairs a standard stream.
The Rust parent captures each invocation in a separate process.
"""

from __future__ import annotations

import json
import os
import sys


_WINDOWS_API = None
_WINDOWS_API_ERROR = None
_SEQUENCE = 0


def _error_details(exc: BaseException) -> dict:
    """Keep error classification without tracebacks, paths, or error text."""
    result = {"error_type": type(exc).__name__}
    for key in ("errno", "winerror"):
        value = getattr(exc, key, None)
        if isinstance(value, int):
            result[key] = value
    return result


def _emit(record: dict) -> None:
    """Use existing stderr; an invalid stderr is itself a diagnostic failure."""
    global _SEQUENCE
    _SEQUENCE += 1
    payload = {
        "schema_version": 1,
        "probe": "setuptools_includes_instrumented",
        "sequence": _SEQUENCE,
        **record,
    }
    sys.stderr.write(json.dumps(payload, ensure_ascii=True, separators=(",", ":")) + "\n")
    sys.stderr.flush()


def _prepare_windows_api() -> None:
    global _WINDOWS_API, _WINDOWS_API_ERROR
    if os.name != "nt":
        return
    try:
        import ctypes
        import msvcrt
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        get_file_type = kernel32.GetFileType
        get_file_type.argtypes = [wintypes.HANDLE]
        get_file_type.restype = wintypes.DWORD
        get_handle_information = kernel32.GetHandleInformation
        get_handle_information.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.DWORD),
        ]
        get_handle_information.restype = wintypes.BOOL
        _WINDOWS_API = (
            ctypes,
            msvcrt,
            wintypes,
            get_file_type,
            get_handle_information,
        )
    except Exception as exc:
        _WINDOWS_API_ERROR = _error_details(exc)


def _stdout_snapshot(stage: str, *, native_inspection: bool = True) -> None:
    snapshot = {"stage": stage, "record": "stdout_checkpoint"}
    stream = sys.stdout
    snapshot["stdout_present"] = stream is not None
    if stream is None:
        _emit(snapshot)
        return

    for name in ("closed", "encoding", "line_buffering", "write_through"):
        try:
            snapshot[name] = getattr(stream, name, None)
        except Exception as exc:
            snapshot[name] = _error_details(exc)

    try:
        fd = stream.fileno()
        snapshot["fileno"] = fd
    except Exception as exc:
        snapshot["fileno"] = _error_details(exc)
        _emit(snapshot)
        return

    try:
        stat_result = os.fstat(fd)
        snapshot["fstat"] = {"ok": True, "mode": stat_result.st_mode}
    except Exception as exc:
        snapshot["fstat"] = {"ok": False, **_error_details(exc)}

    if not native_inspection:
        snapshot["windows_handle_inspection"] = "not_initialized"
    elif os.name != "nt":
        snapshot["windows_handle_inspection"] = "not_windows"
    elif _WINDOWS_API is None:
        snapshot["windows_handle_inspection"] = {
            "available": False,
            **(_WINDOWS_API_ERROR or {}),
        }
    else:
        ctypes, msvcrt, wintypes, get_file_type, get_handle_information = _WINDOWS_API
        try:
            handle = msvcrt.get_osfhandle(fd)
            snapshot["osfhandle"] = {"ok": True, "value": handle}

            ctypes.set_last_error(0)
            file_type = int(get_file_type(wintypes.HANDLE(handle)))
            file_type_error = ctypes.get_last_error()
            snapshot["get_file_type"] = {
                "value": file_type,
                "kind": {0: "unknown", 1: "disk", 2: "character", 3: "pipe"}.get(
                    file_type & 0x7FFF, "other"
                ),
                "last_error": file_type_error,
                "call_failed": file_type == 0 and file_type_error != 0,
            }

            flags = wintypes.DWORD()
            ctypes.set_last_error(0)
            information_ok = bool(
                get_handle_information(wintypes.HANDLE(handle), ctypes.byref(flags))
            )
            information_error = ctypes.get_last_error()
            snapshot["get_handle_information"] = {
                "ok": information_ok,
                "last_error": information_error,
                "flags": int(flags.value) if information_ok else None,
            }
        except Exception as exc:
            snapshot["native_inspection_error"] = _error_details(exc)
    _emit(snapshot)


def _versions() -> None:
    # Version discovery is deliberately after the include-dir print and flush.
    # It must not add imports before the operation we are observing.
    import importlib.metadata
    import platform
    import struct
    import sysconfig

    packages = {}
    for name in ("setuptools", "maturin", "cffi", "pycparser"):
        try:
            packages[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            packages[name] = None
        except Exception as exc:
            packages[name] = _error_details(exc)
    _emit(
        {
            "record": "runtime_versions",
            "python_version": list(sys.version_info[:3]),
            "sys_version": sys.version,
            "implementation": sys.implementation.name,
            "machine": platform.machine(),
            "sysconfig_platform": sysconfig.get_platform(),
            "pointer_bits": struct.calcsize("P") * 8,
            "executable_logical_name": os.path.basename(sys.executable),
            "in_venv": sys.prefix != sys.base_prefix,
            "package_versions": packages,
        }
    )


def main() -> int:
    stage = "startup"
    try:
        _stdout_snapshot("startup_before_windows_support", native_inspection=False)
        _prepare_windows_api()
        stage = "before_setuptools_imports"
        _stdout_snapshot(stage)

        import setuptools.dist
        import setuptools.command.build_ext

        stage = "after_setuptools_imports"
        _stdout_snapshot(stage)
        distribution = setuptools.dist.Distribution()
        stage = "after_distribution"
        _stdout_snapshot(stage)
        builder = setuptools.command.build_ext.build_ext(distribution)
        stage = "after_build_ext"
        _stdout_snapshot(stage)
        builder.finalize_options()
        stage = "after_finalize_options"
        _stdout_snapshot(stage)
        stage = "before_print"
        _stdout_snapshot(stage)
        print(os.pathsep.join(builder.include_dirs), end="")
        stage = "after_print"
        _stdout_snapshot(stage)
        stage = "before_flush"
        _stdout_snapshot(stage)
        sys.stdout.flush()
        stage = "after_flush"
        _stdout_snapshot(stage)
        stage = "version_metadata"
        _versions()
        stage = "before_exit"
        _stdout_snapshot(stage)
        return 0
    except Exception as exc:
        try:
            _emit({"record": "probe_exception", "stage": stage, **_error_details(exc)})
        except Exception:
            # Do not create a substitute stream or hide the failing exit code.
            pass
        if stage != "version_metadata":
            try:
                _versions()
            except Exception as metadata_exc:
                try:
                    _emit({"record": "version_metadata_error", **_error_details(metadata_exc)})
                except Exception:
                    pass
        try:
            _stdout_snapshot("after_failure_before_exit")
        except Exception:
            pass
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
