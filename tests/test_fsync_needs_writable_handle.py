"""``os.fsync`` is never called on a handle that was opened read-only.

Windows implements ``os.fsync`` with ``FlushFileBuffers``, which needs write
access: on a handle from ``open(path, "rb")`` it fails with EBADF. POSIX
accepts the same call, so the mistake is invisible on Linux and macOS and
fatal on Windows. This scan runs everywhere.

Directory handles are a different matter (``os.open(..., O_RDONLY)`` is the
only way to sync a directory on POSIX, and the callers skip Windows); the
scan covers ``open()`` and ``Path.open()`` with a literal mode.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCANNED = ("src/one_link", "scripts")
WRITE_FLAGS = frozenset("wax+")


def _literal_mode(call: ast.Call) -> str | None:
    """The mode of an ``open()``/``Path.open()`` call, or None when unknown."""
    builtin = isinstance(call.func, ast.Name) and call.func.id == "open"
    method = isinstance(call.func, ast.Attribute) and call.func.attr == "open"
    if not (builtin or method):
        return None
    if method and isinstance(call.func.value, ast.Name) and call.func.value.id == "os":
        return None  # os.open takes flags
    position = 1 if builtin else 0
    node = call.args[position] if len(call.args) > position else None
    for keyword in call.keywords:
        if keyword.arg == "mode":
            node = keyword.value
    if node is None:
        return "r"
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _fsynced_names(body: list[ast.stmt]) -> set[str]:
    names: set[str] = set()
    for statement in body:
        for node in ast.walk(statement):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "fsync"
                and node.args
            ):
                continue
            arg = node.args[0]
            if (
                isinstance(arg, ast.Call)
                and isinstance(arg.func, ast.Attribute)
                and arg.func.attr == "fileno"
                and isinstance(arg.func.value, ast.Name)
            ):
                names.add(arg.func.value.id)
    return names


def read_only_fsyncs(source: str, label: str) -> list[str]:
    found = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, (ast.With, ast.AsyncWith)):
            continue
        synced = _fsynced_names(node.body)
        for item in node.items:
            if not (isinstance(item.context_expr, ast.Call) and isinstance(item.optional_vars, ast.Name)):
                continue
            mode = _literal_mode(item.context_expr)
            if mode is None or WRITE_FLAGS & set(mode):
                continue
            if item.optional_vars.id in synced:
                found.append(f"{label}:{node.lineno}: os.fsync on a handle opened {mode!r}")
    return found


def test_no_fsync_on_a_read_only_handle() -> None:
    found = []
    scanned = 0
    for directory in SCANNED:
        for path in sorted((ROOT / directory).rglob("*.py")):
            scanned += 1
            found += read_only_fsyncs(path.read_text(encoding="utf-8"), path.relative_to(ROOT).as_posix())
    assert scanned > 100, "the scan did not find the source tree"
    assert not found, (
        "os.fsync fails with EBADF on Windows for a read-only handle; open the file "
        'with "r+b" before syncing it:\n' + "\n".join(found)
    )


def test_the_scan_sees_the_mistake_it_exists_for() -> None:
    offenders = {
        "builtin": 'with open(p, "rb") as fh:\n    os.fsync(fh.fileno())\n',
        "default mode": "with open(p) as fh:\n    os.fsync(fh.fileno())\n",
        "path method": 'with p.open("rb") as fh:\n    os.fsync(fh.fileno())\n',
        "keyword mode": 'with open(p, mode="r") as fh:\n    data = fh.read()\n    os.fsync(fh.fileno())\n',
        "nested": 'with open(p, "rb") as fh:\n    if ok:\n        os.fsync(fh.fileno())\n',
    }
    for name, source in offenders.items():
        assert read_only_fsyncs(source, name), f"missed: {name}"

    fine = {
        "read-write": 'with open(p, "r+b") as fh:\n    os.fsync(fh.fileno())\n',
        "write": 'with p.open("wb") as fh:\n    fh.write(b"x")\n    os.fsync(fh.fileno())\n',
        "append": 'with open(p, "ab") as fh:\n    os.fsync(fh.fileno())\n',
        "read without sync": 'with open(p, "rb") as fh:\n    data = fh.read()\n',
        "another handle synced": 'with open(p, "rb") as src, open(q, "wb") as dst:\n    os.fsync(dst.fileno())\n',
        "os.open flags": "with os.open(p, flags) as fd:\n    os.fsync(fd)\n",
    }
    for name, source in fine.items():
        assert not read_only_fsyncs(source, name), f"false alarm: {name}"
