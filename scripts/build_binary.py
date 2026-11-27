"""Build a self-contained PyInstaller onedir application for One Link.

Works on Windows, macOS, and Linux.  The launcher is intentionally accompanied
by PyInstaller's ``_internal`` runtime tree; copying or publishing the launcher
alone produces an application that cannot start.
Requires PyInstaller in the active environment:

    pip install pyinstaller

Usage:

    python scripts/build_binary.py
    python scripts/build_binary.py --gui          # windowed (no console)
    python scripts/build_binary.py --include-preview-ml
                                                  # research build only

Output goes to ``dist/one-link/one-link.exe`` on Windows,
``dist/one-link.app`` for the default macOS GUI build, and
``dist/one-link/one-link`` on Linux. Release tooling must archive the complete
onedir/application bundle, never the launcher by itself.

Preview ML bundling:

Stable artifacts deliberately exclude the semantic voice/scene checkpoints,
ONNX Runtime, and preview-only codec modules.  The browser media pipeline does
not yet capture, negotiate, transport, reconstruct, and play these formats end
to end, so shipping their assets by default would add weight without adding a
stable capability.  ``--include-preview-ml`` produces an explicitly labelled
engineering build containing the validated research substrate; it does not
advertise or activate the preview capabilities.

Mandatory native runtime:

Stable standalone builds require an importable ``one_link_native`` package
whose version matches the core package. Its importable submodules are
collected explicitly so the .pyd / .so / .dylib files are bundled without
copying wheel metadata that can contain developer-local paths and
nondeterministic build records. A missing, stale, or wrong-architecture native
wheel fails the build; there is no pure-Python stable-artifact waiver.

Install the matching native wheel before invoking this script, for example:

    pip install one_link_native --find-links \\
      https://github.com/coherence-energy-labs/one-link/releases/latest

The release workflow builds and installs the matching native wheel on each
architecture-specific runner before invoking this script. It also requires a
fresh native CDC sidecar library and executes its ABI known vector before
PyInstaller analysis begins.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import platform
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


_PREVIEW_MODEL_DIRS = (
    "voice_predictor_v3_librispeech",
    "scene_predictor_v1",
)
_PREVIEW_RUNTIME_MODULES = ("numpy", "scipy", "onnxruntime")
_PREVIEW_HIDDEN_IMPORTS = (
    "numpy",
    "scipy.fft",
    "scipy.signal",
    "one_link.semantic_voice_codec",
    "one_link.semantic_scene_codec",
    "one_link.ml",
    "one_link.ml.mfcc",
    "one_link.ml.onnx_oracles",
    "one_link.ml.speech_synth",
)


def _collect_preview_model_files(models_dir: Path) -> list[Path]:
    """Return the complete, validated ONNX preview-model payload.

    ONNX may store tensor weights in a sibling ``checkpoint.onnx.data`` file.
    Selecting only ``checkpoint.onnx`` creates a bundle that looks complete but
    cannot initialize the voice session.  Keep collection explicit and fail
    closed when a required checkpoint/config is absent or malformed.
    """
    if not models_dir.is_dir():
        raise RuntimeError(f"preview model directory not found: {models_dir}")

    files: list[Path] = []
    for model_name in _PREVIEW_MODEL_DIRS:
        model_dir = models_dir / model_name
        checkpoint = model_dir / "checkpoint.onnx"
        config = model_dir / "config.json"
        missing = [path for path in (checkpoint, config) if not path.is_file()]
        if missing:
            rendered = ", ".join(str(path) for path in missing)
            raise RuntimeError(f"preview model payload is incomplete: {rendered}")
        if checkpoint.stat().st_size <= 0:
            raise RuntimeError(f"preview ONNX checkpoint is empty: {checkpoint}")
        try:
            parsed_config = json.loads(config.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"invalid preview model config {config}: {exc}") from exc
        if not isinstance(parsed_config, dict):
            raise RuntimeError(f"preview model config must be an object: {config}")

        files.extend((checkpoint, config))
        files.extend(path for path in sorted(model_dir.glob("checkpoint.onnx.*")) if path.is_file())

    # Deterministic order makes the generated spec reproducible and prevents a
    # duplicated path from being silently packaged twice.
    return sorted(set(files), key=lambda path: path.as_posix())


def _validate_preview_runtime(model_files: list[Path]) -> None:
    """Prove an opt-in preview build has every required runtime component."""
    loaded: dict[str, object] = {}
    for module_name in _PREVIEW_RUNTIME_MODULES:
        try:
            loaded[module_name] = importlib.import_module(module_name)
        except ImportError as exc:
            raise RuntimeError(
                "--include-preview-ml requires the locked 'preview-ml' extra; "
                "run `uv sync --frozen --extra release --extra preview-ml` "
                f"(missing {module_name})"
            ) from exc

    ort = loaded["onnxruntime"]
    for checkpoint in (path for path in model_files if path.name == "checkpoint.onnx"):
        try:
            session = ort.InferenceSession(  # type: ignore[attr-defined]
                str(checkpoint), providers=["CPUExecutionProvider"]
            )
        except Exception as exc:
            raise RuntimeError(
                f"preview ONNX checkpoint cannot initialize: {checkpoint}: {exc}"
            ) from exc
        if not session.get_inputs() or not session.get_outputs():
            raise RuntimeError(f"preview ONNX checkpoint has no usable interface: {checkpoint}")


def _remove_tree_required(path: Path) -> bool:
    """Remove a build directory and report whether it is provably gone.

    PyInstaller/Defender can briefly hold ``*.pkg`` files after a build, but
    continuing after a partial cleanup could package stale files.  Release
    packaging therefore fails closed and asks the operator to retry.
    """
    try:
        shutil.rmtree(path)
    except OSError as exc:
        print(f"[build] could not fully remove {path}: {exc}")
        return False
    return not path.exists()


def _discard_invalid_artifact(executable: Path, bundle: Path | None) -> bool:
    """Remove a built artifact that failed its mandatory execution smoke.

    A launcher that times out, cannot execute, or exits non-zero is not a
    releasable artifact.  Leaving it in ``dist`` makes later packaging steps
    vulnerable to publishing a known-bad prior result, so cleanup is part of
    the fail-closed contract rather than a best-effort courtesy.
    """
    target = bundle if bundle is not None else executable
    if target.is_dir():
        return _remove_tree_required(target)
    try:
        target.unlink()
    except OSError as exc:
        print(f"[build] could not remove invalid artifact {target}: {exc}")
        return False
    return not target.exists()


def _split_pyinstaller_pairs(items: list[str], sep: str) -> list[tuple[str, str]]:
    """Convert CLI-style --add-data/--add-binary args into spec tuples."""
    out: list[tuple[str, str]] = []
    pending_flag = False
    for item in items:
        if item in {"--add-data", "--add-binary"}:
            pending_flag = True
            continue
        if sep not in item:
            if pending_flag:
                pending_flag = False
            continue
        src, dest = item.split(sep, 1)
        if src and dest:
            out.append((src.replace("\\", "/"), dest.replace("\\", "/")))
        pending_flag = False
    return out


def _validated_staged_native_cdc(stage_dir: Path) -> tuple[Path, Path]:
    """Return a freshly staged CDC library and its verified sidecar.

    Public packaging must never consume the tracked package copy: that can be
    stale even when the compiler subprocess reports success, and rebuilding it
    mutates source checkout state.  The caller gives this helper the build-only
    staging directory populated by ``build_native_cdc.py --output-dir``.
    """
    from one_link.native_cdc import native_library_name, validate_native_cdc_library

    library = stage_dir / native_library_name()
    sidecar = library.with_suffix(library.suffix + ".sha256")
    for label, path in (("library", library), ("SHA-256 sidecar", sidecar)):
        if path.is_symlink() or not path.is_file():
            raise RuntimeError(f"staged native CDC {label} is missing: {path}")
    if library.stat().st_size <= 0:
        raise RuntimeError(f"staged native CDC library is empty: {library}")

    digest = hashlib.sha256(library.read_bytes()).hexdigest()
    try:
        sidecar_text = sidecar.read_text(encoding="ascii")
    except (OSError, UnicodeError) as exc:
        raise RuntimeError(f"staged native CDC sidecar cannot be read: {sidecar}: {exc}") from exc
    expected = f"{digest}  {library.name}\n"
    if sidecar_text != expected:
        raise RuntimeError(
            f"staged native CDC sidecar does not match the freshly built library: {sidecar}"
        )
    try:
        validate_native_cdc_library(library)
    except Exception as exc:
        raise RuntimeError(
            f"staged native CDC library failed its ABI known vector: {library}: {exc}"
        ) from exc
    return library, sidecar


def _runtime_source_manifest_bytes(repo: Path) -> bytes:
    """Return the canonical stable Python source/code contract for ``repo``.

    PyInstaller stores modules in its PYZ archive, so a file-tree inventory
    alone cannot distinguish current bytecode from a stale archive assembled
    with the same version and module names.  This manifest is generated from
    the immutable source input immediately before Analysis runs.  The release
    verifier independently rebuilds it from the checkout and compares it with
    both the packaged manifest and code objects loaded by the frozen process.
    """
    from one_link.build_identity import (
        EXPECTED_STABLE_RUNTIME_MODULES,
        EXPECTED_STABLE_RUNTIME_MODULES_SHA256,
        normalized_code_sha256,
        stable_module_source_path,
    )

    package_root = (repo / "src" / "one_link").resolve()
    modules: dict[str, dict[str, str]] = {}
    for module in EXPECTED_STABLE_RUNTIME_MODULES:
        source_path = stable_module_source_path(package_root, module)
        try:
            metadata = source_path.lstat()
        except OSError as exc:
            raise RuntimeError(
                f"stable runtime source is missing or unreadable: {source_path}: {exc}"
            ) from exc
        if source_path.is_symlink() or not source_path.is_file():
            raise RuntimeError(
                f"stable runtime source must be a physical regular file: {source_path}"
            )
        try:
            source = source_path.read_bytes()
            after = source_path.stat()
        except OSError as exc:
            raise RuntimeError(
                f"stable runtime source could not be read: {source_path}: {exc}"
            ) from exc
        identity_before = (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        )
        if identity_before != identity_after:
            raise RuntimeError(f"stable runtime source changed during build: {source_path}")
        try:
            code = compile(
                source,
                str(source_path),
                "exec",
                dont_inherit=True,
                optimize=sys.flags.optimize,
            )
        except (SyntaxError, ValueError) as exc:
            raise RuntimeError(
                f"stable runtime source cannot be compiled: {source_path}: {exc}"
            ) from exc
        relative = source_path.relative_to(package_root).as_posix()
        modules[module] = {
            "source_path": relative,
            "source_sha256": hashlib.sha256(source).hexdigest(),
            "normalized_code_sha256": normalized_code_sha256(code),
        }

    payload = {
        "schema": "one-link-runtime-source-manifest-v1",
        "python_cache_tag": sys.implementation.cache_tag,
        "python_optimization": sys.flags.optimize,
        "runtime_module_manifest_sha256": EXPECTED_STABLE_RUNTIME_MODULES_SHA256,
        "modules": modules,
    }
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _resolve_build_commit(repo: Path) -> str:
    """The commit being packaged: CI's SHA, an explicit override, else git.

    Order matters. GITHUB_SHA is authoritative in CI because the checkout may be
    detached and `git rev-parse HEAD` on a merge ref can name a commit that does
    not exist upstream.
    """

    for key in ("ONE_LINK_BUILD_COMMIT", "GITHUB_SHA"):
        value = (os.environ.get(key) or "").strip().lower()
        if len(value) == 40:
            try:
                bytes.fromhex(value)
                return value
            except ValueError:
                pass
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(repo),
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    candidate = (out.stdout or "").strip().lower()
    if out.returncode != 0 or len(candidate) != 40:
        return ""
    try:
        bytes.fromhex(candidate)
    except ValueError:
        return ""
    return candidate


def _write_build_stamp(destination_dir: Path) -> Path | None:
    """Write the bundled build stamp, or None when the commit is unknown.

    An unstamped artifact degrades to "cannot compare" rather than claiming a
    version it cannot substantiate, which is the honest failure: a bogus commit
    would make every installed copy nag about an update forever. In CI the
    commit is always known, so this refusing path only affects an exported
    source tree with no git and no override.

    The file name comes from build_info.STAMP_FILENAME, never from here:
    PyInstaller keeps the source basename when bundling into a destination
    directory, and build_info only ever reads that exact name, so a locally
    chosen name would ship a stamp the running app can never find.
    """

    repo = Path(__file__).resolve().parent.parent
    commit = _resolve_build_commit(repo)
    if not commit:
        print(
            "[build] WARNING: no build commit available (no GITHUB_SHA, no "
            "ONE_LINK_BUILD_COMMIT, no git). The artifact will not be able to "
            "detect that it is out of date."
        )
        return None
    sys.path.insert(0, str(repo / "src"))
    try:
        from one_link.build_info import STAMP_FILENAME, write_stamp
    finally:
        sys.path.pop(0)
    ref = (os.environ.get("GITHUB_REF") or "").strip()
    channel = "release" if ref.startswith("refs/tags/v") else "rolling"
    destination_dir.mkdir(parents=True, exist_ok=True)
    stamp = write_stamp(
        destination_dir / STAMP_FILENAME,
        commit=commit,
        built_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        channel=channel,
    )
    print(f"[build] stamped {channel} build {commit[:12]} -> {stamp.name}")
    return stamp


def _materialize_bundle_symlinks(bundle_root: Path) -> int:
    """Replace intra-bundle symlinks with real copies of their targets.

    A link whose target dangles or escapes the bundle is a packaging error
    and fails the build rather than shipping a broken member.
    """

    root = bundle_root.resolve()
    replaced = 0
    for path in sorted(bundle_root.rglob("*")):
        if not path.is_symlink():
            continue
        target = path.resolve(strict=False)
        if not target.is_file() or not target.is_relative_to(root):
            raise RuntimeError(
                f"bundle symlink dangles or escapes the bundle: {path} -> {target}"
            )
        data = target.read_bytes()
        path.unlink()
        path.write_bytes(data)
        shutil.copystat(target, path)
        replaced += 1
    return replaced


def _rebind_bundled_native_sidecars(bundle_root: Path) -> None:
    """Bind CDC and native-shell sidecars to their final bundled bytes.

    Bundling may legitimately rewrite the library after staging (macOS
    ad-hoc code-signing); the sidecar's whole purpose is to bind the shipped
    bytes exactly, so it is recomputed here. LF bytes are load-bearing (see
    scripts/build_native_cdc.py). A sidecar with no resolvable library is a
    packaging error and fails the build.
    """

    repo = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(repo / "src"))
    try:
        from one_link.native_cdc import native_library_name
    finally:
        sys.path.pop(0)
    library_name = native_library_name()
    shell_name = "ol_shell.exe" if sys.platform == "win32" else "ol_shell"
    for binary_name in (library_name, shell_name):
        sidecars = [
            candidate
            for candidate in bundle_root.rglob(binary_name + ".sha256")
            if candidate.is_file() and not candidate.is_symlink()
        ]
        if not sidecars:
            # Packaging-unit fixtures can stub all collected binaries. The
            # release gate independently requires the real binary pairs.
            continue
        binaries = [
            candidate
            for candidate in bundle_root.rglob(binary_name)
            if candidate.is_file()
        ]
        if not binaries:
            raise RuntimeError(f"bundle contains no native binary named {binary_name}")
        digest = hashlib.sha256(binaries[0].read_bytes()).hexdigest()
        for other in binaries[1:]:
            if hashlib.sha256(other.read_bytes()).hexdigest() != digest:
                raise RuntimeError(
                    "bundle contains divergent native binary copies: "
                    f"{binaries[0]} vs {other}"
                )
        line = f"{digest}  {binary_name}\n"
        for sidecar in sidecars:
            if sidecar.read_text(encoding="ascii") != line:
                sidecar.write_text(line, encoding="ascii", newline="\n")
                print(f"[build] rebound native sidecar to shipped bytes: {sidecar}")


def _write_runtime_source_manifest(repo: Path, destination: Path) -> Path:
    """Freeze the exact stable Python source/code contract used by this build."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(_runtime_source_manifest_bytes(repo))
    return destination


def _verify_runtime_sources_unchanged(repo: Path, manifest: Path) -> None:
    """Fail if stable source moved after the build snapshot was captured.

    PyInstaller analysis can take several minutes.  Without an end-of-build
    comparison, a concurrent editor can produce an artifact whose PYZ archive
    and embedded source manifest describe different revisions.  Such an
    artifact must never be reported as successful or left in ``dist``.
    """
    try:
        frozen_contract = manifest.read_bytes()
    except OSError as exc:
        raise RuntimeError(f"build source manifest is unreadable: {manifest}: {exc}") from exc
    current_contract = _runtime_source_manifest_bytes(repo)
    if current_contract != frozen_contract:
        raise RuntimeError(
            "stable runtime source changed while PyInstaller was building; "
            "discard this mixed-revision artifact and rebuild from a stable checkout"
        )


def _render_spec(
    *,
    name: str,
    entry: str,
    excludes: list[str],
    hidden_imports: list[str],
    collect_submodules: list[str],
    collect_all: list[str],
    add_data_args: list[str],
    add_binary_args: list[str],
    hook_paths: list[str],
    icon: str,
    console: bool,
    forbidden_path_fragments: list[str],
    macos_bundle: bool = False,
    bundle_identifier: str = "earth.weareone.one-link",
    bundle_version: str = "0.21.0",
    target_arch: str | None = None,
    include_preview_ml: bool = False,
) -> str:
    sep = ";" if platform.system() == "Windows" else ":"
    datas = _split_pyinstaller_pairs(add_data_args, sep)
    binaries = _split_pyinstaller_pairs(add_binary_args, sep)

    lines: list[str] = [
        "# Auto-generated by scripts/build_binary.py. Do not edit by hand.",
        "# This spec wraps PyInstaller Analysis with a post-filter",
        "# that strips heavy training/GPU dependencies discovered transitively.",
        "# -*- mode: python ; coding: utf-8 -*-",
        "",
        "from PyInstaller.utils.hooks import collect_submodules, collect_all",
        "",
        "block_cipher = None",
        f"ONE_LINK_PREVIEW_ML = {include_preview_ml!r}",
        "",
        f"datas = {datas!r}",
        f"binaries = {binaries!r}",
        f"hiddenimports = {hidden_imports!r}",
        "",
    ]
    for module in collect_submodules:
        lines.append(f"hiddenimports += collect_submodules({module!r})")
    for module in collect_all:
        lines.extend(
            [
                f"_d, _b, _h = collect_all({module!r})",
                "datas += _d",
                "binaries += _b",
                "hiddenimports += _h",
            ]
        )
    lines.extend(
        [
            "",
            "a = Analysis(",
            f"    [{entry!r}],",
            "    pathex=[],",
            "    binaries=binaries,",
            "    datas=datas,",
            "    hiddenimports=hiddenimports,",
            f"    hookspath={hook_paths!r},",
            "    runtime_hooks=[],",
            f"    excludes={excludes!r},",
            "    win_no_prefer_redirects=False,",
            "    win_private_assemblies=False,",
            "    cipher=block_cipher,",
            "    noarchive=False,",
            ")",
            "",
            f"_FORBIDDEN = {forbidden_path_fragments!r}",
            "def _allowed(entry):",
            "    src = entry[1] if len(entry) > 1 else ''",
            "    norm = src.replace('\\\\', '/')",
            "    return not any(f in norm or f.replace('/', '\\\\') in src for f in _FORBIDDEN)",
            "",
            "_orig_bin = list(a.binaries)",
            "_orig_dat = list(a.datas)",
            "a.binaries = [e for e in a.binaries if _allowed(e)]",
            "a.datas = [e for e in a.datas if _allowed(e)]",
            "print(f'[build/spec] post-filter dropped {len(_orig_bin) - len(a.binaries)} binaries '",
            "      f'+ {len(_orig_dat) - len(a.datas)} datas (heavy-deps filter)')",
            "",
            "pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)",
            "",
            "# --onedir layout: EXE() gets ONLY the script + PYZ, then",
            "# COLLECT() places binaries + datas alongside in a sibling",
            "# directory. This eliminates the PyInstaller --onefile",
            "# self-extracting bootloader (which copied the 110MB bundle",
            "# to %TEMP%\\_MEI<random>\\ on every launch — 30-60s wait +",
            "# 'Failed to remove temporary directory' warnings when the",
            "# detached daemon held files the launcher tried to clean up).",
            "# Onedir launches in ~2s with zero extraction.",
            "exe = EXE(",
            "    pyz,",
            "    a.scripts,",
            "    [],",
            "    exclude_binaries=True,",
            f"    name={name!r},",
            "    debug=False,",
            "    bootloader_ignore_signals=False,",
            "    strip=False,",
            "    upx=False,",
            f"    console={console!r},",
            "    disable_windowed_traceback=False,",
            "    argv_emulation=False,",
            f"    target_arch={target_arch!r},",
            "    codesign_identity=None,",
            "    entitlements_file=None,",
            f"    icon={icon!r}," if icon else "    icon=None,",
            ")",
            "",
            "coll = COLLECT(",
            "    exe,",
            "    a.binaries,",
            "    a.zipfiles,",
            "    a.datas,",
            "    strip=False,",
            "    upx=False,",
            "    upx_exclude=[],",
            f"    name={name!r},",
            ")",
            "",
        ]
    )
    if macos_bundle:
        # PyInstaller's BUNDLE() wraps the COLLECT output in a proper
        # ``.app`` directory layout (Contents/MacOS/, Contents/Resources/,
        # Contents/Info.plist) — the canonical macOS way to ship an
        # application. Without this block, dist/ ships only a raw
        # ``one-link/`` folder which Finder treats as a Unix-executable
        # blob, not a clickable app. info_plist values seed Spotlight,
        # Dock title, and `defaults read` metadata so the app feels
        # native.
        lines.extend(
            [
                "app = BUNDLE(",
                "    coll,",
                f"    name={name + '.app'!r},",
                f"    icon={icon!r}," if icon else "    icon=None,",
                f"    bundle_identifier={bundle_identifier!r},",
                "    info_plist={",
                "        'CFBundleName': 'One Link',",
                "        'CFBundleDisplayName': 'One Link',",
                f"        'CFBundleShortVersionString': {bundle_version!r},",
                f"        'CFBundleVersion': {bundle_version!r},",
                "        # No login items, no background launch agents,",
                "        # no document type associations beyond what's",
                "        # genuinely needed. The daemon spawns from the",
                "        # app itself; macOS does not need to know.",
                "        'LSMinimumSystemVersion': '11.0',",
                "        'LSUIElement': False,",
                "        'NSHighResolutionCapable': True,",
                "        'NSHumanReadableCopyright': 'I am One. You are One. We are One.',",
                "        'NSRequiresAquaSystemAppearance': False,",
                "    },",
                ")",
                "",
            ]
        )
    return "\n".join(lines)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    # GUI/windowed is the default: end-user clicks the desktop icon, the
    # daemon should run silently in the background — no black console
    # window flashing up. Developers wanting a console for debugging
    # pass --console.
    parser.add_argument(
        "--gui",
        action="store_true",
        default=True,
        help="Build a windowed binary (no console window). DEFAULT.",
    )
    parser.add_argument(
        "--console",
        dest="gui",
        action="store_false",
        help="Build a console binary (visible stdout/stderr). For "
        "debugging only; end users want --gui.",
    )
    preview_group = parser.add_mutually_exclusive_group()
    preview_group.add_argument(
        "--include-preview-ml",
        action="store_true",
        help="Build an engineering-only artifact containing the validated "
        "semantic codec/model research substrate. This does not enable "
        "or advertise a stable call capability.",
    )
    preview_group.add_argument(
        "--no-ml",
        dest="include_preview_ml",
        action="store_false",
        help=argparse.SUPPRESS,
    )
    parser.set_defaults(include_preview_ml=False)
    parser.add_argument(
        "--allow-native-cdc-fallback",
        action="store_true",
        help="Deprecated compatibility flag; always rejected because stable "
        "standalone artifacts require a freshly built native CDC scanner.",
    )
    parser.add_argument(
        "--target-arch",
        default=None,
        help="Deprecated compatibility option; any supplied value is rejected. "
        "Stable binaries must be built on a matching architecture runner so "
        "the Python, Rust extension, and native CDC payload all match.",
    )
    return parser


def _resolve_output_root(
    repository_root: Path,
    output_root: str | Path | None,
) -> Path:
    """Resolve the root that owns all generated packaging artifacts.

    Production callers omit ``output_root`` and retain the historical
    ``<repository>/build`` and ``<repository>/dist`` layout.  Tests inject a
    temporary absolute path so exercising fail-closed cleanup can never remove
    a developer's real build or release artifact.  Source inputs deliberately
    continue to come from ``repository_root``.

    This is an internal Python seam, not a command-line option: release jobs
    cannot accidentally redirect or publish an unreviewed output tree.
    """
    if output_root is None:
        return repository_root

    candidate = Path(output_root).expanduser()
    if not candidate.is_absolute():
        raise ValueError("output_root must be an absolute path")
    resolved = candidate.resolve(strict=False)
    if resolved == Path(resolved.anchor):
        raise ValueError("output_root must not be a filesystem root")
    return resolved


def main(
    argv: list[str] | None = None,
    *,
    output_root: str | Path | None = None,
) -> int:
    args = build_arg_parser().parse_args(list(argv or ()))

    repo = Path(__file__).resolve().parent.parent
    artifact_root = _resolve_output_root(repo, output_root)
    entry = repo / "src" / "one_link" / "__main__.py"

    # Stable releases are a native-complete contract.  PyInstaller cannot
    # manufacture a universal binary from single-architecture Rust/CDC wheels;
    # the former target-arch path silently produced a slower, capability-
    # incomplete application.  Build each release matrix architecture on its
    # matching runner instead.
    if args.target_arch:
        print(
            "[build] --target-arch is not supported for stable standalone "
            "artifacts; build on a matching architecture with native wheels"
        )
        return 9
    if args.allow_native_cdc_fallback:
        print(
            "[build] stable standalone artifacts require the compiled CDC "
            "scanner; --allow-native-cdc-fallback is non-releasable"
        )
        return 12

    # Packaging consumes source; it must never repair or rewrite the checkout.
    # A missing entrypoint is a repository defect and therefore fails closed.
    if entry.is_symlink() or not entry.is_file():
        print(f"[build] required source entrypoint is missing or unsafe: {entry}")
        return 7

    try:
        importlib.import_module("PyInstaller")
    except ImportError:
        print("PyInstaller is not installed. Run:  pip install pyinstaller")
        return 2

    try:
        core_module = importlib.import_module("one_link")
        native_module = importlib.import_module("one_link_native")
    except ImportError as exc:
        print(
            "[build] one_link_native is mandatory for a stable standalone "
            f"artifact and could not be imported: {exc}"
        )
        return 10
    core_version = str(getattr(core_module, "__version__", ""))
    native_version = str(getattr(native_module, "__version__", ""))
    if native_version not in {core_version, f"{core_version}.0"}:
        print(
            "[build] native/core version mismatch: "
            f"one_link={core_version!r}, one_link_native={native_version!r}"
        )
        return 11
    native_collect = True

    suffix = ".exe" if platform.system() == "Windows" else ""
    name = "one-link"
    out_name = f"{name}{suffix}"

    # ``repo`` is immutable source input; every generated/cleaned path must be
    # rooted at ``artifact_root``.  Keeping the distinction explicit prevents
    # a unit test (or another embedded caller) from destroying a real artifact.
    build = artifact_root / "build"
    dist = artifact_root / "dist"

    for p in (build, dist):
        if p.exists() and not _remove_tree_required(p):
            print(f"[build] refusing to continue with a partially cleaned {p.name}/ tree")
            return 6
    # PyInstaller 6.x on Python 3.14 has a race where it tries to
    # open build/<name>/base_library.zip for writing without first
    # creating the parent directory. Pre-create it so we never hit
    # that path.
    (build / name).mkdir(parents=True, exist_ok=True)

    staged_native_library: Path | None = None
    staged_native_sidecar: Path | None = None
    staged_native_tag = ""
    from one_link.native_cdc import native_platform_tag

    staged_native_tag = native_platform_tag()
    native_stage = build / "native-cdc" / staged_native_tag
    native_cmd = [
        sys.executable,
        str(repo / "scripts" / "build_native_cdc.py"),
        "--output-dir",
        str(native_stage),
        "--required",
    ]
    native_build = subprocess.run(native_cmd, cwd=repo)
    if native_build.returncode != 0:
        print(f"[build] native CDC build failed: exit {native_build.returncode}")
        print("[build] refusing to package a missing or stale native CDC library")
        return native_build.returncode
    try:
        staged_native_library, staged_native_sidecar = _validated_staged_native_cdc(
            native_stage
        )
    except RuntimeError as exc:
        print(f"[build] native CDC staging validation failed: {exc}")
        print(
            "[build] refusing to package a missing, stale, or "
            "hash-inconsistent native CDC library"
        )
        return 5

    # PyInstaller's --add-data uses ';' on Windows, ':' elsewhere.
    sep = ";" if platform.system() == "Windows" else ":"
    web_dir = repo / "src" / "one_link" / "web"
    add_data_web = f"{web_dir}{sep}one_link/web"
    package_data_dir = repo / "src" / "one_link" / "data"
    add_data_package = (
        [f"{package_data_dir}{sep}one_link/data"] if package_data_dir.is_dir() else []
    )

    # THE CERTIFIED SURFACE. The peer row is drawn from a table whose layout and security laws
    # were discharged over every integer input by the Coherence prover at build time; the product
    # ships the answers, not the prover (see one_link/certified_surface.py).
    #
    # REFUSING TO BUILD WITHOUT IT is the point of this block. If the directory were merely
    # skipped when absent, the bundle would run, `certified_surface.available()` would quietly
    # return False, and every row would fall back to unproven layout -- shipping the claim
    # "this row is proven" with nothing behind it. That failure is invisible from the outside,
    # which is exactly the class this whole mechanism exists to end. A missing artifact is a
    # BUILD failure, and it is regenerated by:
    #     python idem/scripts/emit_certified_views.py --out-dir src/one_link/data/certified
    # ONE LINK'S OWN WINDOW. Built here rather than by the `native/` workspace build, because
    # ol_shell is deliberately its own cargo workspace -- a webview stack is ~260 transitive
    # crates and the daemon's crates should not resolve against them.
    #
    # `--required`: a release that advertises a native window and ships without it degrades to the
    # browser path silently from the user's side. That is the exact silent-claim failure the
    # certified surfaces exist to end, so the build stops instead.
    shell_stage = build / "native-shell"
    # REQUIRED ONLY WHERE THE WINDOW HAS BEEN VERIFIED, which today is Windows.
    #
    # `wry` needs WebKitGTK development packages on Linux and a working macOS SDK; a runner
    # without them fails the cargo build. Hard-failing a Linux release for a window nobody has
    # yet opened on Linux would trade a working product for an unverified feature -- the release
    # simply ships the browser fallback there, which is the behaviour it had yesterday.
    #
    # This is deliberately NOT "best effort everywhere": on Windows the window is verified end to
    # end, so a Windows release that quietly lost it would be exactly the silent-claim failure
    # the certified surfaces exist to end.
    shell_required = sys.platform == "win32"
    shell_cmd = [
        sys.executable,
        str(repo / "scripts" / "build_native_shell.py"),
        "--output-dir",
        str(shell_stage),
    ] + (["--required"] if shell_required else [])
    shell_build = subprocess.run(shell_cmd, cwd=repo)
    if shell_build.returncode != 0:
        print(f"[build] native window build failed: exit {shell_build.returncode}")
        if shell_required:
            print("[build] refusing to package a release that claims a native window it lacks")
            return shell_build.returncode
        print(f"[build] {sys.platform}: packaging WITHOUT the native window; the launcher will "
              "use the browser path and say so")

    # An absent staging directory must not become an empty `--add-data` entry: PyInstaller would
    # accept it and the spec validator would then see a destination with nothing behind it.
    staged_shell = shell_stage / ("ol_shell.exe" if sys.platform == "win32" else "ol_shell")
    add_data_shell = [f"{shell_stage}{sep}."] if staged_shell.is_file() else []

    certified_dir = repo / "src" / "one_link" / "data" / "certified"
    if not (certified_dir / "peer_row.json").is_file():
        print(
            f"  FATAL: the certified surface is missing at {certified_dir / 'peer_row.json'}.\n"
            "  The bundle would run and silently render UNPROVEN rows while the code still\n"
            "  claims a proven surface. Regenerate with idem/scripts/emit_certified_views.py."
        )
        return 6
    # No separate --add-data entry: the artifact lives under `data/`, which is already
    # carried by `add_data_package`. A second entry would stage the same bytes twice.
    runtime_source_manifest = _write_runtime_source_manifest(
        repo,
        build / "release-contract" / "runtime-source-manifest.json",
    )
    add_runtime_contract = [
        f"{runtime_source_manifest}{sep}one_link/_build",
    ]
    # Stamp WHICH COMMIT this artifact came from. Without it every rolling
    # build reports the same __version__, so an installed copy cannot tell it is
    # older than what the download button serves -- and cannot tell its user.
    # Bundled as data rather than written into a .py because the build hashes
    # the source tree for its own manifest, and rewriting a module during
    # packaging would make that record describe bytes never present in git.
    build_stamp = _write_build_stamp(build / "release-contract")
    add_build_stamp = [f"{build_stamp}{sep}one_link"] if build_stamp else []
    add_native: list[str] = []
    add_native_sidecar: list[str] = []
    if staged_native_library is not None and staged_native_sidecar is not None:
        native_destination = f"one_link/native/{staged_native_tag}"
        add_native = [
            "--add-binary",
            f"{staged_native_library}{sep}{native_destination}",
        ]
        add_native_sidecar = [
            "--add-data",
            f"{staged_native_sidecar}{sep}{native_destination}",
        ]

    # Preview-only ML research substrate. Stable/public artifacts leave this
    # out because no browser media-wire E2E path consumes it. An explicit
    # engineering build gets the complete ONNX payload (including external
    # tensor-data sidecars) and is validated before PyInstaller runs.
    add_models: list[str] = []
    models_dir = repo / "assets" / "models"
    if args.include_preview_ml:
        try:
            preview_model_files = _collect_preview_model_files(models_dir)
            _validate_preview_runtime(preview_model_files)
        except RuntimeError as exc:
            print(f"[build] preview ML validation failed: {exc}")
            return 4
        for model_file in preview_model_files:
            rel = model_file.parent.relative_to(repo).as_posix()
            add_models.extend(
                [
                    "--add-data",
                    f"{model_file}{sep}{rel}",
                ]
            )
        print(
            "[build] PREVIEW ONLY: bundling "
            f"{len(preview_model_files)} validated semantic-model file(s); "
            "stable capabilities remain disabled"
        )
    else:
        print("[build] stable artifact: preview semantic models/runtime excluded")

    from one_link.build_identity import (
        EXPECTED_STABLE_RUNTIME_MODULES,
        STABLE_FROZEN_EXCLUDED_MODULE_PREFIXES,
    )

    onnx_collect: list[str] = []
    if args.include_preview_ml:
        # Presence + model initialization were proven above. Collection is
        # explicit because the stable daemon has no import edge to the preview
        # substrate (by design).
        onnx_collect = ["--collect-all", "onnxruntime"]

    icon_arg: list[str] = []
    if platform.system() == "Darwin":
        # Prefer ``.icns`` (native macOS multi-resolution icon format)
        # over ``.ico``. PyInstaller's BUNDLE() expects .icns; .ico
        # works for the EXE but produces a low-res Dock icon. The
        # .icns is generated at CI time on the macOS runner via
        # ``iconutil`` from the existing PNG family (see
        # ``packaging/macos/make_icns.sh``); on developer machines
        # the file may not exist yet, in which case we fall back to
        # the .ico — still valid for the EXE icon, just less crisp.
        icns = web_dir / "assets" / "one-glyph.icns"
        ico = web_dir / "assets" / "one-glyph.ico"
        chosen = icns if icns.is_file() else ico
        if chosen.is_file():
            icon_arg = ["--icon", str(chosen)]
            print(f"[build] icon embedded: {chosen} ({chosen.stat().st_size} bytes)")
        else:
            print(
                f"[build] WARNING: no icon found at {icns} or {ico} — "
                f"exe will ship with the default Python+floppy icon"
            )
    elif platform.system() == "Windows":
        ico = web_dir / "assets" / "one-glyph.ico"
        if ico.is_file():
            icon_arg = ["--icon", str(ico)]
            print(f"[build] icon embedded: {ico} ({ico.stat().st_size} bytes)")
        else:
            print(
                f"[build] WARNING: icon not found at {ico} — exe will ship "
                f"with the default Python+floppy icon"
            )

    print("[build] validated one_link_native — bundling complete native ABI")

    # GUI mode = no console window. Use --windowed on Mac/Win, no-op on Linux.
    console_flag = "--windowed" if args.gui and platform.system() != "Linux" else "--console"

    # NOTE: --clean is intentionally NOT passed. We've already wiped
    # build/ + dist/ above, and PyInstaller's own --clean step has a
    # known bug on Python 3.14 where it deletes base_library.zip's
    # parent directory mid-write. Pre-wiping has the same effect.
    #
    # Stable runtime does not use the research ML stack. Preview builds use
    # CPU-only ONNX Runtime; torch remains an export/training dependency and is
    # never allowed into a distributed artifact. Exclude it explicitly to
    # avoid pulling ~2 GB of CUDA libraries into an engineering build.
    exclude_modules = [
        # ML training/export-only.
        "torch",
        "torchvision",
        "torchaudio",
        "tensorflow",
        "tensorflow_intel",
        "jax",
        "jaxlib",
        # GPU compute / numba / llvmlite — not needed at runtime.
        # PyInstaller's binary analyzer picks up torch's CUDA DLLs
        # via these transitive deps; excluding them shrinks the
        # bundle by ~1.6 GB.
        "numba",
        "cupy",
        "llvmlite",
        "nvidia",
        "torch.cuda",
        "torch.distributed",
        "torch.backends",
        # Heavy scientific stack the daemon doesn't import.
        "matplotlib",
        "pandas",
        "sympy",
        # Dev / notebook deps.
        "IPython",
        "jupyter",
        "notebook",
        # Test deps.
        "test",
        "tests",
        "pytest",
        "aiohttp.pytest_plugin",
        "aiohttp.test_utils",
        "aiohttp.worker",
        "ast_serialize",
        "hypothesis",
        "mypy",
        "mypy_extensions",
        # Frozen applications categorically reject in-place updates. Sigstore
        # remains a required source-install/release-CI dependency, but its CLI
        # and frozen-only dependency graph cannot be invoked by this launcher.
        "sigstore",
        "sigstore_models",
        "rekor_types",
        "tuf",
        "securesystemslib",
        "id",
        "pyasn1",
        "jwt",
        "requests",
        "urllib3",
        "rfc3161_client",
        "rfc8785",
        "pydantic",
        "pydantic_core",
        "annotated_types",
        "typing_inspection",
        "email_validator",
        "rich",
        "markdown_it",
        "mdurl",
        "pygments",
        "certifi",
        "charset_normalizer",
        # Runtime CFFI is required by the Windows credential backend, but its
        # source-compilation engines and packaging toolchain are not.
        "cffi._shimmed_dist_utils",
        "cffi.ffiplatform",
        "cffi.recompiler",
        "cffi.setuptools_ext",
        "cffi.verifier",
        "cffi.vengine_cpy",
        "cffi.vengine_gen",
        "setuptools",
        "wheel",
        # qrcode's SVG renderer has a stdlib ElementTree fallback. Shipping
        # lxml solely for that optional fast path adds native binaries without
        # changing the user-visible QR capability.
        "lxml",
        # PyInstaller's pydantic hook discovers static-analysis/test plugins;
        # the runtime package remains available where a dependency needs it.
        "pydantic.mypy",
        "pydantic.v1.mypy",
        "pydantic.v1._hypothesis_plugin",
        # Preview builds need NumPy itself, never its build/test frontends.
        "numpy.f2py",
        "numpy.testing",
    ]
    if args.include_preview_ml:
        # The ONNX preview needs only inference, MFCC extraction, and the
        # deterministic receiver synth. Keep torch-backed trainers out even
        # though PyInstaller can discover their nested fallback imports.
        exclude_modules.extend(
            [
                "one_link.ml.scene_dataset",
                "one_link.ml.scene_predictor",
                "one_link.ml.trained_scene_oracle",
                "one_link.ml.trained_voice_oracle",
                "one_link.ml.voice_predictor",
                "one_link.neural_extrapolator",
            ]
        )
    else:
        # Stable releases cannot accidentally grow dead preview code merely
        # because a developer happens to have numpy/onnxruntime installed.
        exclude_modules.extend(
            [
                "onnxruntime",
                "numpy",
                "scipy",
                "one_link.ml",
                "one_link.semantic_scene_codec",
                "one_link.semantic_voice_codec",
                "one_link.neural_extrapolator",
            ]
        )
        # The authoritative contract lives with the runtime identity so the
        # independent validator and this builder cannot drift.  Keep local
        # comments above for rationale, then close any omissions here.
        exclude_modules.extend(STABLE_FROZEN_EXCLUDED_MODULE_PREFIXES)
    exclude_modules = sorted(set(exclude_modules))
    excludes = []
    for m in exclude_modules:
        excludes.extend(["--exclude-module", m])

    # Path patterns that must NEVER end up in the bundle. PyInstaller's
    # binary analyzer recursively follows DLL imports and pulls in CUDA
    # libraries (torch/lib/*.dll, cupy/cuda/*, nvidia/*) via transitive
    # deps even when --exclude-module names the parent. We post-filter
    # the Analysis result via a generated .spec file.
    from one_link.build_identity import (
        DELIBERATELY_UNPACKAGED as _DELIBERATELY_UNPACKAGED,
    )

    forbidden_paths = [
        # Developer diagnostics must not ship in a release bundle. /dr_test is
        # a Double Ratchet self-test harness served UNGUARDED by the daemon's
        # loopback UI; it exposes no secrets and is CSP-locked, but it is
        # surface a user never asked for and cannot benefit from. Excluding it
        # here means the route's own 404 ("dr_test.html not bundled") becomes
        # the shipped behaviour, which is what that branch was written for.
        # From build_identity.DELIBERATELY_UNPACKAGED -- the same tuple the release-time payload
        # verifier reads, so the two can never disagree about what is meant to be absent again.
        *[f"one_link/{p}" for p in _DELIBERATELY_UNPACKAGED],
        *[f"one_link\\{p.replace('/', chr(92))}" for p in _DELIBERATELY_UNPACKAGED],
        "torch/lib/",
        "torch\\lib\\",
        "torchvision/",
        "torchvision\\",
        "torchaudio/",
        "torchaudio\\",
        "cupy/cuda/",
        "cupy\\cuda\\",
        "cupy_backends/",
        "cupy_backends\\",
        "numba/",
        "numba\\",
        "llvmlite/binding/",
        "llvmlite\\binding\\",
        "nvidia/",
        "nvidia\\",
        "tensorflow/",
        "tensorflow\\",
        "tensorflow_intel/",
        "tensorflow_intel\\",
        "jax/",
        "jax\\",
        "jaxlib/",
        "jaxlib\\",
        "matplotlib/",
        "matplotlib\\",
        "pandas/",
        "pandas\\",
        "sympy/",
        "sympy\\",
        "IPython/",
        "IPython\\",
        "jupyter/",
        "jupyter\\",
        "notebook/",
        "notebook\\",
        "aiohttp/pytest_plugin",
        "aiohttp\\pytest_plugin",
        "aiohttp/test_utils",
        "aiohttp\\test_utils",
        "aiohttp/worker",
        "aiohttp\\worker",
        "ast_serialize/",
        "ast_serialize\\",
        "hypothesis/",
        "hypothesis\\",
        "lxml/",
        "lxml\\",
        "mypy/",
        "mypy\\",
        "mypy_extensions/",
        "mypy_extensions\\",
        "setuptools/",
        "setuptools\\",
        "wheel/",
        "wheel\\",
        "sigstore/",
        "sigstore\\",
        "sigstore_models/",
        "sigstore_models\\",
        "rekor_types/",
        "rekor_types\\",
        "tuf/",
        "tuf\\",
        "securesystemslib/",
        "securesystemslib\\",
        "pydantic/",
        "pydantic\\",
        "pydantic_core/",
        "pydantic_core\\",
        "rich/",
        "rich\\",
        "pygments/",
        "pygments\\",
        "direct_url.json",
        "uv_cache.json",
        "uv_build.json",
    ]
    for frozen_disabled_namespace in (
        "annotated_types",
        "certifi",
        "charset_normalizer",
        "email_validator",
        "id",
        "jwt",
        "markdown_it",
        "mdurl",
        "pyasn1",
        "requests",
        "rfc3161_client",
        "rfc8785",
        "securesystemslib",
        "typing_inspection",
        "urllib3",
    ):
        forbidden_paths.extend(
            [
                f"{frozen_disabled_namespace}/",
                f"{frozen_disabled_namespace}\\",
            ]
        )
    if not args.include_preview_ml:
        forbidden_paths.extend(
            [
                "onnxruntime/",
                "onnxruntime\\",
                "scipy/",
                "scipy\\",
                "numpy/",
                "numpy\\",
                "numpy.libs/",
                "numpy.libs\\",
            ]
        )
        for excluded_prefix in STABLE_FROZEN_EXCLUDED_MODULE_PREFIXES:
            path_prefix = excluded_prefix.replace(".", "/")
            forbidden_paths.extend((f"{path_prefix}/", f"{path_prefix}\\"))
    forbidden_paths = sorted(set(forbidden_paths))
    spec_path = build / f"{name}.spec"
    spec_path.parent.mkdir(parents=True, exist_ok=True)
    # `add_native` and `add_models` are PyInstaller CLI-form lists
    # (alternating "--add-data"/"--add-binary" flag tokens and their
    # path arguments). For spec generation we only want the path
    # arguments — strip every other token starting at index 0.
    add_data_args = (
        [add_data_web]
        + add_data_package
        + add_data_shell
        + add_runtime_contract
        + add_build_stamp
        + list(add_models[1::2])
        + list(add_native_sidecar[1::2])
    )
    add_binary_args = list(add_native[1::2])
    # Generate a self-contained spec file. We do this rather than
    # using the CLI so we can post-filter Analysis.binaries by path.
    spec_path.write_text(
        _render_spec(
            name=name,
            entry=str(entry).replace("\\", "/"),
            excludes=exclude_modules,
            hidden_imports=(
                list(EXPECTED_STABLE_RUNTIME_MODULES)
                + (list(_PREVIEW_HIDDEN_IMPORTS) if args.include_preview_ml else [])
            ),
            collect_submodules=(
                ["zeroconf", "cryptography", "aiohttp"]
                + (["one_link_native"] if native_collect else [])
            ),
            collect_all=(["onnxruntime"] if onnx_collect else []),
            add_data_args=add_data_args,
            add_binary_args=add_binary_args,
            hook_paths=[
                str((repo / "scripts" / "pyinstaller_hooks")).replace("\\", "/"),
            ]
            if (repo / "scripts" / "pyinstaller_hooks").is_dir()
            else [],
            icon=str(icon_arg[1]).replace("\\", "/") if icon_arg else "",
            console=("--console" == console_flag),
            forbidden_path_fragments=forbidden_paths,
            # On macOS, BUNDLE() wraps the COLLECT output in a proper
            # ``one-link.app`` directory. Without this PyInstaller ships
            # only ``dist/one-link/`` — a UNIX-executable folder that
            # Finder won't double-click. We only set bundle mode in GUI
            # builds; the console-binary path is for developers who want
            # to invoke from a terminal anyway.
            macos_bundle=(platform.system() == "Darwin" and args.gui),
            bundle_version=__import__("one_link").__version__,
            # Stable builds reject cross-architecture requests above, so this
            # remains None and records the host-native PyInstaller contract.
            target_arch=args.target_arch,
            include_preview_ml=args.include_preview_ml,
        ),
        encoding="utf-8",
    )
    # Note: --clean intentionally omitted. PyInstaller's own --clean
    # has a Python 3.14 bug where it deletes localpycs/struct.pyc
    # mid-write. We pre-wipe build/ + dist/ above, which has the
    # same effect without triggering the bug.
    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--distpath",
        str(dist),
        "--workpath",
        str(build),
        str(spec_path),
    ]
    print("[build] running:", " ".join(cmd))
    res = subprocess.run(cmd, cwd=repo)
    if res.returncode != 0:
        print(f"[build] PyInstaller failed: exit {res.returncode}")
        if dist.exists() and not _remove_tree_required(dist):
            print("[build] WARNING: failed to remove partial PyInstaller dist tree")
        return res.returncode

    # --onedir layout: dist/<name>/<name>.exe (the exe lives INSIDE a
    # folder named after the project; sibling DLLs + datas live next
    # to it). A launcher-only/legacy --onefile result is never accepted as a
    # stable artifact because the release contract validates the full tree.
    final_onedir = dist / name / out_name
    final_macos_app = dist / f"{name}.app" / "Contents" / "MacOS" / out_name
    final_bundle: Path | None = None
    if platform.system() == "Darwin" and args.gui:
        if final_macos_app.exists():
            final = final_macos_app
            final_bundle = dist / f"{name}.app"
        else:
            print(f"[build] expected macOS application launcher not found at {final_macos_app}")
            if dist.exists() and not _remove_tree_required(dist):
                print("[build] WARNING: failed to remove incomplete PyInstaller dist tree")
            return 3
    elif final_onedir.exists():
        final = final_onedir
        final_bundle = final.parent
    else:
        print(
            "[build] expected output not found at "
            f"{final_macos_app} or {final_onedir}"
        )
        if dist.exists() and not _remove_tree_required(dist):
            print("[build] WARNING: failed to remove incomplete PyInstaller dist tree")
        return 3

    # PyInstaller on Linux emits versioned shared objects as SYMLINKS
    # (e.g. libSvtAv1Enc-*.so.4 -> sibling). A portable bundle must survive
    # ZIP round-trips onto filesystems with no symlink support, and the
    # packaged-artifact gate fails closed on any contained link -- so
    # materialize them into independent real files before anything hashes
    # the tree. macOS .app bundles keep their mandatory Framework links;
    # the gate hashes those through its dedicated safe-relative-link path.
    if platform.system() == "Linux" and final_bundle is not None:
        replaced_links = _materialize_bundle_symlinks(final_bundle)
        if replaced_links:
            print(f"[build] materialized {replaced_links} bundle symlink(s) into real files")

    # Native sidecars must bind the bytes we SHIP, not the bytes we staged:
    # on Apple Silicon PyInstaller ad-hoc code-signs every collected Mach-O
    # during bundling, so the staged hash is stale by design there and the
    # release gate refused the first macOS binaries to reach it. Recompute
    # against the bundled library on every platform (a no-op where bundling
    # left the bytes untouched).
    _rebind_bundled_native_sidecars(final_bundle)

    # The updater must execute outside the directory it replaces. Build a
    # separately frozen one-file helper with the complete Sigstore verifier
    # graph, then place it inside the application tree *before* the bundle
    # manifest/release ZIP is generated. Its exact bytes are consequently
    # covered by BUNDLE_SHA256SUMS and the release artifact signature.
    helper_suffix = ".exe" if platform.system() == "Windows" else ""
    helper_parent = (
        final_bundle / "Contents" / "MacOS"
        if platform.system() == "Darwin" and args.gui
        else final_bundle
    )
    assert helper_parent is not None
    helper_output = helper_parent / f"one-link-update-helper{helper_suffix}"
    helper_command = [
        sys.executable,
        str(repo / "scripts" / "build_update_helper.py"),
        "--output",
        str(helper_output),
        "--work-root",
        str(build / "update-helper-build"),
    ]
    if icon_arg:
        helper_command.extend(("--icon", icon_arg[1]))
    print("[build] building authenticated external update helper")
    helper_result = subprocess.run(helper_command, cwd=repo)
    if helper_result.returncode != 0 or not helper_output.is_file():
        print(
            "[build] external update helper failed; refusing a standalone "
            "artifact that cannot replace itself transactionally"
        )
        if dist.exists() and not _remove_tree_required(dist):
            print("[build] WARNING: failed to remove helper-incomplete dist tree")
        return 13

    try:
        _verify_runtime_sources_unchanged(repo, runtime_source_manifest)
    except RuntimeError as exc:
        print(f"[build] source consistency validation failed: {exc}")
        if not _remove_tree_required(dist):
            print("[build] WARNING: failed to remove the invalid mixed-revision dist tree")
        return 8

    # Folder-mode: report total size of the bundle directory.
    if final_bundle is not None:
        total = sum(f.stat().st_size for f in final_bundle.rglob("*") if f.is_file())
        print(
            f"[build] OK -> {final}  "
            f"(exe {final.stat().st_size:,} bytes; "
            f"bundle dir {total:,} bytes, {total // (1024 * 1024)} MB)"
        )
    else:
        print(f"[build] OK -> {final}  ({final.stat().st_size:,} bytes)")

    print("[build] smoke test: one-link --version")
    try:
        smoke = subprocess.run(
            [str(final), "--version"], capture_output=True, text=True, timeout=15
        )
        print("  stdout:", smoke.stdout.strip())
        if smoke.stderr.strip():
            print("  stderr:", smoke.stderr.strip())
        expected_version_output = f"one-link, version {core_version}"
        if (
            smoke.returncode != 0
            or smoke.stdout.strip() != expected_version_output
            or bool(smoke.stderr.strip())
        ):
            print(
                "[build] smoke failed: expected exact output "
                f"{expected_version_output!r} with no stderr and exit 0; "
                f"got exit={smoke.returncode}, stdout={smoke.stdout.strip()!r}, "
                f"stderr={smoke.stderr.strip()!r}"
            )
            if not _discard_invalid_artifact(final, dist):
                print("[build] WARNING: failed to remove invalid smoke-test dist tree")
            return 9
        print("[build] smoke OK")
    except (OSError, subprocess.TimeoutExpired) as e:
        print(f"[build] smoke failed: executable could not prove it runs: {e}")
        if not _discard_invalid_artifact(final, dist):
            print("[build] WARNING: failed to remove invalid smoke-test dist tree")
        return 9
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
