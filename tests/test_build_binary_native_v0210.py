"""PyInstaller build-spec and native packaging guardrails.

The public binary is the highest-risk artifact: it can be stale even
when source is correct, or miss dynamically imported modules/data that
tests exercise only from the source tree. These tests exercise
scripts/build_binary.py without actually running PyInstaller.
"""

from __future__ import annotations

import hashlib
import importlib.util
import platform
import subprocess
import sys
import types
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "build_binary.py"

# The packager's version gates compare against the REAL one_link.__version__,
# so the fakes must track it dynamically or every release bump breaks here.
from one_link import __version__ as _CORE_VERSION  # noqa: E402

_FAKE_SMOKE_STDOUT = f"one-link, version {_CORE_VERSION}"
_FAKE_NATIVE_VERSION = f"{_CORE_VERSION}.0"
NATIVE_BUILD_SCRIPT = SCRIPT.with_name("build_native_cdc.py")
PACKAGED_VALIDATOR_SCRIPT = SCRIPT.with_name("validate_packaged_artifact.py")


def _load_module():
    spec = importlib.util.spec_from_file_location("build_binary", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class FakeCompleted:
    def __init__(self, returncode: int = 0, stdout: str = ""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = ""


def _fake_exe_path(output_root: Path) -> Path:
    out_name = "one-link.exe" if sys.platform == "win32" else "one-link"
    return output_root / "dist" / "one-link" / out_name


def _tree_fingerprint(root: Path) -> tuple[tuple[str, str, str], ...]:
    """Return a byte-sensitive snapshot without writing into repo outputs."""
    if not root.exists() and not root.is_symlink():
        return ((".", "absent", ""),)

    entries: list[tuple[str, str, str]] = [(".", "directory", "")]
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            entries.append((relative, "symlink", str(path.readlink())))
        elif path.is_dir():
            entries.append((relative, "directory", ""))
        elif path.is_file():
            entries.append((relative, "file", hashlib.sha256(path.read_bytes()).hexdigest()))
        else:
            entries.append((relative, "special", ""))
    return tuple(entries)


@pytest.fixture(autouse=True)
def _real_repo_outputs_are_immutable():
    """Prove every packaging test leaves pre-existing real outputs untouched."""
    repo = SCRIPT.parent.parent
    before = {name: _tree_fingerprint(repo / name) for name in ("build", "dist")}
    yield
    after = {name: _tree_fingerprint(repo / name) for name in ("build", "dist")}
    assert after == before, (
        "a packaging test modified the real repository build/dist outputs; "
        "all generated artifacts must stay under its tmp_path output root"
    )


@pytest.fixture
def isolated_output_root(tmp_path: Path) -> Path:
    return (tmp_path / "packaging-output").resolve()


def _install_fake_runner(
    monkeypatch,
    mod,
    output_root: Path,
    *,
    native_rc: int = 0,
    stage_outputs: bool = True,
    corrupt_stage_hash: bool = False,
    pyinstaller_rc: int = 0,
    helper_rc: int = 0,
    smoke_rc: int = 0,
    smoke_failure: str | None = None,
    smoke_stdout: str = _FAKE_SMOKE_STDOUT,
    legacy_onefile_output: bool = False,
):
    captured_cmds: list[list[str]] = []
    repo = SCRIPT.parent.parent
    output_root = output_root.resolve()
    fake_exe = _fake_exe_path(output_root)

    real_import_module = mod.importlib.import_module

    def fake_import_module(name, package=None):
        if name == "PyInstaller":
            return object()
        return real_import_module(name, package)

    monkeypatch.setattr(mod.importlib, "import_module", fake_import_module)
    # The mandatory-native import gate runs before every stage these tests
    # target, and CI runners for the pure-Python suite do not build the
    # compiled ABI. Provide the same version-stamped stand-in on every path
    # so each test reaches its stage regardless of the host; the gate itself
    # keeps its own dedicated test that blocks this import explicitly.
    fake_native = types.ModuleType("one_link_native")
    fake_native.__version__ = _FAKE_NATIVE_VERSION
    monkeypatch.setitem(sys.modules, "one_link_native", fake_native)
    # The fake runner writes sentinel DLL bytes. Native ABI behavior is covered
    # by dedicated compiled-library tests; packaging unit tests keep their
    # subprocess seam while asserting the builder invokes the mandatory probe.
    import one_link.native_cdc as native_cdc_module

    monkeypatch.setattr(native_cdc_module, "validate_native_cdc_library", lambda _path: None)
    # These tests model a frozen source snapshot while other repository audit
    # agents may legitimately edit unrelated runtime files in parallel. The
    # dedicated drift test above exercises the real comparison directly.
    monkeypatch.setattr(mod, "_verify_runtime_sources_unchanged", lambda _repo, _manifest: None)

    real_remove_tree = mod._remove_tree_required

    def guarded_remove_tree(path: Path) -> bool:
        resolved = Path(path).resolve(strict=False)
        assert resolved.is_relative_to(output_root), (
            f"cleanup escaped isolated output root: {resolved}"
        )
        return real_remove_tree(path)

    monkeypatch.setattr(mod, "_remove_tree_required", guarded_remove_tree)

    def fake_run(cmd, *args, **kwargs):
        captured_cmds.append(list(cmd))
        if len(cmd) == 3 and Path(str(cmd[1])).name == "make_icns.sh":
            icon = Path(cmd[2])
            assert icon == output_root / "build" / "one-glyph.icns"
            icon.write_bytes(b"fixture macOS application icon")
            return FakeCompleted()
        if any("build_native_cdc.py" in str(a) for a in cmd):
            assert Path(kwargs["cwd"]).resolve() == repo.resolve()
            output_flag = cmd.index("--output-dir")
            output_dir = Path(cmd[output_flag + 1]).resolve()
            assert output_dir.is_relative_to(output_root / "build" / "native-cdc")
            if native_rc == 0 and stage_outputs:
                output_dir.mkdir(parents=True, exist_ok=True)
                from one_link.native_cdc import native_library_name

                library = output_dir / native_library_name()
                library.write_bytes(b"fresh staged native CDC test library")
                digest = hashlib.sha256(library.read_bytes()).hexdigest()
                if corrupt_stage_hash:
                    digest = "0" * 64
                library.with_suffix(library.suffix + ".sha256").write_text(
                    f"{digest}  {library.name}\n",
                    encoding="ascii",
                )
            return FakeCompleted(returncode=native_rc)
        if any("build_native_shell.py" in str(a) for a in cmd):
            # ONE LINK'S NATIVE WINDOW, staged the way the real step stages it. Without this the
            # fake runner returned success and staged NOTHING, so the spec advertised a shell
            # directory with no shell in it -- and the packaging gate passed. That hollow pass is
            # exactly what `build_binary` now refuses to produce, so the fake has to model the
            # real thing rather than merely not fail.
            assert Path(kwargs["cwd"]).resolve() == repo.resolve()
            output_dir = Path(cmd[cmd.index("--output-dir") + 1]).resolve()
            assert output_dir.is_relative_to(output_root / "build" / "native-shell")
            if stage_outputs:
                output_dir.mkdir(parents=True, exist_ok=True)
                exe = output_dir / ("ol_shell.exe" if sys.platform == "win32" else "ol_shell")
                exe.write_bytes(b"fake native window")
                digest = hashlib.sha256(exe.read_bytes()).hexdigest()
                (output_dir / f"{exe.name}.sha256").write_text(
                    f"{digest}  {exe.name}\n", encoding="ascii")
            return FakeCompleted(returncode=0)
        if any("build_update_helper.py" in str(a) for a in cmd):
            assert Path(kwargs["cwd"]).resolve() == repo.resolve()
            output = Path(cmd[cmd.index("--output") + 1]).resolve()
            assert output.parent == fake_exe.parent
            if helper_rc == 0:
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_bytes(b"fake external update helper")
            return FakeCompleted(returncode=helper_rc)
        if any("PyInstaller" in str(a) for a in cmd):
            assert Path(kwargs["cwd"]).resolve() == repo.resolve()
            dist_path = Path(cmd[cmd.index("--distpath") + 1]).resolve()
            work_path = Path(cmd[cmd.index("--workpath") + 1]).resolve()
            spec_path = Path(cmd[-1]).resolve()
            assert dist_path == output_root / "dist"
            assert work_path == output_root / "build"
            assert spec_path == output_root / "build" / "one-link.spec"
            if pyinstaller_rc == 0:
                generated = (
                    output_root / "dist" / fake_exe.name
                    if legacy_onefile_output
                    else fake_exe
                )
                generated.parent.mkdir(parents=True, exist_ok=True)
                generated.write_bytes(b"fake")
            return FakeCompleted(returncode=pyinstaller_rc)
        if cmd and Path(str(cmd[0])).resolve(strict=False) == fake_exe.resolve():
            assert cmd[1:] == ["--version"]
            if smoke_failure == "timeout":
                raise subprocess.TimeoutExpired(cmd=cmd, timeout=15)
            if smoke_failure == "oserror":
                raise OSError("test executable launch denied")
            return FakeCompleted(
                returncode=smoke_rc,
                stdout=smoke_stdout,
            )
        return FakeCompleted(
            returncode=0,
            stdout=_FAKE_SMOKE_STDOUT,
        )

    monkeypatch.setattr(mod.subprocess, "run", fake_run)
    monkeypatch.setattr(mod.subprocess, "Popen", lambda *a, **kw: FakeCompleted())
    return captured_cmds, fake_exe


def _pyinstaller_cmds(cmds: list[list[str]]) -> list[list[str]]:
    return [c for c in cmds if any("PyInstaller" in str(arg) for arg in c)]


def _native_cdc_cmds(cmds: list[list[str]]) -> list[list[str]]:
    return [c for c in cmds if any("build_native_cdc.py" in str(arg) for arg in c)]


def test_build_binary_script_imports_cleanly():
    mod = _load_module()
    assert callable(mod.main)


def test_build_help_matches_mandatory_native_and_host_arch_contract():
    mod = _load_module()
    help_text = " ".join(mod.build_arg_parser().format_help().split())
    assert "always rejected" in help_text
    assert "freshly built native CDC scanner" in help_text
    assert "matching architecture runner" in help_text


def test_runtime_source_manifest_binds_every_stable_module_deterministically(
    tmp_path: Path,
):
    from one_link import build_identity

    mod = _load_module()
    first = mod._write_runtime_source_manifest(
        SCRIPT.parent.parent,
        tmp_path / "first.json",
    )
    second = mod._write_runtime_source_manifest(
        SCRIPT.parent.parent,
        tmp_path / "second.json",
    )
    assert first.read_bytes() == second.read_bytes()
    payload = __import__("json").loads(first.read_bytes())
    assert payload["schema"] == "one-link-runtime-source-manifest-v1"
    assert payload["runtime_module_manifest_sha256"] == (
        build_identity.EXPECTED_STABLE_RUNTIME_MODULES_SHA256
    )
    assert set(payload["modules"]) == set(build_identity.EXPECTED_STABLE_RUNTIME_MODULES)
    assert all(
        len(entry["source_sha256"]) == 64 and len(entry["normalized_code_sha256"]) == 64
        for entry in payload["modules"].values()
    )


def test_runtime_source_manifest_detects_post_snapshot_drift(
    monkeypatch,
    tmp_path: Path,
):
    mod = _load_module()
    repo = SCRIPT.parent.parent
    manifest = mod._write_runtime_source_manifest(repo, tmp_path / "runtime-source.json")

    mod._verify_runtime_sources_unchanged(repo, manifest)
    original_contract = mod._runtime_source_manifest_bytes
    monkeypatch.setattr(
        mod,
        "_runtime_source_manifest_bytes",
        lambda path: original_contract(path) + b"changed-after-snapshot",
    )

    with pytest.raises(RuntimeError, match="changed while PyInstaller was building"):
        mod._verify_runtime_sources_unchanged(repo, manifest)


def test_output_root_resolver_preserves_production_default_and_rejects_unsafe_paths(
    isolated_output_root: Path,
):
    mod = _load_module()
    repo = SCRIPT.parent.parent.resolve()

    assert mod._resolve_output_root(repo, None) == repo
    assert mod._resolve_output_root(repo, str(isolated_output_root)) == isolated_output_root
    with pytest.raises(ValueError, match="absolute"):
        mod._resolve_output_root(repo, Path("relative-output"))
    with pytest.raises(ValueError, match="filesystem root"):
        mod._resolve_output_root(repo, Path(isolated_output_root.anchor))


def test_build_binary_collects_native_modules_without_local_build_metadata(
    monkeypatch,
    isolated_output_root: Path,
):
    mod = _load_module()
    repo = SCRIPT.parent.parent
    source_native = repo / "src" / "one_link" / "native"
    source_before = {
        path.relative_to(source_native): path.read_bytes()
        for path in source_native.rglob("*")
        if path.is_file()
    }
    captured_cmds, fake_exe = _install_fake_runner(
        monkeypatch,
        mod,
        isolated_output_root,
    )
    # The fake runner intercepts `git rev-parse` too, so without this the
    # build-identity stamp exists exactly when the ambient environment
    # provides GITHUB_SHA (CI yes, laptop no) and the spec gate flips with
    # it. Pin the commit so the packaged contract is identical everywhere.
    monkeypatch.setenv("ONE_LINK_BUILD_COMMIT", "5f" * 20)

    assert mod.main(output_root=isolated_output_root) == 0
    assert fake_exe.is_file()

    native_cmds = _native_cdc_cmds(captured_cmds)
    assert native_cmds, f"native CDC build never invoked: {captured_cmds}"
    assert "--required" in native_cmds[0], (
        "Release binary builds must fail if native CDC cannot rebuild; "
        "otherwise a stale locked DLL can be silently bundled."
    )
    assert "--output-dir" in native_cmds[0]
    stage_dir = Path(native_cmds[0][native_cmds[0].index("--output-dir") + 1])
    assert stage_dir.is_relative_to(isolated_output_root / "build" / "native-cdc")
    assert not stage_dir.is_relative_to(source_native)
    pyinst_cmds = _pyinstaller_cmds(captured_cmds)
    assert pyinst_cmds, f"PyInstaller never invoked. Captured: {captured_cmds}"
    joined = " ".join(pyinst_cmds[0])
    assert "build" in joined and "one-link.spec" in joined
    helper_cmds = [
        command
        for command in captured_cmds
        if any("build_update_helper.py" in str(argument) for argument in command)
    ]
    assert len(helper_cmds) == 1
    helper_suffix = ".exe" if platform.system() == "Windows" else ""
    assert (fake_exe.parent / f"one-link-update-helper{helper_suffix}").is_file()

    spec_text = (isolated_output_root / "build" / "one-link.spec").read_text(encoding="utf-8")
    assert "one_link.sessions" in spec_text
    assert "one_link.recovery_api" in spec_text
    assert "one_link/data" in spec_text
    assert "one_link/_build" in spec_text
    assert (
        isolated_output_root / "build" / "release-contract" / "runtime-source-manifest.json"
    ).is_file()
    assert "collect_submodules('one_link_native')" in spec_text
    assert "collect_all('one_link_native')" not in spec_text
    assert "ONE_LINK_PREVIEW_ML = False" in spec_text
    assert "assets/models" not in spec_text
    assert "collect_all('onnxruntime')" not in spec_text
    for excluded in (
        "aiohttp.pytest_plugin",
        "cffi.verifier",
        "hypothesis",
        "lxml",
        "mypy",
        "numpy",
        "pydantic",
        "pydantic.mypy",
        "setuptools",
        "sigstore",
        "wheel",
    ):
        assert repr(excluded) in spec_text
    assert "'PIL'" not in spec_text
    assert "'Pillow'" not in spec_text
    validator_spec = importlib.util.spec_from_file_location(
        "validate_packaged_artifact_from_build_test",
        PACKAGED_VALIDATOR_SCRIPT,
    )
    validator = importlib.util.module_from_spec(validator_spec)
    assert validator_spec.loader is not None
    validator_spec.loader.exec_module(validator)
    validator.validate_spec(isolated_output_root / "build" / "one-link.spec")
    normalized_spec = spec_text.replace("\\", "/")
    assert "build/native-cdc/" in normalized_spec
    assert any(
        name in normalized_spec
        for name in (
            "ol_native_cdc.dll.sha256",
            "ol_native_cdc.so.sha256",
            "ol_native_cdc.dylib.sha256",
        )
    )
    assert "src/one_link/native" not in normalized_spec
    assert "ol_native_cdc.c" not in normalized_spec
    source_after = {
        path.relative_to(source_native): path.read_bytes()
        for path in source_native.rglob("*")
        if path.is_file()
    }
    assert source_after == source_before


def test_build_binary_fails_closed_when_native_extension_is_missing(
    monkeypatch,
    isolated_output_root: Path,
):
    mod = _load_module()
    captured_cmds, fake_exe = _install_fake_runner(
        monkeypatch,
        mod,
        isolated_output_root,
    )

    real_import_module = mod.importlib.import_module

    def blocked_import_module(name, *args, **kwargs):
        if name == "one_link_native" or name.startswith("one_link_native."):
            raise ImportError("test: pretending one_link_native is absent")
        return real_import_module(name, *args, **kwargs)

    monkeypatch.setattr(mod.importlib, "import_module", blocked_import_module)

    assert mod.main(output_root=isolated_output_root) == 10
    assert not fake_exe.exists()
    assert not captured_cmds


def test_preview_ml_is_explicit_complete_and_never_stable_advertising(
    monkeypatch,
    isolated_output_root: Path,
):
    mod = _load_module()
    captured_cmds, fake_exe = _install_fake_runner(
        monkeypatch,
        mod,
        isolated_output_root,
    )
    monkeypatch.setattr(mod, "_validate_preview_runtime", lambda _files: None)

    assert (
        mod.main(
            ["--include-preview-ml"],
            output_root=isolated_output_root,
        )
        == 0
    )
    assert fake_exe.is_file()

    assert _pyinstaller_cmds(captured_cmds)
    spec_text = (isolated_output_root / "build" / "one-link.spec").read_text(encoding="utf-8")
    assert "ONE_LINK_PREVIEW_ML = True" in spec_text
    assert "collect_all('onnxruntime')" in spec_text
    assert "one_link.semantic_voice_codec" in spec_text
    assert "one_link.semantic_scene_codec" in spec_text
    assert "checkpoint.onnx.data" in spec_text
    assert "checkpoint.pt" not in spec_text


def test_build_binary_stops_when_required_native_cdc_build_fails(
    monkeypatch,
    isolated_output_root: Path,
):
    mod = _load_module()
    captured_cmds, _fake_exe = _install_fake_runner(
        monkeypatch,
        mod,
        isolated_output_root,
        native_rc=1,
    )

    assert mod.main(output_root=isolated_output_root) == 1
    native_cmds = _native_cdc_cmds(captured_cmds)
    assert native_cmds and "--required" in native_cmds[0]
    assert not _pyinstaller_cmds(captured_cmds), (
        "PyInstaller must not run after a required native CDC build failure"
    )


def test_build_binary_propagates_pyinstaller_failure_without_touching_repo_outputs(
    monkeypatch,
    isolated_output_root: Path,
):
    mod = _load_module()
    captured_cmds, fake_exe = _install_fake_runner(
        monkeypatch,
        mod,
        isolated_output_root,
        pyinstaller_rc=17,
    )

    assert mod.main(output_root=isolated_output_root) == 17
    assert _native_cdc_cmds(captured_cmds)
    assert _pyinstaller_cmds(captured_cmds)
    assert not fake_exe.exists()


def test_build_binary_fails_closed_and_discards_bundle_when_helper_build_fails(
    monkeypatch,
    isolated_output_root: Path,
):
    mod = _load_module()
    captured_cmds, fake_exe = _install_fake_runner(
        monkeypatch,
        mod,
        isolated_output_root,
        helper_rc=19,
    )

    assert mod.main(output_root=isolated_output_root) == 13
    assert _pyinstaller_cmds(captured_cmds)
    assert any(
        any("build_update_helper.py" in str(argument) for argument in command)
        for command in captured_cmds
    )
    assert not fake_exe.exists()
    assert not (isolated_output_root / "dist").exists()


def test_build_binary_rejects_legacy_launcher_only_output(
    monkeypatch,
    isolated_output_root: Path,
):
    mod = _load_module()
    captured_cmds, fake_exe = _install_fake_runner(
        monkeypatch,
        mod,
        isolated_output_root,
        legacy_onefile_output=True,
    )

    assert mod.main(output_root=isolated_output_root) == 3
    assert _pyinstaller_cmds(captured_cmds)
    assert not fake_exe.exists()
    assert not (isolated_output_root / "dist").exists()


def test_macos_gui_build_requires_application_bundle_layout(
    monkeypatch,
    isolated_output_root: Path,
):
    mod = _load_module()
    captured_cmds, _fake_exe = _install_fake_runner(
        monkeypatch,
        mod,
        isolated_output_root,
    )
    monkeypatch.setattr(mod.platform, "system", lambda: "Darwin")

    assert mod.main(output_root=isolated_output_root) == 3
    assert _pyinstaller_cmds(captured_cmds)
    assert not (isolated_output_root / "dist").exists()


def test_macos_finalization_rebinds_both_native_binaries_before_helper_and_manifest(
    monkeypatch,
    isolated_output_root: Path,
):
    """Model PyInstaller signing bytes after staged sidecars were written."""
    import zipfile

    from scripts.package_standalone_bundle import package_bundle
    import one_link.native_cdc as native_cdc
    from one_link.update_transaction import _validate_zip_index

    mod = _load_module()
    commands, _ = _install_fake_runner(monkeypatch, mod, isolated_output_root)
    original_run = mod.subprocess.run
    monkeypatch.setattr(mod.platform, "system", lambda: "Darwin")
    bundle = isolated_output_root / "dist" / "one-link.app"
    executable = bundle / "Contents" / "MacOS" / "one-link"
    native_pairs: list[tuple[Path, Path]] = []

    def assert_final_hashes():
        assert len(native_pairs) == 2
        for binary, sidecar in native_pairs:
            expected = f"{hashlib.sha256(binary.read_bytes()).hexdigest()}  {binary.name}\n"
            assert sidecar.read_bytes() == expected.encode("ascii")

    def fake_macos_run(cmd, *args, **kwargs):
        if any("PyInstaller" in str(arg) for arg in cmd):
            result = original_run(cmd, *args, **kwargs)
            executable.parent.mkdir(parents=True)
            executable.write_bytes(b"final app launcher")
            executable.chmod(0o755)
            # The Darwin layout is simulated on every CI host; match the
            # existing subprocess stub's host-native filename selection.
            shell_name = "ol_shell.exe" if sys.platform == "win32" else "ol_shell"
            for name in (shell_name, native_cdc.native_library_name()):
                binary = bundle / "Contents" / "Frameworks" / name
                sidecar = bundle / "Contents" / "Resources" / (name + ".sha256")
                binary.parent.mkdir(parents=True, exist_ok=True)
                sidecar.parent.mkdir(parents=True, exist_ok=True)
                sidecar.write_text(f"{hashlib.sha256(b'staged').hexdigest()}  {name}\n", encoding="ascii")
                binary.write_bytes(b"post-PyInstaller-signing:" + name.encode("ascii"))
                native_pairs.append((binary, sidecar))
            return result
        if any("build_update_helper.py" in str(arg) for arg in cmd):
            commands.append(list(cmd))
            assert_final_hashes()
            output = Path(cmd[cmd.index("--output") + 1])
            assert output == executable.with_name("one-link-update-helper")
            output.write_bytes(b"finished helper fixture")
            return FakeCompleted()
        if cmd and Path(str(cmd[0])) == executable:
            commands.append(list(cmd))
            assert cmd[1:] == ["--version"]
            assert_final_hashes()
            return FakeCompleted(stdout=_FAKE_SMOKE_STDOUT)
        return original_run(cmd, *args, **kwargs)

    monkeypatch.setattr(mod.subprocess, "run", fake_macos_run)
    assert mod.main(output_root=isolated_output_root) == 0
    icon = isolated_output_root / "build" / "one-glyph.icns"
    assert icon.read_bytes() == b"fixture macOS application icon"
    assert icon.as_posix() in (icon.parent / "one-link.spec").read_text(encoding="utf-8")
    assert_final_hashes()
    archive_path = isolated_output_root / "finished-app.zip"
    package_bundle(bundle, archive_path, executable="Contents/MacOS/one-link", epoch=1700000001)
    with zipfile.ZipFile(archive_path) as archive:
        _, _, rows = _validate_zip_index(
            archive, expected_executable="Contents/MacOS/one-link", expected_bundle_root="one-link.app",
        )
        assert archive.read("one-link.app/Contents/MacOS/one-link-update-helper") == b"finished helper fixture"
        for binary, sidecar in native_pairs:
            for member in (binary, sidecar):
                name = "one-link.app/" + member.relative_to(bundle).as_posix()
                assert archive.read(name) == member.read_bytes()
                assert rows[name].digest == hashlib.sha256(member.read_bytes()).hexdigest()


@pytest.mark.parametrize(
    ("target_platform", "cdc_name", "shell_name"),
    [("win32", "ol_native_cdc.dll", "ol_shell.exe"),
     ("linux", "ol_native_cdc.so", "ol_shell"),
     ("darwin", "ol_native_cdc.dylib", "ol_shell")],
)
def test_final_native_sidecars_bind_bytes_on_each_platform(
    monkeypatch, tmp_path, target_platform, cdc_name, shell_name,
):
    import one_link.native_cdc as native_cdc

    mod = _load_module()
    monkeypatch.setattr(mod, "sys", types.SimpleNamespace(path=sys.path, platform=target_platform))
    monkeypatch.setattr(native_cdc, "native_library_name", lambda: cdc_name)
    for name in (cdc_name, shell_name):
        (tmp_path / name).write_bytes(b"finished:" + name.encode("ascii"))
        (tmp_path / (name + ".sha256")).write_bytes(("0" * 64 + f"  {name}\n").encode("ascii"))
    mod._rebind_bundled_native_sidecars(tmp_path)
    for name in (cdc_name, shell_name):
        digest = hashlib.sha256((tmp_path / name).read_bytes()).hexdigest()
        assert (tmp_path / (name + ".sha256")).read_bytes() == f"{digest}  {name}\n".encode("ascii")


@pytest.mark.parametrize("shape", ["orphan", "divergent"])
def test_native_sidecar_rebinding_refuses_missing_or_divergent_shells(monkeypatch, tmp_path, shape):
    mod = _load_module()
    monkeypatch.setattr(mod, "sys", types.SimpleNamespace(path=sys.path, platform="darwin"))
    (tmp_path / "ol_shell.sha256").write_text("0" * 64 + "  ol_shell\n", encoding="ascii")
    if shape == "divergent":
        (tmp_path / "ol_shell").write_bytes(b"first")
        (tmp_path / "other").mkdir()
        (tmp_path / "other" / "ol_shell").write_bytes(b"different")
    with pytest.raises(RuntimeError, match="no native binary|divergent native binary"):
        mod._rebind_bundled_native_sidecars(tmp_path)


@pytest.mark.parametrize(
    ("smoke_rc", "smoke_failure"),
    [
        (23, None),
        (0, "timeout"),
        (0, "oserror"),
    ],
)
def test_build_binary_fails_closed_and_discards_artifact_when_execution_smoke_fails(
    monkeypatch,
    isolated_output_root: Path,
    smoke_rc: int,
    smoke_failure: str | None,
):
    mod = _load_module()
    captured_cmds, fake_exe = _install_fake_runner(
        monkeypatch,
        mod,
        isolated_output_root,
        smoke_rc=smoke_rc,
        smoke_failure=smoke_failure,
    )

    assert mod.main(output_root=isolated_output_root) == 9
    assert _pyinstaller_cmds(captured_cmds)
    assert not fake_exe.exists()
    assert not fake_exe.parent.exists()


def test_build_binary_rejects_stale_version_smoke_output(
    monkeypatch,
    isolated_output_root: Path,
):
    mod = _load_module()
    _captured_cmds, fake_exe = _install_fake_runner(
        monkeypatch,
        mod,
        isolated_output_root,
        smoke_stdout="one-link, version 0.20.0",
    )

    assert mod.main(output_root=isolated_output_root) == 9
    assert not fake_exe.exists()
    assert not (isolated_output_root / "dist").exists()


def test_build_binary_fails_closed_when_output_cleanup_is_incomplete(
    monkeypatch,
    isolated_output_root: Path,
):
    mod = _load_module()
    isolated_build = isolated_output_root / "build"
    isolated_build.mkdir(parents=True, exist_ok=True)
    sentinel = isolated_build / "preexisting-build-output.bin"
    sentinel.write_bytes(b"must survive failed cleanup")
    captured_cmds, _fake_exe = _install_fake_runner(
        monkeypatch,
        mod,
        isolated_output_root,
    )

    def incomplete_cleanup(path: Path) -> bool:
        assert Path(path).resolve() == isolated_build.resolve()
        return False

    monkeypatch.setattr(mod, "_remove_tree_required", incomplete_cleanup)

    assert mod.main(output_root=isolated_output_root) == 6
    assert sentinel.read_bytes() == b"must survive failed cleanup"
    assert not _native_cdc_cmds(captured_cmds)
    assert not _pyinstaller_cmds(captured_cmds)


@pytest.mark.parametrize("corrupt_hash", [False, True])
def test_build_binary_rejects_missing_or_corrupt_staged_native_cdc(
    monkeypatch,
    isolated_output_root: Path,
    corrupt_hash,
):
    mod = _load_module()
    captured_cmds, _fake_exe = _install_fake_runner(
        monkeypatch,
        mod,
        isolated_output_root,
        stage_outputs=corrupt_hash,
        corrupt_stage_hash=corrupt_hash,
    )

    assert mod.main(output_root=isolated_output_root) == 5
    assert _native_cdc_cmds(captured_cmds)
    assert not _pyinstaller_cmds(captured_cmds)


def test_build_native_cdc_explicit_output_does_not_touch_package_tree(
    monkeypatch,
    tmp_path,
):
    native_spec = importlib.util.spec_from_file_location(
        "build_native_cdc_test",
        NATIVE_BUILD_SCRIPT,
    )
    native_script = importlib.util.module_from_spec(native_spec)
    assert native_spec.loader is not None
    native_spec.loader.exec_module(native_script)

    import one_link.native_cdc as native_cdc

    repo = SCRIPT.parent.parent
    source_native = repo / "src" / "one_link" / "native"
    source_before = {
        path.relative_to(source_native): path.read_bytes()
        for path in source_native.rglob("*")
        if path.is_file()
    }
    output_dir = tmp_path / "native-stage"
    # This test pins OUTPUT-DIR ISOLATION, not compilation. The script now
    # compiles through the shared try-every-compiler ladder, which also
    # ABI-validates the produced library -- so the fake bytes need the
    # candidate list and the validator stubbed alongside _compile.
    monkeypatch.setattr(native_cdc, "_candidate_c_compilers", lambda: ["fake-cc"])
    monkeypatch.setattr(
        native_cdc,
        "_compile",
        lambda _compiler, _source, library: library.write_bytes(b"fresh-cdc"),
    )
    monkeypatch.setattr(native_cdc, "validate_native_cdc_library", lambda _lib: None)
    monkeypatch.setattr(
        sys,
        "argv",
        [str(NATIVE_BUILD_SCRIPT), "--required", "--output-dir", str(output_dir)],
    )

    assert native_script.main() == 0
    library = output_dir / native_cdc.native_library_name()
    sidecar = library.with_suffix(library.suffix + ".sha256")
    assert library.read_bytes() == b"fresh-cdc"
    assert sidecar.read_text(encoding="ascii") == (
        f"{hashlib.sha256(library.read_bytes()).hexdigest()}  {library.name}\n"
    )
    assert (output_dir / "ol_native_cdc.c").is_file()
    source_after = {
        path.relative_to(source_native): path.read_bytes()
        for path in source_native.rglob("*")
        if path.is_file()
    }
    assert source_after == source_before


def test_build_binary_rejects_native_cdc_fallback_for_stable_artifacts(
    monkeypatch,
    isolated_output_root: Path,
):
    mod = _load_module()
    captured_cmds, fake_exe = _install_fake_runner(
        monkeypatch,
        mod,
        isolated_output_root,
        stage_outputs=False,
    )

    assert (
        mod.main(
            ["--allow-native-cdc-fallback"],
            output_root=isolated_output_root,
        )
        == 12
    )
    assert not fake_exe.exists()
    assert not captured_cmds


def test_materialize_bundle_symlinks_replaces_links_and_rejects_escapes(tmp_path):
    """Linux PyInstaller output carries versioned .so SYMLINKS; a portable
    bundle must hold real files (ZIP round-trips, link-refusing gate). An
    escaping or dangling link is a packaging error, not something to ship."""
    mod = _load_module()
    bundle = tmp_path / "bundle"
    (bundle / "sub").mkdir(parents=True)
    real = bundle / "sub" / "libx.so.4.1.0"
    real.write_bytes(b"shared-object-bytes")
    link = bundle / "sub" / "libx.so.4"
    try:
        link.symlink_to(real.name)  # relative sibling link, PyInstaller-style
    except OSError:
        pytest.skip("symlinks unavailable on this host")
    assert mod._materialize_bundle_symlinks(bundle) == 1
    assert not link.is_symlink()
    assert link.read_bytes() == b"shared-object-bytes"
    assert real.read_bytes() == b"shared-object-bytes"

    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"outside")
    (bundle / "evil").symlink_to(outside)
    with pytest.raises(RuntimeError, match="dangles or escapes"):
        mod._materialize_bundle_symlinks(bundle)
