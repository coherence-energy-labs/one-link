"""Independent wheel/sdist completeness and clean-install truth gates."""

from __future__ import annotations

import base64
import csv
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import zipfile

import pytest

from one_link import build_identity


REPO = Path(__file__).resolve().parent.parent
VALIDATOR = REPO / "scripts" / "validate_python_distributions.py"


def _load_validator():
    spec = importlib.util.spec_from_file_location(
        "validate_python_distributions_test",
        VALIDATOR,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _record_bytes(entries: dict[str, bytes], record_name: str) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    for name, payload in entries.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=")
        writer.writerow((name, f"sha256={digest.decode('ascii')}", len(payload)))
    writer.writerow((record_name, "", ""))
    return stream.getvalue().encode("utf-8")


def _stage_distribution_source(destination: Path) -> None:
    destination.mkdir()
    for relative in (
        "LICENSE",
        "LICENSE-NOTICE",
        "NOTICE",
        "README.md",
        "pyproject.toml",
        "setup.py",
    ):
        shutil.copy2(REPO / relative, destination / relative)
    shutil.copytree(
        REPO / "src",
        destination / "src",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.egg-info"),
    )


def test_stable_distribution_contract_exactly_matches_source_tree() -> None:
    # 207: one_link.group_invite added 2026-08-07 -- the CONSUMER the group-invite mint never
    # had. The daemon signed `one-link://group-invite/<token>` in two places and peer.html
    # offered a Copy invite button, while `protocol_handler` answered "unsupported one-link
    # route" to the app's OWN URL -- nothing decoded that token on any surface. It is a stable
    # runtime module because the deep-link handler imports it: a frozen build without it would
    # accept the link and then fail to verify anything behind it.
    # (206 before it: one_link.env_bounds added 2026-08-05 -- the single validated parser
    # for numeric environment overrides. It exists because nine constants in
    # daemon.py and server.py used bare int(os.environ.get(...)), so
    # ONE_LINK_MAX_PEERS=abc raised at IMPORT and the daemon could not start,
    # while ONE_LINK_MAX_PEERS=0 was accepted and silently set the peer ceiling
    # to zero. It is imported at module scope by both, so a frozen build
    # missing it would fail before logging exists.
    # (204 before it: bounded_resolver, 2026-07-30.)
    assert len(build_identity.EXPECTED_STABLE_RUNTIME_MODULES) == 207
    assert build_identity.EXPECTED_STABLE_RUNTIME_MODULES == tuple(
        sorted(set(build_identity.EXPECTED_STABLE_RUNTIME_MODULES))
    )
    assert build_identity.EXPECTED_STABLE_PACKAGE_DATA == tuple(
        sorted(set(build_identity.EXPECTED_STABLE_PACKAGE_DATA))
    )
    assert len(build_identity.EXPECTED_STABLE_PACKAGE_DATA) == 23

    package_root = build_identity.package_root()
    discovered_data = {
        path.relative_to(package_root).as_posix()
        for subtree in ("data", "web")
        for path in (package_root / subtree).rglob("*")
        if path.is_file()
    }
    assert discovered_data == set(build_identity.EXPECTED_STABLE_PACKAGE_DATA)
    assert (
        build_identity.stable_package_data_manifest_sha256()
        == build_identity.EXPECTED_STABLE_PACKAGE_DATA_SHA256
    )

    discovered_modules: set[str] = set()
    for path in package_root.rglob("*.py"):
        relative = path.relative_to(package_root)
        if relative.name == "__init__.py":
            suffix = ".".join(relative.parts[:-1])
        else:
            suffix = ".".join(relative.with_suffix("").parts)
        discovered_modules.add("one_link" + (f".{suffix}" if suffix else ""))
    excluded_modules = {
        module
        for module in discovered_modules
        if module in build_identity.STABLE_RUNTIME_EXCLUDED_MODULES
        or any(
            module == prefix or module.startswith(f"{prefix}.")
            for prefix in build_identity.STABLE_RUNTIME_EXCLUDED_PREFIXES
        )
    }
    assert set(build_identity.EXPECTED_STABLE_RUNTIME_MODULES) == (
        discovered_modules - excluded_modules
    )


def test_distribution_source_contract_hashes_every_packaged_python_file() -> None:
    validator = _load_validator()
    contract = validator.load_source_contract(REPO)
    package_root = REPO / "src" / "one_link"
    source_python = {
        f"one_link/{path.relative_to(package_root).as_posix()}"
        for path in package_root.rglob("*.py")
        if "__pycache__" not in path.parts
    }
    packaged_python = {name for name in contract.payload_hashes if name.endswith(".py")}
    # 223 / 246: group_invite.py added 2026-08-07 -- the CONSUMER the group-invite mint never
    # had. The daemon signed `one-link://group-invite/<token>` in two places and peer.html
    # offered a Copy invite button, while the deep-link handler answered "unsupported one-link
    # route" to the app's own URL: nothing anywhere decoded that token, on phone or desktop.
    # Verifies the signature, and RECOMPUTES the issuer fingerprint from the key -- without that
    # binding an attacker mints a validly-signed invite carrying a trusted contact's fingerprint.
    # (222 / 245 before it: data/certified/unread_badge.json, 2026-08-07 -- the FIFTH certified
    # surface and where design §11.1 model (b) reaches a pixel: what an unread count is
    # ALLOWED TO SAY, proven over every integer.
    # (222 / 244: data/certified/origin_fence.json -- the THIRD certified
    # surface, and the first that is not a pixel: it is the NATIVE SHELL's navigation decision
    # (which characters may extend an origin), proven over every integer and checked by the
    # shell against its own Rust implementation at all 257 points.
    # (222 / 243: data/certified/link_badge.json -- the SECOND certified
    # surface (is this connection direct, and authenticated?), emitted through the same
    # pipeline as the first. No new module: `certified_surface.py` carries both.
    # (222 / 242 before it: certified_surface.py + data/certified/peer_row.json, the
    # peer row's proven layout table, laws discharged over every integer input.)
    # (221 / 240 before it: env_bounds.py, 2026-08-05. 220 / 239: bounded_resolver.py.)
    assert len(source_python) == 223
    assert packaged_python == source_python
    assert len(contract.payload_hashes) == 246


def test_developer_only_modules_are_not_stable_distribution_requirements() -> None:
    developer_only = {
        "one_link.call_reliability_soak",
        "one_link.perf_lab",
        "one_link.perf_lab_native",
        "one_link.transfer_sim",
    }
    assert developer_only <= build_identity.STABLE_RUNTIME_EXCLUDED_MODULES
    assert developer_only.isdisjoint(build_identity.EXPECTED_STABLE_RUNTIME_MODULES)


def test_stable_module_source_path_is_exact_and_fail_closed() -> None:
    root = Path("/reviewed/src/one_link")
    assert build_identity.stable_module_source_path(root, "one_link") == (root / "__init__.py")
    assert (
        build_identity.stable_module_source_path(
            root,
            "one_link.transport_adapters",
        )
        == root / "transport_adapters" / "__init__.py"
    )
    assert build_identity.stable_module_source_path(root, "one_link.wire") == (root / "wire.py")
    with pytest.raises(ValueError, match="outside the stable runtime contract"):
        build_identity.stable_module_source_path(root, "one_link.transfer_sim")


def test_normalized_code_digest_ignores_paths_but_preserves_semantics() -> None:
    source = "def outer(value):\n    return lambda: value + 1\n"
    first = compile(source, "C:/first/checkout/module.py", "exec")
    second = compile(source, "/different/checkout/module.py", "exec")
    changed = compile(source.replace("value + 1", "value + 2"), "module.py", "exec")

    assert build_identity.normalized_code_sha256(first) == (
        build_identity.normalized_code_sha256(second)
    )
    assert build_identity.normalized_code_sha256(first) != (
        build_identity.normalized_code_sha256(changed)
    )
    with pytest.raises(TypeError, match="types.CodeType"):
        build_identity.normalized_code_sha256("not code")  # type: ignore[arg-type]


def test_normalized_code_digest_supports_literal_slice_constants() -> None:
    """Literal-slice bytecode is accepted without weakening semantic parity.

    Python versions differ in whether ``rows[1:3]`` stores the three operands
    separately or interns a ``slice`` in ``co_consts``.  ``CodeType.replace``
    exercises the latter representation on every supported interpreter, so a
    regression cannot hide behind the compiler version running this test.
    """
    template = compile("pass\n", "C:/first/module.py", "exec")
    first = template.replace(co_consts=(slice(1, 3, None),))
    second = compile("pass\n", "/other/module.py", "exec").replace(co_consts=(slice(1, 3, None),))
    changed_stop = second.replace(co_consts=(slice(1, 4, None),))
    changed_start = second.replace(co_consts=(slice(0, 3, None),))
    changed_step = second.replace(co_consts=(slice(1, 3, 2),))
    assert build_identity.normalized_code_sha256(first) == (
        build_identity.normalized_code_sha256(second)
    )
    digest = build_identity.normalized_code_sha256(first)
    assert digest != build_identity.normalized_code_sha256(changed_stop)
    assert digest != build_identity.normalized_code_sha256(changed_start)
    assert digest != build_identity.normalized_code_sha256(changed_step)


@pytest.mark.parametrize(
    ("value", "expected_sha256"),
    [
        (
            slice(None, None, None),
            "10f1c316b799ee1e48298af7c2bef1b94d06d72a61d04c10943e93830d73617b",
        ),
        (
            slice(1, 3, None),
            "b2700054b138c0dda7662a7e20ae7cec7df4c622d1decd880e0d4ca3b59fd675",
        ),
        (
            slice(-5, None, 2),
            "610f382bb00f584dafda19df43228a40d6e4b4a279bfb6bcf1e3cf6ca10a3d1d",
        ),
        (
            slice("a", b"b", Ellipsis),
            "50b01a6ff4e928b76f59853841ceb6e1120c7c5abd21e7a2e9d9bfed4efa9ce7",
        ),
    ],
)
def test_slice_constant_encoding_has_cross_version_known_answers(
    value: slice,
    expected_sha256: str,
) -> None:
    """The slice-value wire form is stable across Python minor versions."""
    encoded = build_identity._canonical_code_value(value)
    assert hashlib.sha256(encoded).hexdigest() == expected_sha256


def test_slice_constant_encoding_fails_closed_for_non_code_constants() -> None:
    with pytest.raises(TypeError, match="unsupported constant"):
        build_identity._canonical_code_value(slice([], None, None))


def test_normalized_code_digest_survives_pyc_marshal_reference_rewriting() -> None:
    import marshal

    source_path = build_identity.stable_module_source_path(
        build_identity.package_root(),
        "one_link.call_reliability",
    )
    compiled = compile(source_path.read_bytes(), str(source_path), "exec")
    pyc_round_trip = marshal.loads(marshal.dumps(compiled))
    assert build_identity.normalized_code_sha256(compiled) == (
        build_identity.normalized_code_sha256(pyc_round_trip)
    )


def test_native_runtime_manifest_exactly_matches_all_public_stubs() -> None:
    stub_root = REPO / "native" / "one_link_native"
    discovered = tuple(
        sorted(
            f"one_link_native.{path.stem}"
            for path in stub_root.glob("*.pyi")
            if path.name != "__init__.pyi"
        )
    )
    assert len(discovered) == 33
    assert build_identity.EXPECTED_NATIVE_RUNTIME_SUBMODULES == discovered
    assert (
        build_identity.native_runtime_submodule_manifest_sha256()
        == build_identity.EXPECTED_NATIVE_RUNTIME_SUBMODULES_SHA256
    )


def test_core_wheel_configuration_is_genuinely_universal() -> None:
    import tomllib

    with (REPO / "pyproject.toml").open("rb") as stream:
        project = tomllib.load(stream)
    package_data = project["tool"]["setuptools"]["package-data"]["one_link"]
    assert project["project"]["license"] == "AGPL-3.0-or-later"
    assert project["project"]["license-files"] == [
        "LICENSE",
        "LICENSE-NOTICE",
        "NOTICE",
    ]
    assert project["build-system"]["requires"] == [
        "setuptools>=83,<84",
        "wheel>=0.47,<0.48",
    ]
    assert project["tool"]["setuptools"]["include-package-data"] is False
    assert not any("ol_native_cdc" in pattern for pattern in package_data)

    setup_source = (REPO / "setup.py").read_text(encoding="utf-8")
    assert "root_is_pure" not in setup_source
    assert "bdist_wheel" not in setup_source
    assert setup_source.count("setup()") == 1


def test_archive_readers_reject_traversal_and_links(tmp_path: Path) -> None:
    validator = _load_validator()
    wheel = tmp_path / "unsafe.whl"
    with zipfile.ZipFile(wheel, mode="w") as archive:
        archive.writestr("../escape.py", b"bad")
    with pytest.raises(validator.GateFailure, match="escapes its root"):
        validator.read_wheel(wheel)

    sdist = tmp_path / "unsafe.tar.gz"
    with tarfile.open(sdist, mode="w:gz") as archive:
        directory = tarfile.TarInfo("one_link-1.0")
        directory.type = tarfile.DIRTYPE
        archive.addfile(directory)
        link = tarfile.TarInfo("one_link-1.0/linked")
        link.type = tarfile.SYMTYPE
        link.linkname = "outside"
        archive.addfile(link)
    with pytest.raises(validator.GateFailure, match="link or special"):
        validator.read_sdist(sdist)


def test_archive_readers_reject_file_subtree_collisions(tmp_path: Path) -> None:
    validator = _load_validator()
    wheel = tmp_path / "ambiguous.whl"
    with zipfile.ZipFile(wheel, mode="w") as archive:
        archive.writestr("one_link", b"regular file")
        archive.writestr("one_link/__init__.py", b"")
    with pytest.raises(validator.GateFailure, match="ancestor"):
        validator.read_wheel(wheel)

    sdist = tmp_path / "ambiguous.tar.gz"
    with tarfile.open(sdist, mode="w:gz") as archive:
        parent = tarfile.TarInfo("one_link-1.0/src")
        parent.size = 1
        archive.addfile(parent, io.BytesIO(b"x"))
        child = tarfile.TarInfo("one_link-1.0/src/one_link/__init__.py")
        child.size = 0
        archive.addfile(child, io.BytesIO())
    with pytest.raises(validator.GateFailure, match="ancestor"):
        validator.read_sdist(sdist)


def test_wheel_record_verifier_rejects_stale_content() -> None:
    validator = _load_validator()
    record_name = "one_link-1.0.dist-info/RECORD"
    entries = {"one_link/__init__.py": b"version = 1\n"}
    entries[record_name] = _record_bytes(entries, record_name)
    validator._validate_wheel_record(entries)

    entries["one_link/__init__.py"] = b"tampered\n"
    with pytest.raises(validator.GateFailure, match="digest mismatch"):
        validator._validate_wheel_record(entries)


def test_payload_verifier_rejects_missing_and_stale_source_bytes() -> None:
    validator = _load_validator()
    expected = {
        "one_link/a.py": hashlib.sha256(b"a").hexdigest(),
        "one_link/b.py": hashlib.sha256(b"b").hexdigest(),
    }
    with pytest.raises(validator.GateFailure, match="missing=.*b.py"):
        validator._assert_payload_hashes(
            {"one_link/a.py": b"a"},
            expected,
            prefix="",
            label="fixture",
        )
    with pytest.raises(validator.GateFailure, match="digest_mismatch=.*a.py"):
        validator._assert_payload_hashes(
            {"one_link/a.py": b"changed", "one_link/b.py": b"b"},
            expected,
            prefix="",
            label="fixture",
        )
    with pytest.raises(validator.GateFailure, match="unexpected=.*evil.py"):
        validator._assert_payload_hashes(
            {
                "one_link/a.py": b"a",
                "one_link/b.py": b"b",
                "one_link/evil.py": b"surprise",
            },
            expected,
            prefix="",
            label="fixture",
            exact_namespace="one_link/",
        )


def test_sdist_verifier_rejects_platform_native_payload(tmp_path: Path) -> None:
    validator = _load_validator()
    empty_digest = hashlib.sha256(b"").hexdigest()
    inputs = {relative: empty_digest for relative in validator.REQUIRED_SDIST_BUILD_INPUTS}
    contract = validator.SourceContract(
        source_root=tmp_path,
        version=validator.Version("1.0"),
        modules=(),
        runtime_module_manifest_sha256="0" * 64,
        package_data=(),
        package_data_manifest_sha256="0" * 64,
        payload_hashes={"one_link/__init__.py": empty_digest},
        sdist_input_hashes=inputs,
        requires_python=None,
        license_expression=None,
        license_files=(),
        requirements=(),
        provides_extras=(),
    )
    sdist = tmp_path / "one_link-1.0.tar.gz"
    members = {
        "one_link-1.0/PKG-INFO": b"Metadata-Version: 2.4\nName: one_link\nVersion: 1.0\n\n",
        "one_link-1.0/src/one_link/__init__.py": b"",
        "one_link-1.0/src/one_link/native/windows-x86_64/ol_native_cdc.dll": b"MZ",
        **{f"one_link-1.0/{relative}": b"" for relative in inputs},
    }
    with tarfile.open(sdist, mode="w:gz") as archive:
        for name, payload in members.items():
            member = tarfile.TarInfo(name)
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))
    with pytest.raises(validator.GateFailure, match="platform-native binaries"):
        validator.validate_sdist(sdist, contract)


def test_distribution_subprocess_environment_is_allowlisted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    validator = _load_validator()
    monkeypatch.setenv("PYTHONPATH", "hostile")
    monkeypatch.setenv("UV_PROJECT_ENVIRONMENT", "hostile")
    monkeypatch.setenv("ONE_LINK_HOME", "hostile")
    monkeypatch.setenv("PATH", os.environ.get("PATH", ""))
    environment = validator._clean_environment()
    assert "PYTHONPATH" not in environment
    assert "UV_PROJECT_ENVIRONMENT" not in environment
    assert "ONE_LINK_HOME" not in environment
    assert environment["PYTHONNOUSERSITE"] == "1"
    assert environment["UV_OFFLINE"] == "1"


def test_release_build_removes_src_egg_info_before_packaging() -> None:
    workflow = (REPO / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    assert "rm -rf dist/ build/ *.egg-info src/*.egg-info" in workflow


def test_fresh_wheel_and_sdist_pass_two_clean_install_probes(tmp_path: Path) -> None:
    validator = _load_validator()
    uv = shutil.which("uv")
    assert uv is not None, "the distribution gate requires the pinned uv CLI"
    source = tmp_path / "source"
    output = tmp_path / "dist"
    _stage_distribution_source(source)
    environment = os.environ.copy()
    environment.pop("PYTHONHOME", None)
    environment.pop("PYTHONPATH", None)
    environment["PYTHONNOUSERSITE"] = "1"
    environment["UV_OFFLINE"] = "1"
    environment["UV_NO_PROGRESS"] = "1"
    process = subprocess.run(
        [
            uv,
            "build",
            "--sdist",
            "--wheel",
            "--offline",
            "--no-build-isolation",
            "--no-create-gitignore",
            "--no-config",
            "--python",
            sys.executable,
            "--out-dir",
            str(output),
            str(source),
        ],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    assert process.returncode == 0, process.stdout + process.stderr

    result = validator.validate_distributions(output, source)
    staged_contract = validator.load_source_contract(source)
    assert result["verification_status"] == "python_distributions_ok"
    assert result["wheel"].endswith("-py3-none-any.whl")
    assert result["stable_runtime_module_count"] == len(
        build_identity.EXPECTED_STABLE_RUNTIME_MODULES
    )
    assert result["stable_package_data_count"] == 23
    assert result["source_payload_file_count"] == len(staged_contract.payload_hashes)
    assert result["source_python_file_count"] == sum(
        name.endswith(".py") for name in staged_contract.payload_hashes
    )
    assert result["declared_requirement_count"] == 48
    assert result["declared_extra_count"] == 9
    assert result["wheel_bytes"] > 0
    assert result["sdist_bytes"] > 0
    assert len(result["wheel_sha256"]) == 64
    assert len(result["sdist_sha256"]) == 64
    assert len(result["sdist_derived_wheel_sha256"]) == 64
