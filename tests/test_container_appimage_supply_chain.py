"""Fail-closed distribution-input contracts for AppImage and rendezvous OCI builds."""

from __future__ import annotations

import ast
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
RENDEZVOUS_MODULES = {
    "__init__",
    "rdz_blind",
    "relay_proto",
    "relay_routing",
    "rendezvous_proto",
    "rendezvous_server",
}


def _read(relative: str) -> str:
    return (REPO / relative).read_text(encoding="utf-8")


def _uv_versions() -> dict[str, str]:
    lock = tomllib.loads(_read("uv.lock"))
    return {package["name"]: package["version"] for package in lock["package"]}


def _requirements_versions() -> dict[str, str]:
    text = _read("deploy/rendezvous/requirements.lock")
    return {
        match.group(1).replace("_", "-").lower(): match.group(2)
        for match in re.finditer(
            r"^([A-Za-z0-9_.-]+)==([^\s;\\]+)",
            text,
            flags=re.MULTILINE,
        )
    }


def test_appimagetool_is_immutable_asset_and_content_pinned():
    script = _read("packaging/linux/make_appimage.sh")

    assert "releases/download/continuous" not in script
    assert "https://api.github.com/repos/AppImage/AppImageKit/releases/assets/$ASSET_ID" in script
    assert 'ASSET_ID="98605504"' in script
    assert 'ASSET_ID="98605483"' in script
    assert (
        'EXPECTED_SHA256="b90f4a8b18967545fda78a445b27680a1642f1ef9488ced28b65398f2be7add2"'
        in script
    )
    assert (
        'EXPECTED_SHA256="a48972e5ae91c944c5a7c80214e7e0a42dd6aa3ae979d8756203512a74ff574d"'
        in script
    )
    assert 'EXPECTED_BYTES="8811712"' in script
    assert 'EXPECTED_BYTES="6115712"' in script
    assert "--proto '=https' --tlsv1.2" in script
    assert "--header 'Accept: application/octet-stream'" in script
    assert "--retry-all-errors" in script

    download = script.index("curl --fail")
    verify_size = script.index('if [ "$ACTUAL_BYTES" != "$EXPECTED_BYTES" ]')
    verify_hash = script.index('if [ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]')
    executable = script.index('chmod +x "$APPIMAGETOOL_BIN"')
    invoke = script.index('"$APPIMAGETOOL_BIN" --no-appstream')
    assert download < verify_size < verify_hash < executable < invoke


def test_appimage_staging_is_bounded_and_non_overwriting():
    script = _read("packaging/linux/make_appimage.sh")
    assert "mktemp -d" in script
    assert "trap 'rm -rf -- \"$TMP\"' EXIT HUP INT TERM" in script
    assert 'if [ -e "$OUT_APPIMAGE" ] || [ -L "$OUT_APPIMAGE" ]' in script
    assert "refusing to overwrite" in script
    assert 'mkdir -p "$APPDIR/usr/bin" "$APPDIR/usr/lib/one-link"' in script
    assert 'payload must contain executable one-link' in script


def test_rendezvous_requirements_are_exact_hashed_lock_subset():
    direct = _read("deploy/rendezvous/requirements.in")
    generated = _read("deploy/rendezvous/requirements.lock")
    versions = _requirements_versions()
    uv_versions = _uv_versions()

    assert "aiohttp==3.14.5" in direct
    assert "cryptography==50.0.0" in direct
    assert "!deploy/rendezvous/requirements.lock" in _read(".gitignore")
    assert len(versions) == 13
    assert versions.keys() <= uv_versions.keys()
    for name, version in versions.items():
        assert version == uv_versions[name], name

    starts = list(
        re.finditer(
            r"^([A-Za-z0-9_.-]+)==([^\s;\\]+)",
            generated,
            flags=re.MULTILINE,
        )
    )
    for index, match in enumerate(starts):
        end = starts[index + 1].start() if index + 1 < len(starts) else len(generated)
        block = generated[match.start() : end]
        assert re.search(r"--hash=sha256:[0-9a-f]{64}(?:\s|$)", block), match.group(1)


def test_dockerfile_external_inputs_and_installs_fail_closed():
    dockerfile = _read("deploy/rendezvous/Dockerfile")
    from_lines = [line for line in dockerfile.splitlines() if line.startswith("FROM ")]

    assert len(from_lines) == 3
    for line in from_lines:
        image = line.split()[1]
        assert re.fullmatch(r"[^\s@]+:[^\s@]+@sha256:[0-9a-f]{64}", image), line

    assert "python:3.12.14-slim-bookworm@sha256:" in dockerfile
    assert "ghcr.io/astral-sh/uv:0.13.10@sha256:" in dockerfile
    assert "apt-get" not in dockerfile
    assert "--require-hashes" in dockerfile
    assert "--no-build" in dockerfile
    assert "--no-deps" in dockerfile
    assert "--no-python-downloads" in dockerfile
    assert "pip install --no-cache-dir" not in dockerfile

    runtime = dockerfile.split(" AS runtime", maxsplit=1)[1]
    assert "COPY --from=dependencies /opt/rendezvous-venv" in runtime
    assert "COPY src /" not in dockerfile
    assert "USER 10001:10001" in runtime
    assert 'PYTHONDONTWRITEBYTECODE=1' in runtime


def test_container_source_allowlist_matches_one_link_import_closure():
    dockerfile = _read("deploy/rendezvous/Dockerfile")
    for module in RENDEZVOUS_MODULES:
        filename = "__init__.py" if module == "__init__" else f"{module}.py"
        assert f"src/one_link/{filename}" in dockerfile

    for module in RENDEZVOUS_MODULES - {"__init__"}:
        tree = ast.parse(_read(f"src/one_link/{module}.py"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "one_link":
                assert {alias.name for alias in node.names} <= RENDEZVOUS_MODULES
            elif isinstance(node, ast.ImportFrom) and (node.module or "").startswith(
                "one_link."
            ):
                imported = (node.module or "").split(".", maxsplit=1)[1]
                assert imported in RENDEZVOUS_MODULES
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith("one_link."):
                        assert alias.name.split(".", maxsplit=1)[1] in RENDEZVOUS_MODULES


def test_minimal_container_module_set_is_runtime_complete(tmp_path: Path):
    package = tmp_path / "one_link"
    package.mkdir()
    # An empty module set would copy nothing and still "prove" the container
    # surface is runtime-complete, because the probe below imports from a
    # package that happens to be importable for other reasons.
    assert len(RENDEZVOUS_MODULES) >= 6, (
        f"rendezvous module set collapsed to {sorted(RENDEZVOUS_MODULES)}"
    )
    for module in RENDEZVOUS_MODULES:
        filename = "__init__.py" if module == "__init__" else f"{module}.py"
        shutil.copy2(REPO / "src" / "one_link" / filename, package / filename)

    probe = f"""
import sys
sys.path.insert(0, {str(tmp_path)!r})
from one_link.rendezvous_proto import Endpoint
from one_link.rendezvous_server import Registration, Registry
r = Registry(max_entries=1)
r.upsert(Registration(
    pubkey=bytes(range(32)),
    observed_endpoint=Endpoint('127.0.0.1', 7118),
    advertised_endpoints=[Endpoint('127.0.0.1', 7118)],
    nat_type='unknown',
    capabilities=[],
    registered_at_ms=1,
    expires_at_ms=2,
))
assert len(r) == 1
"""
    subprocess.run(
        [sys.executable, "-I", "-c", probe],
        check=True,
        capture_output=True,
        text=True,
    )


def test_compose_never_pulls_public_image_and_exposes_only_proxy_loopback():
    compose = _read("deploy/rendezvous/docker-compose.yml")

    assert not re.search(r"(?m)^\s+image\s*:", compose)
    assert '"127.0.0.1:7118:7118"' in compose
    assert 'ONE_LINK_RDZ_TRUST_PROXY_HEADERS: "true"' in compose
    assert "read_only: true" in compose
    assert "no-new-privileges:true" in compose
    assert re.search(r"cap_drop:\s*\n\s*- ALL", compose)
    assert "pids_limit: 128" in compose
    assert "noexec,nosuid,nodev,size=16m" in compose
    assert "init: true" in compose
    assert 'max-size: "10m"' in compose


def test_container_version_and_operator_docs_match_source_version():
    version = tomllib.loads(_read("pyproject.toml"))["project"]["version"]
    compose = _read("deploy/rendezvous/docker-compose.yml")
    init = _read("src/one_link/__init__.py")
    desktop = _read("packaging/linux/one-link.desktop")
    operator_docs = _read("docs/RENDEZVOUS_DEPLOY.md")

    assert f'ONE_LINK_VERSION: "{version}"' in compose
    assert f'__version__ = "{version}"' in init
    # Match the complete line: a bare substring check let 0.21.0 "match"
    # X-AppImage-Version=0.21.0-alpha, shipping a stale desktop version
    # behind a green gate.
    assert f"X-AppImage-Version={version}\n" in desktop
    assert not re.search(r"(?m)^\s*(?:image:|docker run).+onelink/rendezvous:", operator_docs)
    assert "onelink/rendezvous:0.5.3" not in operator_docs
    assert "Do not pull `onelink/rendezvous:latest`" in operator_docs
    assert "does not currently publish a verified" in operator_docs


def test_entrypoint_validates_proxy_trust_and_maps_bounded_server_controls():
    entrypoint = _read("deploy/rendezvous/entrypoint.sh")

    assert "ONE_LINK_RDZ_TRUST_PROXY_HEADERS must be true or false" in entrypoint
    assert "--trust-proxy-headers" in entrypoint
    assert "--rate-lookup-per-ip-per-min" in entrypoint
    assert "--rate-new-pubkey-register-per-ip-per-min" in entrypoint
    assert "--rate-listener-replace-per-pubkey-per-min" in entrypoint
    assert "--max-concurrent-connections" in entrypoint
    assert "exec /opt/rendezvous-venv/bin/python" in entrypoint
    assert "umask 077" in entrypoint


def test_docker_build_context_is_default_deny_and_contains_no_local_state():
    lines = [
        line.strip()
        for line in _read(".dockerignore").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]

    assert lines[0] == "**"
    allowed_files = {
        line[1:] for line in lines if line.startswith("!") and not line.endswith("/")
    }
    assert allowed_files == {
        "deploy/rendezvous/Dockerfile",
        "deploy/rendezvous/entrypoint.sh",
        "deploy/rendezvous/requirements.lock",
        "src/one_link/__init__.py",
        "src/one_link/rdz_blind.py",
        "src/one_link/relay_proto.py",
        "src/one_link/relay_routing.py",
        "src/one_link/rendezvous_proto.py",
        "src/one_link/rendezvous_server.py",
    }
