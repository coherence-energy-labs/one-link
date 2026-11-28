#!/usr/bin/env python3
"""Third-party notices and the license gate.

One Link is AGPL-3.0-or-later and ships other people's code: the Rust crates
compiled into the native extension and the Python packages bundled with the
daemon. Most of their licenses (MIT, Apache-2.0, BSD) require that their
copyright and license be passed along, and a dependency under a license that
cannot be combined with the AGPL must never get in at all.

This script does both jobs from the lock files:

    python scripts/third_party_licenses.py            # rewrite THIRD_PARTY_NOTICES.md
    python scripts/third_party_licenses.py --check    # fail if it is stale or a license is not allowed

Rust licenses come from ``cargo metadata``. Python licenses come from the
metadata of the installed packages; the few that are not installable on the
current platform, or that publish no machine-readable license, are named in
``PYTHON_LICENSE_OVERRIDES`` with the license their upstream declares.
"""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NOTICES = ROOT / "THIRD_PARTY_NOTICES.md"
UV_LOCK = ROOT / "uv.lock"
# Each Rust workspace has its own lock file. ``key`` names the section when
# the notices file is read back.
RUST_WORKSPACES = (
    ("rust", "Rust crates compiled into the native extension", ROOT / "native"),
    ("shell", "Rust crates compiled into the desktop window (ol_shell)", ROOT / "native" / "ol_shell"),
)

# Licenses that may be combined with AGPL-3.0-or-later and redistributed.
# Adding an identifier here is a licensing decision; make it in review.
ALLOWED_LICENSES = frozenset(
    {
        "0BSD",
        "AGPL-3.0-or-later",
        "Apache-2.0",
        "BSD-1-Clause",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "BSL-1.0",
        "CC0-1.0",
        "GPL-3.0-or-later",
        "ISC",
        "LGPL-2.1-or-later",
        "LGPL-3.0-or-later",
        "MIT",
        "MIT-0",
        "MPL-2.0",
        "PSF-2.0",
        "Unicode-3.0",
        "Unicode-DFS-2016",
        "Unlicense",
        "Zlib",
    }
)
# ``WITH`` exceptions that only add permissions.
ALLOWED_EXCEPTIONS = frozenset({"LLVM-exception"})

# Free-text license fields seen in Python package metadata, mapped to SPDX.
_PYTHON_LICENSE_ALIASES = {
    "apache 2.0": "Apache-2.0",
    "apache software license": "Apache-2.0",
    "apache license, version 2.0": "Apache-2.0",
    "apache-2.0 and mit": "Apache-2.0 AND MIT",
    "bsd": "BSD-3-Clause",
    "bsd license": "BSD-3-Clause",
    "mit license": "MIT",
    "python software foundation license": "PSF-2.0",
}

# Packages whose installed metadata carries no usable license, or that cannot
# be installed on every platform this script runs on. The value is the
# license the project itself publishes.
PYTHON_LICENSE_OVERRIDES = {
    "backports-tarfile": "MIT",
    "colorama": "BSD-3-Clause",
    "google-crc32c": "Apache-2.0",
    "importlib-metadata": "Apache-2.0",
    "pywin32-ctypes": "BSD-3-Clause",
    "sigstore-models": "Apache-2.0",
    "zipp": "MIT",
}

DATA_AND_MODELS = """\
## Data and models

| Component | Source | License | Attribution |
|---|---|---|---|
| `voice_predictor_v3_librispeech` (voice predictor weights) | Trained on the LibriSpeech ASR corpus, <https://www.openslr.org/12> | CC BY 4.0 (corpus) | V. Panayotov, G. Chen, D. Povey and S. Khudanpur, "Librispeech: an ASR corpus based on public domain audio books", ICASSP 2015. The corpus is derived from LibriVox public-domain audiobooks. The weights were trained by the One Link project; no corpus audio is redistributed. |
"""


# ─── SPDX expressions ───────────────────────────────────────────────

_TOKEN = re.compile(r"\(|\)|[A-Za-z0-9.+-]+")


def normalize_expression(expression: str) -> str:
    """Bring Cargo's legacy ``A/B`` form to SPDX ``A OR B``."""
    return re.sub(r"\s*/\s*", " OR ", expression.strip())


def expression_allowed(expression: str) -> bool:
    """Can a component under ``expression`` be shipped?

    ``A OR B`` is allowed when either side is; ``A AND B`` when both are;
    ``A WITH E`` when ``A`` is allowed and ``E`` is a known exception.
    Anything that does not parse is not allowed.
    """
    tokens = _TOKEN.findall(normalize_expression(expression))
    if not tokens:
        return False
    position = 0

    def peek() -> str | None:
        return tokens[position] if position < len(tokens) else None

    def take() -> str:
        nonlocal position
        token = tokens[position]
        position += 1
        return token

    def atom() -> bool:
        token = peek()
        if token is None:
            raise ValueError("unexpected end")
        if token == "(":
            take()
            value = either()
            if peek() != ")":
                raise ValueError("unbalanced parenthesis")
            take()
            return value
        if token in {")", "AND", "OR", "WITH"}:
            raise ValueError(f"unexpected {token}")
        value = take() in ALLOWED_LICENSES
        if peek() == "WITH":
            take()
            exception = peek()
            if exception is None:
                raise ValueError("WITH needs an exception")
            value = value and take() in ALLOWED_EXCEPTIONS
        return value

    def both() -> bool:
        value = atom()
        while peek() == "AND":
            take()
            value = atom() and value
        return value

    def either() -> bool:
        value = both()
        while peek() == "OR":
            take()
            value = both() or value
        return value

    try:
        result = either()
    except ValueError:
        return False
    return result and position == len(tokens)


# ─── inventories ────────────────────────────────────────────────────


def rust_components(workspace_dir: Path) -> list[tuple[str, str, str]]:
    """``(name, version, license)`` for every crate a workspace depends on.

    Workspace members are One Link's own code and are left out. Vendored
    forks (path dependencies outside the workspace) are third-party code and
    are listed.
    """
    raw = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--locked", "--all-features"],
        cwd=workspace_dir,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    metadata = json.loads(raw)
    workspace = set(metadata["workspace_members"])
    components = {
        (pkg["name"], pkg["version"], normalize_expression(pkg.get("license") or "UNKNOWN"))
        for pkg in metadata["packages"]
        if pkg["id"] not in workspace
    }
    return sorted(components)


def locked_rust_packages(workspace_dir: Path) -> set[tuple[str, str]]:
    """``(name, version)`` of every non-member package in a workspace's lock."""
    lock = tomllib.loads((workspace_dir / "Cargo.lock").read_text(encoding="utf-8"))
    # A member has no ``source``; so does a vendored fork, which is why the
    # member names are read from the manifests instead.
    members = _workspace_member_names(workspace_dir)
    return {
        (pkg["name"], pkg["version"])
        for pkg in lock["package"]
        if pkg["name"] not in members
    }


def _workspace_member_names(workspace_dir: Path) -> set[str]:
    manifest = tomllib.loads((workspace_dir / "Cargo.toml").read_text(encoding="utf-8"))
    names: set[str] = set()
    if "package" in manifest:
        names.add(manifest["package"]["name"])
    for member in manifest.get("workspace", {}).get("members", []):
        member_manifest = workspace_dir / member / "Cargo.toml"
        if member_manifest.is_file():
            names.add(
                tomllib.loads(member_manifest.read_text(encoding="utf-8"))["package"]["name"]
            )
    return names


def python_runtime_packages() -> dict[str, str]:
    """``{name: version}`` for the project's runtime dependency closure."""
    lock = tomllib.loads(UV_LOCK.read_text(encoding="utf-8"))
    packages = {pkg["name"]: pkg for pkg in lock["package"]}
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["name"]
    root = packages.get(project) or packages[project.replace("_", "-")]
    seen: dict[str, str] = {}
    pending = [dep["name"] for dep in root.get("dependencies", [])]
    while pending:
        name = pending.pop()
        if name in seen:
            continue
        seen[name] = packages[name]["version"]
        pending.extend(dep["name"] for dep in packages[name].get("dependencies", []))
    return dict(sorted(seen.items()))


def python_license(name: str) -> str:
    if name in PYTHON_LICENSE_OVERRIDES:
        return PYTHON_LICENSE_OVERRIDES[name]
    try:
        meta = importlib.metadata.metadata(name)
    except importlib.metadata.PackageNotFoundError:
        return "UNKNOWN"
    expression = (meta.get("License-Expression") or "").strip()
    if expression:
        return expression
    declared = (meta.get("License") or "").strip()
    if declared and "\n" not in declared and len(declared) < 60:
        return _PYTHON_LICENSE_ALIASES.get(declared.lower(), declared)
    for classifier in meta.get_all("Classifier") or []:
        if classifier.startswith("License ::"):
            label = classifier.split(" :: ")[-1]
            return _PYTHON_LICENSE_ALIASES.get(label.lower(), label)
    return "UNKNOWN"


def python_components() -> list[tuple[str, str, str]]:
    return [
        (name, version, python_license(name))
        for name, version in python_runtime_packages().items()
    ]


# ─── document ───────────────────────────────────────────────────────


def _table(rows: list[tuple[str, str, str]]) -> str:
    lines = ["| Component | Version | License |", "|---|---|---|"]
    lines += [f"| {name} | {version} | {license_} |" for name, version, license_ in rows]
    return "\n".join(lines)


def render(
    rust: dict[str, list[tuple[str, str, str]]], python: list[tuple[str, str, str]]
) -> str:
    rust_sections = "".join(
        f"## {title} ({len(rust[key])})\n\n{_table(rust[key])}\n\n"
        for key, title, _dir in RUST_WORKSPACES
    )
    return (
        "# Third-party notices\n\n"
        "One Link is licensed under AGPL-3.0-or-later (see `LICENSE`). It includes\n"
        "or links the third-party components listed here, each under its own\n"
        "license. The full license texts are distributed with each component's\n"
        "source: for Rust crates in the crate archive on crates.io, for Python\n"
        "packages in the package's distribution metadata.\n\n"
        "This file is generated by `python scripts/third_party_licenses.py` from\n"
        "`native/Cargo.lock`, `native/ol_shell/Cargo.lock` and `uv.lock`. Do not\n"
        "edit it by hand.\n"
        "`python scripts/third_party_licenses.py --check` fails when it is stale\n"
        "or when a component's license is not on the allow list in that script.\n\n"
        f"{DATA_AND_MODELS}\n"
        f"{rust_sections}"
        f"## Python packages bundled with the daemon ({len(python)})\n\n"
        f"{_table(python)}\n"
    )


def parse_tables(text: str) -> dict[str, list[tuple[str, str, str]]]:
    """Read the component tables back out of a rendered notices file."""
    sections: dict[str, list[tuple[str, str, str]]] = {}
    current: str | None = None
    for line in text.splitlines():
        rust_key = next(
            (key for key, title, _dir in RUST_WORKSPACES if line.startswith(f"## {title}")),
            None,
        )
        if rust_key:
            current = rust_key
            sections[current] = []
        elif line.startswith("## Python packages"):
            current = "python"
            sections[current] = []
        elif line.startswith("## "):
            current = None
        elif current and line.startswith("| ") and not line.startswith(("| Component", "|---")):
            cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
            if len(cells) == 3:
                sections[current].append((cells[0], cells[1], cells[2]))
    return sections


def disallowed(components: list[tuple[str, str, str]]) -> list[tuple[str, str, str]]:
    return [c for c in components if not expression_allowed(c[2])]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--check", action="store_true", help="verify instead of writing")
    args = parser.parse_args(argv)

    rust = {key: rust_components(directory) for key, _title, directory in RUST_WORKSPACES}
    python = python_components()
    everything = [c for rows in rust.values() for c in rows] + python
    problems = [
        f"license not allowed: {name} {version} ({license_})"
        for name, version, license_ in disallowed(everything)
    ]
    document = render(rust, python)
    if args.check:
        current = NOTICES.read_text(encoding="utf-8") if NOTICES.is_file() else ""
        if current != document:
            problems.append(
                f"{NOTICES.name} is stale; run `python scripts/third_party_licenses.py`"
            )
    else:
        NOTICES.write_text(document, encoding="utf-8")
        crates = sum(len(rows) for rows in rust.values())
        print(f"wrote {NOTICES.name}: {crates} crates, {len(python)} Python packages")
    for problem in problems:
        print(problem, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
