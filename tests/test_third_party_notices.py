"""Third-party components are listed, and none has a license we cannot ship."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load():
    spec = importlib.util.spec_from_file_location(
        "third_party_licenses_under_test", ROOT / "scripts" / "third_party_licenses.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


tpl = _load()
TABLES = tpl.parse_tables(tpl.NOTICES.read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    "expression",
    [
        "MIT",
        "MIT OR Apache-2.0",
        "MIT/Apache-2.0",
        "Apache-2.0 / MIT",
        "Apache-2.0 AND ISC",
        "(MIT OR Apache-2.0) AND Unicode-3.0",
        "Apache-2.0 WITH LLVM-exception",
        "Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT",
        "GPL-2.0-only OR MIT",  # one allowed alternative is enough
        "LGPL-2.1-or-later",
        "MPL-2.0",
    ],
)
def test_shippable_expressions(expression: str) -> None:
    assert tpl.expression_allowed(expression) is True


@pytest.mark.parametrize(
    "expression",
    [
        "",
        "UNKNOWN",
        "GPL-2.0-only",
        "SSPL-1.0",
        "BUSL-1.1",
        "CC-BY-NC-4.0",
        "MIT AND GPL-2.0-only",  # every AND term must be allowed
        "Proprietary",
        "Apache-2.0 WITH Commons-Clause",
        "MIT OR",
        "(MIT",
        "MIT Apache-2.0",
    ],
)
def test_unshippable_or_unparseable_expressions(expression: str) -> None:
    assert tpl.expression_allowed(expression) is False


@pytest.mark.parametrize("key, _title, directory", tpl.RUST_WORKSPACES)
def test_every_locked_crate_is_listed(key: str, _title: str, directory: Path) -> None:
    listed = {(name, version) for name, version, _license in TABLES[key]}
    locked = tpl.locked_rust_packages(directory)
    assert locked - listed == set(), (
        "crates in the lock file but not in THIRD_PARTY_NOTICES.md; run "
        "`python scripts/third_party_licenses.py`"
    )
    assert listed - locked == set(), "THIRD_PARTY_NOTICES.md lists crates no longer locked"


def test_every_runtime_python_package_is_listed() -> None:
    listed = {name: version for name, version, _license in TABLES["python"]}
    assert listed == tpl.python_runtime_packages()


def test_no_listed_component_has_a_disallowed_license() -> None:
    everything = [row for rows in TABLES.values() for row in rows]
    assert len(everything) > 500
    assert tpl.disallowed(everything) == []


def test_vendored_forks_are_listed_as_third_party() -> None:
    assert any(name == "ml-kem" for name, _v, _l in TABLES["rust"])
    assert any(name == "glib" for name, _v, _l in TABLES["shell"])


def test_trained_model_carries_its_dataset_attribution() -> None:
    text = tpl.NOTICES.read_text(encoding="utf-8")
    assert "voice_predictor_v3_librispeech" in text
    assert "Panayotov" in text and "CC BY 4.0" in text and "openslr.org/12" in text


def test_the_project_itself_is_not_listed_as_third_party() -> None:
    for rows in TABLES.values():
        assert not [name for name, _v, _l in rows if name in {"one_link", "one-link", "ol_pqkem"}]
