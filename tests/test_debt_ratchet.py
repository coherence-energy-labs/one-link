"""Known debt may shrink but not grow. See ``tests/debt_ratchet.py``."""

from __future__ import annotations

import ast

from tests import debt_ratchet as ratchet


def test_debt_is_at_its_recorded_baseline() -> None:
    assert ratchet.compare(ratchet.measure(), ratchet.load_baseline()) == []


def _handlers(source: str) -> list[bool]:
    return [
        ratchet._is_broad(node)
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.ExceptHandler)
    ]


def test_what_counts_as_a_broad_handler() -> None:
    template = "try:\n    pass\nexcept {}:\n    pass\n"
    for clause in ("Exception", "BaseException", "(OSError, Exception)", "Exception as exc"):
        assert _handlers(template.format(clause)) == [True], clause
    assert _handlers("try:\n    pass\nexcept:\n    pass\n") == [True]
    for clause in ("OSError", "(OSError, ValueError)", "KeyError as exc", "asyncio.TimeoutError"):
        assert _handlers(template.format(clause)) == [False], clause


def test_growth_is_refused_and_shrinkage_must_be_recorded() -> None:
    baseline = {"broad_handlers": {"a.py": 2}, "ui_source_tests": ["test_old.py"]}
    grown = {"broad_handlers": {"a.py": 3}, "ui_source_tests": ["test_old.py"]}
    assert "baseline allows 2" in ratchet.compare(grown, baseline)[0]
    new_file = {"broad_handlers": {"a.py": 2, "b.py": 1}, "ui_source_tests": ["test_old.py"]}
    assert ratchet.compare(new_file, baseline)[0].startswith("b.py")
    shrunk = {"broad_handlers": {"a.py": 1}, "ui_source_tests": ["test_old.py"]}
    assert "--write" in ratchet.compare(shrunk, baseline)[0]
    new_ui_test = {"broad_handlers": {"a.py": 2}, "ui_source_tests": ["test_new.py", "test_old.py"]}
    assert "tests/test_new.py asserts on the text" in ratchet.compare(new_ui_test, baseline)[0]


def test_the_measurement_sees_the_debt_it_is_for() -> None:
    current = ratchet.measure()
    assert current["broad_handlers_total"] > 1000
    assert current["broad_handlers"]["daemon.py"] > 100
    assert len(current["ui_source_tests"]) > 50
    # This change's own tests must not have added to either pile.
    for name in ("test_peer_admission.py", "test_html_sink_gate.py", "test_dev_pages_opt_in.py"):
        assert name not in current["ui_source_tests"]
