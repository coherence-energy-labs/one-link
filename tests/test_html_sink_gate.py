"""New places that turn a string into markup do not get in unnoticed."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load():
    spec = importlib.util.spec_from_file_location(
        "check_html_sinks_under_test", ROOT / "scripts" / "check_html_sinks.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


sinks = _load()


def _kinds(source: str) -> list[str]:
    return [s.kind for s in sinks.scan_source(source, "x.js")]


@pytest.mark.parametrize(
    "source",
    [
        'el.innerHTML = "";',
        "el.innerHTML = '<b>fixed</b>';",
        "el.innerHTML = `<p>no substitutions</p>`;",
        'el.innerHTML = "<a>" + "<b>" + `<c>`;',
        'el.innerHTML = ("<a>" +\n    "<b>");',
        'el.innerHTML = "a;b";',
        'el.insertAdjacentHTML("beforeend", "<hr>");',
        'el.outerHTML = "<div></div>";',
        'if (ok) el.innerHTML = "<b>x</b>"\n',
    ],
)
def test_markup_spelled_out_in_literals_is_static(source: str) -> None:
    assert _kinds(source) == ["static"]


@pytest.mark.parametrize(
    "source",
    [
        "el.innerHTML = name;",
        "el.innerHTML = `<b>${name}</b>`;",
        'el.innerHTML = "<b>" + name + "</b>";',
        "el.innerHTML = render(row);",
        'el.innerHTML = ok ? "<a>" : "<b>";',
        'el.innerHTML += "<li></li>";',
        'el.insertAdjacentHTML("beforeend", row);',
        'el.insertAdjacentHTML("beforeend", `<li>${x}</li>`);',
        "frame.srcdoc = page;",
        "document.write(html);",
        "range.createContextualFragment(html);",
        "el.innerHTML = [a, b].join('');",
        "el.innerHTML = `${a}`\n",
    ],
)
def test_anything_that_can_carry_data_is_dynamic(source: str) -> None:
    assert _kinds(source) == ["dynamic"]


def test_comparisons_reads_and_comments_are_not_sinks() -> None:
    source = """
    if (el.innerHTML === "") return;
    const copy = el.innerHTML;
    // el.innerHTML = danger;
    /* el.innerHTML = danger; */
    const text = "el.innerHTML = danger;";
    """
    assert _kinds(source) == []


def test_brackets_inside_strings_do_not_confuse_the_scanner() -> None:
    assert _kinds('el.insertAdjacentHTML("beforeend", "a, b) c");') == ["static"]
    assert _kinds("el.insertAdjacentHTML(where(a, b), row);") == ["dynamic"]


def test_ui_sources_are_at_their_baseline() -> None:
    current = sinks.dynamic_counts(sinks.scan_tree())
    assert sinks.compare(current, sinks.load_baseline()) == []


def test_a_new_dynamic_sink_fails_the_gate() -> None:
    baseline = {"a.js": 1}
    (problem,) = sinks.compare({"a.js": 2}, baseline)
    assert "baseline allows 1" in problem
    (problem,) = sinks.compare({"a.js": 1, "new.js": 1}, baseline)
    assert problem.startswith("new.js")


def test_a_removed_sink_must_be_locked_in() -> None:
    (problem,) = sinks.compare({}, {"a.js": 1})
    assert "--update" in problem


def test_sinks_fixed_in_this_change_stay_fixed() -> None:
    peer_settings = (ROOT / "frontend/peer/ui/settings.js").read_text(encoding="utf-8")
    assert [s for s in sinks.scan_source(peer_settings, "s.js") if s.kind == "dynamic"] == []
    paste = (ROOT / "frontend/owner/main/upload_paste.js").read_text(encoding="utf-8")
    # Clipboard markup is parsed into an inert document, never into the page.
    assert "DOMParser().parseFromString" in paste
    assert sinks.scan_source(paste, "p.js") == []
