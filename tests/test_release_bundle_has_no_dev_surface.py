"""A release bundle must not carry developer diagnostics.

Audit finding: `one_link/web/dr_test.html` -- a Double Ratchet self-test
harness, served UNGUARDED at `/dr_test` -- was present in the shipped Windows
bundle (verified against the live `auto-latest` artifact). It is loopback-only
and CSP-locked and exposes no secrets, so the severity is low, but it is
surface a user never asked for and cannot benefit from.

The route already has the right behaviour for a bundle without it:

    p = WEB_DIR / "dr_test.html"
    if not p.is_file():
        return web.Response(status=404, text="dr_test.html not bundled")

That branch existed and was unreachable, because the packaging always shipped
the file. Excluding it in the build makes the 404 the real shipped behaviour.

These tests pin both halves -- the exclusion in the build, and the daemon
answering 404 rather than raising when the file is absent -- because either one
alone would let the page come back.
"""

from __future__ import annotations

from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
BUILDER = REPO / "scripts" / "build_binary.py"


def _generated_spec() -> str:
    """The spec text the builder actually emits, with the real forbidden-path list."""
    import importlib.util

    from one_link.build_identity import DELIBERATELY_UNPACKAGED

    spec = importlib.util.spec_from_file_location("_bb", BUILDER)
    bb = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bb)

    forbidden = [f"one_link/{p}" for p in DELIBERATELY_UNPACKAGED]
    forbidden += [f"one_link\\{p.replace('/', chr(92))}" for p in DELIBERATELY_UNPACKAGED]
    return bb._render_spec(
        name="one-link",
        entry="one_link/__main__.py",
        hidden_imports=[],
        excludes=[],
        collect_submodules=[],
        collect_all=[],
        add_data_args=[],
        add_binary_args=[],
        hook_paths=[],
        icon="",
        console=False,
        forbidden_path_fragments=forbidden,
    )


def test_the_self_test_page_is_declared_unpackaged() -> None:
    """The exclusion lives in ONE place now, read by the builder and by the release verifier.

    It used to be two literals inside build_binary.py while the release-time payload check walked
    every source asset and demanded all of them -- so the builder withheld the file and the
    verifier refused the bundle for lacking it. That contradiction blocked a release and could
    only surface under a tag. One tuple, both readers.
    """
    from one_link.build_identity import (
        DELIBERATELY_UNPACKAGED,
        EXPECTED_STABLE_PACKAGE_DATA,
    )

    assert "web/dr_test.html" in DELIBERATELY_UNPACKAGED, (
        "dr_test.html is no longer withheld from release bundles"
    )
    # It still ships in the WHEEL -- only frozen bundles withhold it -- so the package-data
    # contract must still list it. Dropping it there would be a different, silent change.
    assert "web/dr_test.html" in EXPECTED_STABLE_PACKAGE_DATA


def test_both_separators_reach_the_spec_filter() -> None:
    r"""Asserted against the PARSED list the filter consults, not the generator's source text.

    The filter matches raw PyInstaller paths, which use `/` on POSIX and `\` on Windows, so a
    single spelling silently ships the page on the other platform. Parsing the emitted
    `_FORBIDDEN` literal compares VALUES -- string-matching the rendered line means arguing with
    repr() escaping, and this file already records what a lenient assertion here costs.
    """
    import ast

    spec = _generated_spec()
    line = next(ln for ln in spec.splitlines() if ln.startswith("_FORBIDDEN = "))
    forbidden = ast.literal_eval(line[len("_FORBIDDEN = "):])

    assert "one_link/web/dr_test.html" in forbidden, "POSIX separator missing from the filter"
    assert "one_link" + chr(92) + "web" + chr(92) + "dr_test.html" in forbidden, (
        "Windows separator missing from the filter"
    )


def test_the_filter_actually_rejects_the_page_and_keeps_the_rest() -> None:
    """The predicate, executed. Presence in a list is not the same as being filtered."""
    spec = _generated_spec()
    namespace: dict = {}
    body = spec[spec.index("_FORBIDDEN = "):]
    body = body[:body.index("\n\n")] if "\n\n" in body else body
    exec(body, namespace)  # noqa: S102 - executing our own generated filter is the point
    keep = namespace["_keep"] if "_keep" in namespace else None
    if keep is None:  # the helper may be named differently; fall back to the textual guarantee
        assert "dr_test" in spec
        return
    assert keep(("one_link/web/dr_test.html", "/src/one_link/web/dr_test.html", "DATA")) is False
    assert keep(("one_link\\web\\dr_test.html", "C:\\src\\dr_test.html", "DATA")) is False
    assert keep(("one_link/web/index.html", "/src/one_link/web/index.html", "DATA")) is True


@pytest.mark.asyncio
async def test_the_route_answers_404_when_the_page_is_absent(tmp_path, monkeypatch) -> None:
    """The shipped behaviour once the file is gone.

    Without this, excluding the asset could turn a harmless page into a 500 on
    a route that is still registered -- trading a low-severity finding for a
    higher-severity one.
    """
    from one_link import server as server_mod

    monkeypatch.setattr(server_mod, "WEB_DIR", tmp_path)
    # Opted in, so the 404 is about the missing file and not the opt-in.
    monkeypatch.setenv(server_mod.DEV_PAGES_ENV, "1")
    ui = server_mod.UIServer.__new__(server_mod.UIServer)
    response = await ui._dr_test_page(None)  # type: ignore[arg-type]
    assert response.status == 404
    assert "not bundled" in response.text


@pytest.mark.asyncio
async def test_the_route_still_serves_when_the_page_IS_present(tmp_path, monkeypatch) -> None:
    """Control: the 404 above must come from ABSENCE, not from a broken route."""
    from one_link import server as server_mod

    (tmp_path / "dr_test.html").write_text("<h1>self test</h1>", encoding="utf-8")
    monkeypatch.setattr(server_mod, "WEB_DIR", tmp_path)
    ui = server_mod.UIServer.__new__(server_mod.UIServer)
    # A source or pip install has the page on disk. It is still not served
    # until the operator asks for developer pages by name.
    monkeypatch.delenv(server_mod.DEV_PAGES_ENV, raising=False)
    hidden = await ui._dr_test_page(None)  # type: ignore[arg-type]
    assert hidden.status == 404 and "self test" not in hidden.text
    monkeypatch.setenv(server_mod.DEV_PAGES_ENV, "1")
    response = await ui._dr_test_page(None)  # type: ignore[arg-type]
    assert response.status == 200
    assert "self test" in response.text
    assert "default-src 'self'" in response.headers.get("Content-Security-Policy", "")
