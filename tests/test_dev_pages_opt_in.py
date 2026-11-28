"""Developer self-test pages are not served unless explicitly enabled."""

from __future__ import annotations

import pytest

from one_link import server as server_module
from one_link.server import UIServer


async def _fetch_dr_test():
    ui = UIServer.__new__(UIServer)
    return await ui._dr_test_page(None)


@pytest.mark.asyncio
async def test_self_test_page_is_hidden_by_default(monkeypatch) -> None:
    monkeypatch.delenv(server_module.DEV_PAGES_ENV, raising=False)
    response = await _fetch_dr_test()
    assert response.status == 404
    assert "dr_test" not in response.text


@pytest.mark.asyncio
@pytest.mark.parametrize("value", ["0", "true", "yes", ""])
async def test_only_the_exact_opt_in_value_enables_it(monkeypatch, value: str) -> None:
    monkeypatch.setenv(server_module.DEV_PAGES_ENV, value)
    assert (await _fetch_dr_test()).status == 404


@pytest.mark.asyncio
async def test_opt_in_serves_the_page_from_a_source_checkout(monkeypatch) -> None:
    monkeypatch.setenv(server_module.DEV_PAGES_ENV, "1")
    response = await _fetch_dr_test()
    if (server_module.WEB_DIR / "dr_test.html").is_file():
        assert response.status == 200
        assert "script-src 'self'" in response.headers["Content-Security-Policy"]
    else:
        assert response.status == 404
