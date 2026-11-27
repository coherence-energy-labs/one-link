"""A settings transaction is never held open across a wait."""

from __future__ import annotations

import asyncio
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from one_link.server import _atomic_settings_update


class _State:
    def __init__(self) -> None:
        self.events: list[str] = []
        self.open = False

    @contextmanager
    def durable_write_transaction(self):
        self.open = True
        self.events.append("begin")
        try:
            yield
            self.events.append("commit")
        except BaseException:
            self.events.append("rollback")
            raise
        finally:
            self.open = False


class _Request:
    """A body that takes a while to arrive, then is cached, like aiohttp's."""

    def __init__(self, state: _State, payload: dict) -> None:
        self._state = state
        self._payload = payload
        self._arrived = False
        self.transaction_open_while_reading: bool | None = None

    async def read(self) -> bytes:
        if not self._arrived:
            self.transaction_open_while_reading = self._state.open
            await asyncio.sleep(0)
            self._arrived = True
        return b""

    async def json(self) -> dict:
        await self.read()
        return self._payload


def _server(state: _State) -> SimpleNamespace:
    return SimpleNamespace(daemon=SimpleNamespace(state=state))


@pytest.mark.asyncio
async def test_body_is_read_before_the_transaction_opens() -> None:
    state = _State()
    request = _Request(state, {"k": 1})

    @_atomic_settings_update
    async def handler(self, req):
        data = await req.json()
        assert state.open
        return SimpleNamespace(status=200, data=data)

    response = await handler(_server(state), request)
    assert response.data == {"k": 1}
    assert request.transaction_open_while_reading is False
    assert state.events == ["begin", "commit"]


@pytest.mark.asyncio
async def test_refused_request_rolls_back() -> None:
    state = _State()

    @_atomic_settings_update
    async def handler(self, req):
        await req.json()
        return SimpleNamespace(status=400)

    response = await handler(_server(state), _Request(state, {}))
    assert response.status == 400
    assert state.events == ["begin", "rollback"]


@pytest.mark.asyncio
async def test_handler_that_waits_inside_the_transaction_is_stopped() -> None:
    state = _State()
    cleaned_up = []

    @_atomic_settings_update
    async def handler(self, req):
        await req.json()
        try:
            await asyncio.sleep(0)  # lets other coroutines write into this commit
        finally:
            cleaned_up.append(True)
        return SimpleNamespace(status=200)

    with pytest.raises(RuntimeError, match="waited on something inside its settings transaction"):
        await handler(_server(state), _Request(state, {}))
    assert state.events == ["begin", "rollback"]
    assert cleaned_up == [True]
    assert state.open is False


@pytest.mark.asyncio
async def test_without_a_state_store_the_handler_just_runs() -> None:
    @_atomic_settings_update
    async def handler(self, req):
        await asyncio.sleep(0)
        return SimpleNamespace(status=200)

    response = await handler(SimpleNamespace(daemon=SimpleNamespace(state=None)), None)
    assert response.status == 200
