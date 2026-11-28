"""A task that is started and not kept must still finish."""

from __future__ import annotations

import asyncio
import gc

import pytest

from one_link import task_refs


@pytest.mark.asyncio
async def test_spawned_task_survives_garbage_collection_and_is_released() -> None:
    finished = asyncio.Event()

    async def work() -> None:
        await asyncio.sleep(0.01)
        finished.set()

    task_refs.spawn(work())
    assert len(task_refs._LIVE) >= 1
    gc.collect()
    await asyncio.wait_for(finished.wait(), timeout=2)
    await asyncio.sleep(0)
    assert not [t for t in task_refs._LIVE if t.done()]


@pytest.mark.asyncio
async def test_failed_task_is_released_too() -> None:
    async def boom() -> None:
        raise RuntimeError("expected")

    task = task_refs.spawn(boom())
    with pytest.raises(RuntimeError):
        await task
    await asyncio.sleep(0)
    assert task not in task_refs._LIVE


def test_no_fire_and_forget_task_is_started_without_a_reference() -> None:
    """The lint rule that enforces this is switched on."""
    import tomllib
    from pathlib import Path

    config = tomllib.loads(
        (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(encoding="utf-8")
    )["tool"]["ruff"]["lint"]
    assert "RUF006" in config["select"]
    assert "RUF006" not in config["ignore"]
    assert {"B", "PLE"} <= set(config["select"])
