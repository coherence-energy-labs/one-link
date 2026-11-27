"""Keeping fire-and-forget tasks alive.

The event loop holds only a weak reference to a task. A task started with
``asyncio.create_task(...)`` whose result is thrown away can be
garbage-collected before it finishes, and when that happens the work simply
stops, with no error anywhere. Anything that starts a task and does not
await it or store it should start it with :func:`spawn`.

The daemon's own ``_track`` does the same job for tasks that ``stop()``
must wait for. :func:`spawn` is for the rest, including the task that
performs the shutdown and therefore cannot be one of the tasks shutdown
waits for.
"""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from typing import Any

_LIVE: set[asyncio.Future[Any]] = set()


def spawn(coro: Coroutine[Any, Any, Any]) -> asyncio.Future[Any]:
    """Start ``coro`` on the running loop and hold it until it finishes."""
    task = asyncio.ensure_future(coro)
    _LIVE.add(task)
    task.add_done_callback(_LIVE.discard)
    return task
