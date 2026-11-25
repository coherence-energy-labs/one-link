"""Import heavy optional modules without ever blocking an asyncio event loop.

A first ``from aiortc import ...`` loads PyAV and native codecs and was
measured at several seconds on a cold cache; done inside a request handler it
stalls every other request, WebSocket and timer the daemon serves. Even a pure
Python module such as ``qrcode.image.svg`` costs ~0.2 s on first import.

:class:`OffLoopImporter` runs each import exactly once per process on a small
dedicated worker pool and lets any number of coroutines, on any event loop,
await the same job:

* concurrent awaiters share one import job;
* a successful import is served from the finished job with no await or thread
  hop afterwards;
* ``ImportError`` (the module is not installed) is cached and re-raised
  immediately, so an unavailable optional dependency fails honestly and fast;
* any other failure (for example a native library that failed to load) is not
  cached: the next caller retries;
* cancelling an awaiting coroutine never cancels the shared import.

The default importer resolves ``__import__`` from builtins at call time, the
same hook an ``import`` statement uses.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import sys
import threading
from types import ModuleType
from typing import Callable, Iterable, Optional

Importer = Callable[[str], ModuleType]


def import_by_name(name: str) -> ModuleType:
    """Import *name* through the builtin import hook and return that module."""

    __import__(name)
    return sys.modules[name]


class OffLoopImporter:
    """Process-wide, loop-agnostic, once-only module import service."""

    def __init__(
        self,
        importer: Importer | None = None,
        *,
        max_workers: int = 2,
    ) -> None:
        self._importer: Importer = importer if importer is not None else import_by_name
        self._max_workers = max(1, int(max_workers))
        self._lock = threading.Lock()
        self._jobs: dict[str, concurrent.futures.Future[ModuleType]] = {}
        self._pool: Optional[concurrent.futures.ThreadPoolExecutor] = None

    def _executor(self) -> concurrent.futures.ThreadPoolExecutor:
        if self._pool is None:
            self._pool = concurrent.futures.ThreadPoolExecutor(
                max_workers=self._max_workers,
                thread_name_prefix="one-link-import",
            )
        return self._pool

    @staticmethod
    def _retryable(job: concurrent.futures.Future[ModuleType]) -> bool:
        if not job.done():
            return False
        if job.cancelled():
            return True
        error = job.exception()
        return error is not None and not isinstance(error, ImportError)

    def job(self, name: str) -> concurrent.futures.Future[ModuleType]:
        """Return the shared import job for *name*, starting it if needed."""

        if not isinstance(name, str) or not name or name.startswith("."):
            raise ValueError("an absolute module name is required")
        with self._lock:
            job = self._jobs.get(name)
            if job is None or self._retryable(job):
                job = self._executor().submit(self._importer, name)
                self._jobs[name] = job
            return job

    async def load(self, name: str) -> ModuleType:
        """Return module *name*, importing it off the running loop if needed.

        Raises ``ImportError`` when the module is not installed and whatever
        else the import raised otherwise.
        """

        job = self.job(name)
        if job.done():
            return job.result()
        return await asyncio.shield(asyncio.wrap_future(job))

    async def load_optional(self, name: str) -> ModuleType | None:
        """Like :meth:`load`, but ``None`` when the module is not installed."""

        try:
            return await self.load(name)
        except ImportError:
            return None

    def warm(self, names: Iterable[str]) -> None:
        """Start background imports now; failures surface on a later load."""

        for name in names:
            job = self.job(name)
            # Retrieve the outcome so an unavailable optional module is never
            # reported as an unobserved exception at interpreter shutdown.
            job.add_done_callback(
                lambda finished: finished.exception() if not finished.cancelled() else None
            )


#: Shared instance used by request handlers.
OFF_LOOP_IMPORTS = OffLoopImporter()
