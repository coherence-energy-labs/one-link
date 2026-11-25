"""What the daemon records when it refuses an owner request.

On 2026-11-25 an open owner window was answered 401 around a daemon restart and
nothing recorded it, so whether the window had presented a per-process owner
token (expected to die with the process) or a persistent session (expected to
survive) could not be recovered afterwards. One line now answers that at the
time. On its first use it reported ``presented=header shape=session`` for a
window whose session a restart had invalidated, which is what pointed at the
one-way migration that was re-running on every start.

The line never contains a credential: only where one was presented and whether
it has the shape of a persistent session bearer. The path is the route pattern,
so peer fingerprints in URLs are not copied into the log. At most one line a
minute per client, in a rate-limit bucket of its own so that it neither
consumes nor hides attempts from the limit that protects the owner token. A
failure to write the note cannot change the answer the client gets.

What it needs from the UI server is the explicit :class:`OwnerAuthPort`.

Tests: ``tests/test_owner_auth_refusal_note.py``.
"""

from __future__ import annotations

import logging
from typing import Any, Protocol

NOTE_BUCKET = "auth_refusal_note"


class OwnerAuthPort(Protocol):
    """The UI server operations the note reads. It changes none of them."""

    @property
    def daemon(self) -> Any: ...

    def _rate_limited(self, bucket_name: str, key: str, *, limit: int) -> bool: ...

    def _client_rate_key(self, request: Any) -> str: ...

    def _authorization_bearer(self, request: Any) -> str: ...

    def _websocket_bearer(self, request: Any) -> str: ...

    def _owner_auth_transport_ok(self, request: Any) -> bool: ...


def note_refused_owner_request(
    port: OwnerAuthPort,
    request: Any,
    *,
    log: logging.Logger,
    cookie_names: tuple[str, str],
) -> None:
    """Log, at most once a minute per client, what a refused owner request presented.

    ``cookie_names`` is (session cookie, owner cookie).
    """
    try:
        if port._rate_limited(NOTE_BUCKET, port._client_rate_key(request), limit=1):
            return
        session_cookie, owner_cookie = cookie_names
        header = port._authorization_bearer(request)
        socket = port._websocket_bearer(request)
        if header:
            presented, token = "header", header
        elif socket:
            presented, token = "websocket", socket
        elif request.cookies.get(session_cookie, "") or request.cookies.get(owner_cookie, ""):
            presented, token = "cookie", request.cookies.get(session_cookie, "")
        else:
            presented, token = "none", ""
        state = getattr(port.daemon, "state", None)
        if not token:
            shape = "none"
        elif state is None:
            shape = "unchecked"
        elif state.ui_session_token_id(token) is not None:
            shape = "session"
        else:
            shape = "other"
        route = getattr(getattr(request.match_info, "route", None), "resource", None)
        pattern = getattr(route, "canonical", None) or request.path
        log.info(
            "owner request refused (401): %s %s presented=%s shape=%s transport_ok=%s",
            request.method,
            pattern,
            presented,
            shape,
            port._owner_auth_transport_ok(request),
        )
    except Exception as exc:  # a diagnostic must never change the answer
        log.debug("owner auth refusal note failed: %s", exc)
