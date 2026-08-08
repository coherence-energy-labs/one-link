"""Native URL protocol handoff helpers for One Link."""

from __future__ import annotations

import re
from urllib.parse import parse_qs, urlencode, urlparse


_INVITE_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{16,8192}$")


def _validate_invite_token(token: str) -> str:
    token = str(token or "").strip()
    if not token:
        raise ValueError("self-mesh enroll link missing token")
    if not _INVITE_TOKEN_RE.fullmatch(token):
        raise ValueError("self-mesh enroll token is malformed")
    return token


def _validate_group_invite_token(token: str) -> str:
    """Shape only, at the door. A malformed token should never reach a decoder, and a URL is the
    least trustworthy input the app has -- it arrives from another person's message."""
    token = str(token or "").strip().strip("/")
    if not token:
        raise ValueError("group invite link missing token")
    if not _INVITE_TOKEN_RE.fullmatch(token):
        raise ValueError("group invite token is malformed")
    return token


def peer_path_for_deep_link(raw_url: str) -> str:
    """Map a supported `one-link://...` URL to a local UI path."""
    parsed = urlparse(str(raw_url or "").strip())
    if parsed.scheme != "one-link":
        raise ValueError("unsupported URL scheme")
    route = f"{parsed.netloc}{parsed.path}".strip("/")
    params = parse_qs(parsed.query, keep_blank_values=False)
    if route == "self-mesh/enroll":
        token = _validate_invite_token((params.get("token") or [""])[0])
        return "/peer?" + urlencode({"self_mesh_invite": token})
    # GROUP INVITES. The app has minted `one-link://group-invite/<token>` for a long time while
    # this function rejected it, so every invite anyone shared led to "unsupported one-link route".
    # The token is carried in the PATH here, not a query parameter, because that is the shape the
    # mint emits.
    #
    # Only the shape is checked here. Whether the invite is genuine, unexpired, and from who it
    # claims is `group_invite.verify_group_invite`, and the UI must not act on it before that
    # answers -- a link that opens a screen is not a link that grants membership.
    if route.startswith("group-invite/"):
        token = _validate_group_invite_token(route[len("group-invite/"):])
        return "/peer?" + urlencode({"group_invite": token})
    raise ValueError(f"unsupported one-link route: {route or '<empty>'}")


def local_ui_url_for_deep_link(raw_url: str, *, port: int, token: str) -> str:
    path = peer_path_for_deep_link(raw_url)
    sep = "&" if "?" in path else "?"
    return f"http://127.0.0.1:{int(port)}{path}{sep}t={token}"


__all__ = [
    "local_ui_url_for_deep_link",
    "peer_path_for_deep_link",
]
