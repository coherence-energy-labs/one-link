"""Sovereignty presets — three named tiers + the resolver layer.

May 15 2026.

One Link's promise is "no corps, no calls home, for the people." The
3-tier model below makes LAN/direct operation convenient while keeping
outside routes explicit. Community STUN can discover a public-facing
ICE address; it is not signaling and it cannot relay traffic. A device
on another network therefore still needs a configured signaling or
rendezvous route and, when direct NAT traversal fails, a configured
relay.

Presets:

  - just_works: the default for fresh installs. Update-check ON.
    STUN ON via INDEPENDENT community-run servers (Nextcloud,
    Sipgate, Antisip — never Google/Cloudflare/Twilio). LAN discovery
    ON. No corp accounts, no analytics, no cloud. LAN/direct routes
    work automatically. Cross-network operation requires a configured
    rendezvous/signaling route and, when needed, a configured relay;
    the stock build supplies neither public endpoint.

  - quiet: zero outbound to anything non-LAN. Update-check OFF.
    STUN OFF. LAN discovery ON. For users who pair on their LAN.

  - off_grid: the activist / high-threat profile. Adds: mDNS OFF
    (no broadcast peer discovery), manual pair only via paste-
    connection-string. Pure paranoia mode.

Each preset is defined as a set of feature ceilings that the respective
subsystems read at runtime. Individual settings can tighten the selected
preset — e.g. you can be on just_works but blank out the STUN list. A stale
setting or environment variable cannot loosen Quiet or Off-grid.

Read order:
  1. Preset prohibition — always wins
  2. Explicit setting (state.settings.<key>) — may further disable
  3. Env var override (where one is defined) — may further disable
  4. Preset permit/default — fallback

The audit endpoint surfaces which preset is active + which features
are overridden, so the user always knows what's happening.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Optional


# ── Independent community STUN servers ─────────────────────────────
#
# We deliberately exclude the Big-3 (Google/Cloudflare/Twilio). The
# servers below are operated by community / privacy-focused orgs:
#
#   - Nextcloud  : private-cloud open-source project. Their STUN is
#                  a free community service; no logging policy posted
#                  publicly but the org's stated values align.
#   - Sipgate    : German VoIP telco. GDPR-strict, EU-jurisdiction.
#                  Their STUN is part of their public infrastructure
#                  for SIP clients.
#   - Antisip    : independent SIP operator.
#
# Operators who want to swap these for their own STUN can override
# via env var ONE_LINK_STUN_SERVERS or the ``stun_servers`` setting.
COMMUNITY_STUN_SERVERS = (
    "stun:stun.nextcloud.com:443",
    "stun:stun.sipgate.net:3478",
    "stun:stun.antisip.com:3478",
)


@dataclass(frozen=True)
class SovereigntyPreset:
    """Frozen feature-flag bundle for one preset tier."""

    name: str
    label: str
    description: str
    # Subsystems read these.
    update_check_enabled: bool
    stun_servers: tuple[str, ...]
    mdns_discovery_enabled: bool
    rendezvous_enabled: bool
    # v0.21.x persistent UI sessions (local-only, never sent over
    # the internet). Each preset supplies a ceiling; users can turn a
    # permitted feature off in the Privacy panel but cannot loosen it.
    #   just_works → both ON  (best UX)
    #   quiet      → persist ON, labels OFF (cookie survives but
    #                no browser fingerprint stored)
    #   off_grid   → both OFF (no cookies, no session table at all)
    ui_session_persistence_enabled: bool
    ui_session_labels_enabled: bool
    # v0.21.x sovereignty audit gaps. Pre-2026-05-27 these were
    # either silently always-on or governed only by env vars,
    # which meant off_grid mode silently broadcast over mDNS,
    # used TURN relays, and inherited rendezvous URLs from any
    # LAN peer. Each preset now gates them honestly.
    #
    # turn_relay_enabled — when False, the daemon refuses to load
    #   any TURN servers (state setting + env var both ignored).
    #   off_grid+quiet OFF; just_works ON as a policy permit for a
    #   user/operator-configured relay. The preset supplies no TURN URL.
    # inherit_rendezvous_from_mdns_enabled — when False, the daemon
    #   ignores rendezvous URLs harvested from ambient LAN peers
    #   even if the inherit setting is on. Quiet + Off-grid OFF;
    #   Just Works ON as a policy permit.
    turn_relay_enabled: bool
    inherit_rendezvous_from_mdns_enabled: bool
    # UI hint — the chooser surfaces this as a one-line "what flows
    # outbound" summary so the user understands the trade.
    outbound_summary: str
    # What the mDNS announcement says about this device beyond the minimum.
    # The minimum is the short ID and the public key, which a peer needs to
    # authenticate the connection it is about to open. With details on, the
    # announcement also carries the chosen display name, the device kind
    # ("macos-laptop") and any rendezvous URLs: convenient at home, and a
    # description of the device to everyone else on a shared network.
    mdns_announce_details_enabled: bool = False


JUST_WORKS = SovereigntyPreset(
    name="just_works",
    label="Just Works",
    description=(
        "Best for most people. Devices on the same local network and "
        "other direct routes work automatically. Community STUN can "
        "discover a public-facing address, but STUN is not signaling "
        "and cannot relay traffic. Connecting across different networks "
        "requires a configured rendezvous or signaling route and, where "
        "direct traversal fails, a configured TURN or One Link relay. "
        "The stock build includes no public rendezvous or TURN endpoint. "
        "You'll see a note when a newer signed version is available. "
        "No accounts, no profile, no tracking."
    ),
    update_check_enabled=True,
    stun_servers=COMMUNITY_STUN_SERVERS,
    mdns_discovery_enabled=True,
    rendezvous_enabled=True,
    ui_session_persistence_enabled=True,
    ui_session_labels_enabled=True,
    turn_relay_enabled=True,
    inherit_rendezvous_from_mdns_enabled=True,
    mdns_announce_details_enabled=True,
    outbound_summary=(
        "Uses disclosed community STUN for address discovery (not "
        "signaling) and checks the public GitHub Releases API once every "
        "6 hours. Local-network sharing is on. Rendezvous and TURN are "
        "used only when an endpoint is configured."
    ),
)

QUIET = SovereigntyPreset(
    name="quiet",
    label="Quiet",
    description=(
        "Only talks to other devices on your local Wi-Fi. Connecting "
        "across different networks (for example, your phone at a "
        "coffee shop to your laptop at home) is unavailable while "
        "Quiet is active. Update notifications are off. Browser "
        "labels in the sessions list are stripped (you'll see uuids "
        "only). Pick this for the strictest privacy without going "
        "completely offline."
    ),
    update_check_enabled=False,
    stun_servers=(),
    mdns_discovery_enabled=True,
    # Quiet = LAN-only. Rendezvous is outside that boundary and remains
    # forbidden even when an older setting says enabled.
    rendezvous_enabled=False,
    ui_session_persistence_enabled=True,
    ui_session_labels_enabled=False,
    turn_relay_enabled=False,
    inherit_rendezvous_from_mdns_enabled=False,
    outbound_summary=(
        "Local Wi-Fi only. No other outside connections."
    ),
)

OFF_GRID = SovereigntyPreset(
    name="off_grid",
    label="Off-grid",
    description=(
        "Your device makes no announcements and no outside "
        "connections at all. Pairing is manual only (you copy a code "
        "from one device to the other, in person). No persistent "
        "sign-in cookies — every daemon restart sends you back to "
        "opening from the tray. For people who need maximum privacy."
    ),
    update_check_enabled=False,
    stun_servers=(),
    mdns_discovery_enabled=False,
    rendezvous_enabled=False,
    ui_session_persistence_enabled=False,
    ui_session_labels_enabled=False,
    turn_relay_enabled=False,
    inherit_rendezvous_from_mdns_enabled=False,
    outbound_summary="Nothing. No connections, no broadcast.",
)


ALL_PRESETS: dict[str, SovereigntyPreset] = {
    "just_works": JUST_WORKS,
    "quiet": QUIET,
    "off_grid": OFF_GRID,
}

# The default for a fresh install. Picked so that "install and use"
# matches normal-person expectations. Strict modes are an opt-in.
DEFAULT_PRESET_NAME = "just_works"

MAX_ICE_SERVER_LIST_CHARS = 8192
MAX_ICE_SERVER_URL_CHARS = 512
MAX_ICE_SERVERS = 16
_HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def get_preset(name: Optional[str]) -> SovereigntyPreset:
    """Resolve a preset name to its definition. Unknown names fall
    back to the default — the only thing that matters is that the
    daemon NEVER crashes on a malformed setting."""
    if not name:
        return ALL_PRESETS[DEFAULT_PRESET_NAME]
    return ALL_PRESETS.get(name.strip().lower(), ALL_PRESETS[DEFAULT_PRESET_NAME])


def resolve_update_check_enabled(
    *,
    state_setting: Optional[str],
    env_var: Optional[str],
    preset_name: Optional[str],
) -> bool:
    """Resolve update-check permission under the preset ceiling.

    A preset is a privacy ceiling, not merely a UI default.  Quiet and
    Off-grid therefore cannot be loosened by an older persisted toggle or an
    environment variable.  Within a preset that permits checks, an explicit
    setting/environment value may still turn them off.
    """
    if not get_preset(preset_name).update_check_enabled:
        return False
    # 1. Explicit setting wins. Strings "0"/"false"/"no"/"off" are
    #    explicit OFF; "1"/"true"/"yes"/"on" are explicit ON.
    s = (state_setting or "").strip().lower()
    if s in ("1", "true", "yes", "on"):
        return True
    if s in ("0", "false", "no", "off"):
        return False
    # 2. Env var.
    e = (env_var or "").strip().lower()
    if e in ("1", "true", "yes", "on"):
        return True
    if e in ("0", "false", "no", "off"):
        return False
    # 3. Preset default.
    return get_preset(preset_name).update_check_enabled


def resolve_stun_servers(
    *,
    state_setting: Optional[str],
    env_var: Optional[str],
    preset_name: Optional[str],
) -> tuple[str, ...]:
    """Resolve STUN servers under the active preset's privacy ceiling.

    Setting + env var are comma-separated lists of stun:host:port
    URLs. Explicit empty string means "user wants NO stun even on a
    preset that defaults to community STUN" — honored.

    Quiet and Off-grid permit no public STUN access, even when a stale setting
    or operator environment variable contains servers.  Just Works permits a
    validated override; an empty override remains an explicit opt-out.
    """
    preset = get_preset(preset_name)
    if not preset.stun_servers:
        return ()
    # state_setting=None means "no override". Empty string means
    # "explicit opt-out of even the preset default."
    if state_setting is not None:
        return parse_ice_server_list(state_setting, allowed_schemes={"stun", "stuns"})
    if env_var is not None:
        return parse_ice_server_list(env_var, allowed_schemes={"stun", "stuns"})
    return preset.stun_servers


def parse_ice_server_list(
    raw: str,
    *,
    allowed_schemes: set[str] | frozenset[str],
) -> tuple[str, ...]:
    """Return a bounded, canonical ICE URL list and drop invalid entries.

    Settings are local/operator inputs, so a typo must fail closed to an
    empty or reduced list rather than crash the call path or hand a browser
    an ambiguous URI. The parser deliberately accepts only RFC-style
    STUN/TURN authorities and TURN's single ``transport`` query.
    """
    if not isinstance(raw, str) or len(raw) > MAX_ICE_SERVER_LIST_CHARS:
        return ()
    normalized_schemes = frozenset(str(s).lower() for s in allowed_schemes)
    if not normalized_schemes or not normalized_schemes <= {
        "stun", "stuns", "turn", "turns",
    }:
        raise ValueError("unsupported ICE URL scheme policy")
    out: list[str] = []
    seen: set[str] = set()
    for candidate in raw.split(","):
        if len(out) >= MAX_ICE_SERVERS:
            break
        canonical = canonicalize_ice_server_url(
            candidate, allowed_schemes=normalized_schemes
        )
        if canonical is not None and canonical not in seen:
            seen.add(canonical)
            out.append(canonical)
    return tuple(out)


def canonicalize_ice_server_url(
    raw: str,
    *,
    allowed_schemes: frozenset[str],
) -> str | None:
    text = raw.strip() if isinstance(raw, str) else ""
    if not text or len(text) > MAX_ICE_SERVER_URL_CHARS:
        return None
    try:
        text.encode("ascii")
    except UnicodeEncodeError:
        return None
    if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in text):
        return None
    if ":" not in text:
        return None
    raw_scheme, remainder = text.split(":", 1)
    scheme = raw_scheme.lower()
    if scheme not in allowed_schemes:
        return None
    if not remainder or any(ch in remainder for ch in "/#@"):
        return None

    authority, separator, query = remainder.partition("?")
    if separator:
        if scheme not in {"turn", "turns"}:
            return None
        if query.lower() not in {"transport=udp", "transport=tcp"}:
            return None
        query = query.lower()
    elif "?" in authority:
        return None

    host: str
    port_text = ""
    port_specified = False
    bracketed = authority.startswith("[")
    if bracketed:
        closing = authority.find("]")
        if closing <= 1:
            return None
        host = authority[1:closing]
        suffix = authority[closing + 1:]
        if suffix:
            if not suffix.startswith(":") or ":" in suffix[1:]:
                return None
            port_specified = True
            port_text = suffix[1:]
        try:
            host = ipaddress.IPv6Address(host).compressed
        except ValueError:
            return None
        rendered_host = f"[{host}]"
    else:
        if authority.count(":") > 1:
            return None  # IPv6 literals must be bracketed.
        if ":" in authority:
            port_specified = True
            host, port_text = authority.rsplit(":", 1)
        else:
            host = authority
        host = host.rstrip(".").lower()
        if not _valid_ice_hostname(host):
            return None
        rendered_host = host

    rendered_port = ""
    if port_specified:
        if not port_text.isascii() or not port_text.isdecimal():
            return None
        port = int(port_text, 10)
        if not 0 < port <= 65535:
            return None
        rendered_port = f":{port}"
    canonical = f"{scheme}:{rendered_host}{rendered_port}"
    if separator:
        canonical += f"?{query}"
    return canonical


def _valid_ice_hostname(host: str) -> bool:
    if not host or len(host) > 253:
        return False
    try:
        ipaddress.IPv4Address(host)
        return True
    except ValueError:
        pass
    # Numeric dotted strings that are not canonical IPv4 addresses should
    # not be reinterpreted as DNS names (e.g. legacy octal-like spellings).
    if all(ch.isdigit() or ch == "." for ch in host):
        return False
    return all(_HOST_LABEL_RE.fullmatch(label) is not None for label in host.split("."))


def _resolve_bool_setting(
    *,
    state_setting: Optional[str],
    preset_value: bool,
) -> bool:
    """Resolve a boolean without allowing a preset prohibition to loosen.

    Explicit settings may make a permitted feature stricter.  They cannot
    re-enable a feature that the selected sovereignty preset forbids.
    """
    if not preset_value:
        return False
    s = (state_setting or "").strip().lower()
    if s in ("1", "true", "yes", "on"):
        return True
    if s in ("0", "false", "no", "off"):
        return False
    return preset_value


def resolve_ui_session_persistence_enabled(
    *,
    state_setting: Optional[str],
    preset_name: Optional[str],
) -> bool:
    """Should we mint persistent ol_session cookies?

    An explicit setting may disable them. Off-grid's prohibition cannot be
    overridden; Just Works and Quiet permit persistence.
    """
    return _resolve_bool_setting(
        state_setting=state_setting,
        preset_value=get_preset(preset_name).ui_session_persistence_enabled,
    )


def resolve_ui_session_labels_enabled(
    *,
    state_setting: Optional[str],
    preset_name: Optional[str],
) -> bool:
    """Should we store browser User-Agent labels on session rows?
    quiet + off_grid default OFF (no fingerprint); just_works defaults ON.
    An explicit setting may only make the selected preset stricter."""
    return _resolve_bool_setting(
        state_setting=state_setting,
        preset_value=get_preset(preset_name).ui_session_labels_enabled,
    )


def resolve_mdns_discovery_enabled(
    *,
    state_setting: Optional[str],
    preset_name: Optional[str],
) -> bool:
    """Should the daemon broadcast on mDNS (zeroconf) so other
    devices on the LAN can find it? off_grid OFF (the whole point);
    just_works + quiet ON. An explicit setting may turn it off, never loosen
    Off-grid."""
    return _resolve_bool_setting(
        state_setting=state_setting,
        preset_value=get_preset(preset_name).mdns_discovery_enabled,
    )


def resolve_rendezvous_enabled(
    *,
    state_setting: Optional[str],
    preset_name: Optional[str],
) -> bool:
    """Return the policy gate for rendezvous client startup.

    ``True`` only permits configured URLs; it does not configure a service or
    prove one is reachable. When False, the daemon will not contact preserved
    URLs. Just Works permits configured routes, while Quiet and Off-grid deny
    them as a hard ceiling.
    """
    return _resolve_bool_setting(
        state_setting=state_setting,
        preset_value=get_preset(preset_name).rendezvous_enabled,
    )


def resolve_turn_relay_enabled(
    *,
    state_setting: Optional[str],
    preset_name: Optional[str],
) -> bool:
    """Return the policy gate for operator/user-configured TURN relays.

    Just Works permits configured relays; it does not supply a TURN endpoint
    or establish reachability. Quiet and Off-grid deny relay traffic as a hard
    ceiling. An explicit setting may disable a permitted relay.
    """
    return _resolve_bool_setting(
        state_setting=state_setting,
        preset_value=get_preset(preset_name).turn_relay_enabled,
    )


def resolve_inherit_rendezvous_from_mdns_enabled(
    *,
    state_setting: Optional[str],
    preset_name: Optional[str],
) -> bool:
    """May an explicitly enabled bootstrap adopt mDNS rendezvous URLs?

    This policy permit is not auto-configuration: the separate
    ``inherit_rendezvous_from_mdns`` setting must also be enabled. Because
    ambient mDNS is unauthenticated, Quiet and Off-grid deny it as a hard
    ceiling.
    """
    return _resolve_bool_setting(
        state_setting=state_setting,
        preset_value=get_preset(
            preset_name,
        ).inherit_rendezvous_from_mdns_enabled,
    )


def resolve_mdns_announce_details_enabled(
    *,
    state_setting: Optional[str],
    preset_name: Optional[str],
) -> bool:
    """May the mDNS announcement describe this device?

    When ``False`` the announcement carries only the short ID and public key:
    no display name, no device kind, no rendezvous URLs. Just Works allows
    the details; Quiet and Off-grid do not, as a hard ceiling. An explicit
    ``mdns_announce_details`` setting may turn them off under Just Works.
    """
    return _resolve_bool_setting(
        state_setting=state_setting,
        preset_value=get_preset(preset_name).mdns_announce_details_enabled,
    )


def mdns_announce_details_for(state) -> bool:
    """:func:`resolve_mdns_announce_details_enabled` for a state store."""
    setting = None
    if state is not None:
        try:
            setting = state.get_setting("mdns_announce_details")
        except Exception:
            setting = None
    return resolve_mdns_announce_details_enabled(
        state_setting=setting, preset_name=current_preset_name(state)
    )


def current_preset_name(state) -> str:
    """Reads the current preset name from state. Returns the
    default if unset."""
    if state is None:
        return DEFAULT_PRESET_NAME
    try:
        v = (state.get_setting("sovereignty_preset") or "").strip().lower()
    except Exception:
        return DEFAULT_PRESET_NAME
    if v not in ALL_PRESETS:
        return DEFAULT_PRESET_NAME
    return v
