"""One Link Rendezvous Server — production aiohttp app.

Runs as a small standalone service that holds, in memory, signed
presence beacons from One Link daemons. Devices on different networks
look each other up here so they can attempt direct connection
(NAT hole-punch in v0.5.1, encrypted relay fallback in v0.5.2).

Deploy as a single Python process behind nginx / Cloudflare / similar
TLS-terminating reverse proxy. The protocol payloads are signed; the
HTTP transport need only be reasonably honest about delivery.

Run with:

    python -m one_link.rendezvous_server --host 0.0.0.0 --port 7118

Or via the convenience entrypoint script in `scripts/rendezvous.py`.

Threats this hardens against:

  - **Spoofed registration**: every register/revoke is Ed25519-signed
    by the device's own key. A third party can replay an unmodified
    register, but only inside the 60s replay window, and the registry
    overwrites idempotently.
  - **Resource exhaustion**: per-IP rate limit + per-pubkey rate limit
    + hard cap on total registrations + bounded TTL.
  - **Censoring lookups**: the protocol is symmetric; anyone can run
    their own. There is no authoritative rendezvous.
  - **Plaintext exposure**: this server never receives chat/file plaintext or
    end-to-end keys. It records presence metadata and, when relay is enabled,
    forwards opaque ciphertext while observing its size and timing.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import hashlib
import heapq
import hmac
import ipaddress
import json
import logging
import math
import os
import secrets
import signal
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Awaitable, Callable, Literal, Optional, cast

import aiohttp
from aiohttp import web

from one_link.relay_proto import (
    CONTROL_FRAME_MAX_BYTES,
    DATA_FRAME_MAX_BYTES,
    FRAME_CLOSE,
    FRAME_DATA,
    SESSION_ID_BYTES,
    bounded_json_loads,
)
from one_link.rendezvous_proto import (
    MAX_REQUEST_BYTES,
    LookupAck,
    RegisterAck,
    RegisterReq,
    RevokeReq,
    Endpoint,
    now_ms,
    timestamp_within_replay_window,
)

log = logging.getLogger("one_link.rendezvous_server")

# Every map keyed on attacker-controlled IPs/pubkeys/nonces shares this
# operator-visible default. A hostile-state RSS probe with 50k registrations,
# 150k aliases, six 50k rate maps, 50k nonces, and 50k replay keys increased RSS
# by 433,811,456 bytes. Twenty thousand keys plus a 128 MiB relay budget leaves
# a defensible margin inside the shipped 512 MiB container rather than claiming
# that Python object state costs only ~100 bytes per key.
_DEFAULT_MAX_REGISTRATIONS = 20_000
_DEFAULT_MAX_ATTACKER_STATE_KEYS = 20_000
_DEFAULT_MAX_CONCURRENT_CONNECTIONS = 64
# One source address (an IPv4 address or an IPv6 /64) may hold at most this
# many of those slots, so a single host cannot occupy the whole server.
_DEFAULT_MAX_CONCURRENT_PER_SOURCE = 16
_DEFAULT_PROCESS_MEMORY_BUDGET_BYTES = 512 * 1024 * 1024
_DEFAULT_RELAY_ROUTE_KEYS = 4_096
_MEASURED_HOSTILE_STATE_KEYS = 50_000
_MEASURED_HOSTILE_STATE_RSS_BYTES = 433_811_456
_MEASURED_REGISTRY_SLOTS_PER_KEY = 4  # registration + three epoch aliases
_MEASURED_AUXILIARY_MAPS = 8  # six limiters + relay nonce + replay cache
# Each blinded route occupies the global routing map plus a listener-owned set,
# auth-public map, and expiry map. Account all four Python container entries.
_RELAY_ROUTE_STATE_SLOTS_PER_KEY = 4
_MEASURED_STATE_SAFETY_NUMERATOR = 5
_MEASURED_STATE_SAFETY_DENOMINATOR = 4
_PROCESS_BASE_RESERVE_BYTES = 64 * 1024 * 1024
# aiohttp materializes a complete WebSocket message before application code can
# acquire a relay-budget lease. Reserve one maximum wire frame plus parser/task
# overhead for every admitted handler so concurrent first-frame allocations are
# represented even when the process-wide relay budget is already exhausted.
_CONCURRENT_HANDLER_RESERVE_BYTES = DATA_FRAME_MAX_BYTES + 1 + SESSION_ID_BYTES + 128 * 1024
_MAX_RATE_PER_MINUTE = 1_000_000
_BEARER_TOKEN_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~+/"
)
#  - H25: chunk sweeps so a single eviction tick doesn't stall the
#    event loop. After every batch of this many keys we yield with
#    asyncio.sleep(0).
_SWEEP_CHUNK = 2_000
#  - M32: per-request body-read deadline. Without this aiohttp's
#    request.read() will happily wait forever for a slowloris client.
_REQUEST_READ_TIMEOUT_S = 10.0

# Native relay clients do not send an Origin header. Browsers always do during
# a WebSocket handshake, so rejecting Origin-bearing relay upgrades prevents a
# hostile web page from consuming listener/session quotas on a visitor's IP.
# Dedicated clients can forge or omit Origin; this is a drive-by abuse boundary,
# not a replacement for the signed listener protocol and rate limits.
_RELAY_WEBSOCKET_HEARTBEAT_S = 30.0
_RELAY_AUTH_TIMEOUT_S = 10.0

# Keep both lookup versions on the same bounded response contract. The v2
# blinded-token route must not become a larger amplification surface than v1.
_LOOKUP_MAX_ADVERTISED_ENDPOINTS = 3
_LOOKUP_MAX_CAPABILITIES = 16

# A rendezvous process normally owns one ``RendezvousApp``.  This ceiling is
# therefore shared by every authenticated relay listener and every session in
# the process, rather than being multiplied by the number of listeners.  The
# separate control reserve guarantees that overload teardown can still make
# progress after DATA has consumed its entire admissible share.
_RELAY_FORWARD_GLOBAL_BUDGET_BYTES = 128 * 1024 * 1024
_RELAY_FORWARD_CONTROL_RESERVE_BYTES = 4 * 1024 * 1024
_RELAY_DATA_FRAME_WIRE_MAX_BYTES = DATA_FRAME_MAX_BYTES + 1 + SESSION_ID_BYTES


# ─── config ─────────────────────────────────────────────────────────


@dataclass
class ServerConfig:
    host: str = "0.0.0.0"  # nosec B104
    port: int = 7118
    # Hard cap on total registrations the server will hold. This bounds the
    # registry itself; concurrent rate/replay maps add material overhead and
    # operators must size this together with the container memory limit.
    max_registrations: int = _DEFAULT_MAX_REGISTRATIONS
    # Shared ceiling for each attacker-keyed rate, nonce, and replay map. Keep
    # this at or below max_registrations unless the memory envelope is measured
    # again under the exact intended configuration.
    max_attacker_state_keys: int = _DEFAULT_MAX_ATTACKER_STATE_KEYS
    # Per-IP token-bucket rate. The bucket holds one minute of burst capacity
    # and refills continuously without retaining one timestamp per request.
    rate_per_ip_per_min: int = 120
    # Per-pubkey rate limit on register specifically. A single device
    # legitimately re-registers every TTL/2 (so for ttl=300, every 150s
    # = 0.4/min). 30/min absorbs reasonable churn.
    rate_register_per_pubkey_per_min: int = 30
    # How often to scan for expired entries. Sub-second granularity not
    # needed; the scan is O(N) where N = registrations.
    eviction_interval_s: float = 5.0
    # Maximum trust we place in client-supplied advertised endpoints.
    # Above this count we reject the registration outright (the proto
    # already enforces a smaller cap; this is double-defense).
    max_advertised_endpoints: int = 8
    # v0.5.5: encrypted relay support. Off by default — operators have
    # to explicitly enable, since the relay forwards bytes (still
    # opaque to us) and so consumes more bandwidth than register/lookup.
    enable_relay: bool = False
    # Per-listener concurrent session cap. The relay multiplexes
    # multiple connector→listener sessions over one listener
    # WebSocket. This cap prevents a malicious listener (or runaway
    # client) from exhausting server memory.
    relay_max_sessions_per_listener: int = 32
    # Global cap on rotating blinded route tags. This is separate from the
    # listener count because one paired device registers multiple epoch tags.
    relay_max_route_keys: int = _DEFAULT_RELAY_ROUTE_KEYS
    # Per-IP rate limit on connect attempts. Independent from the
    # main rate_per_ip_per_min so relay-heavy operators can tune
    # separately.
    relay_connect_per_ip_per_min: int = 60
    # Idle timeout for an established session. Both sides quiet for
    # this long → relay closes. Senders re-establish for the next msg.
    relay_session_idle_s: float = 300.0  # 5 min
    # Every relay forward has a finite deadline.  A WebSocket whose TCP
    # peer stopped reading must not pin the opposite request handler forever.
    relay_forward_timeout_s: float = 30.0
    # Listener→connector traffic is demultiplexed into one ordered queue per
    # session. The listener receive loop never awaits a connector socket.
    # Four maximum DATA frames give normal WAN paths enough flight while
    # strictly capping a non-reading connector at ~4 MiB.
    relay_forward_queue_limit_bytes: int = 4 * (1024 * 1024 + 9)
    relay_forward_queue_max_items: int = 64
    # One process-wide payload-memory ceiling across all server-side relay
    # listeners and sessions.  It accounts received frames retained by a
    # handler, queued/in-flight forwarding frames, signalling controls, and
    # teardown controls.  DATA cannot consume the reserved control tail.
    relay_forward_global_budget_bytes: int = _RELAY_FORWARD_GLOBAL_BUDGET_BYTES
    relay_forward_control_reserve_bytes: int = _RELAY_FORWARD_CONTROL_RESERVE_BYTES
    # Trust reverse-proxy client IP headers. Disabled by default
    # because a directly exposed server would otherwise let clients
    # spoof X-Forwarded-For and bypass per-IP rate limits.
    trust_proxy_headers: bool = False
    # v0.20.7 (security audit H24): /lookup is unauthenticated and the
    # response is meaningfully larger than the request (15-30x). Lower
    # the lookup-specific cap so a botnet can't use the rendezvous as
    # a reflector. Independent from rate_per_ip_per_min so register
    # / revoke aren't dragged down with it.
    rate_lookup_per_ip_per_min: int = 30
    # v0.20.7 (security audit H26): per-IP NEW-pubkey registration
    # limit, separate from per-pubkey. Defeats fresh-pubkey churn
    # against the registry by forcing a per-source ceiling on how
    # often a single IP can mint a brand-new device beacon.
    rate_new_pubkey_register_per_ip_per_min: int = 10
    # v0.20.7 (security audit M31): per-pubkey listener-slot
    # replacement rate. Without this, a leaked listener key + repeated
    # ping-pong reconnect = perma-kick the legitimate owner.
    rate_listener_replace_per_pubkey_per_min: int = 2
    # v0.20.7 (security audit M33): global cap on concurrent in-flight
    # connections. Defends against fd / asyncio-task exhaustion under
    # fan-out attack from many source IPs. This must remain finite so the
    # declared process memory envelope has a meaningful upper bound.
    max_concurrent_connections: int = _DEFAULT_MAX_CONCURRENT_CONNECTIONS
    # Share of those slots one source address may hold at a time. Without it
    # the global cap is a denial-of-service lever: whoever opens the most
    # WebSockets owns the server. Behind a reverse proxy this needs
    # trust_proxy_headers, or every client shares the proxy's address.
    max_concurrent_per_source: int = _DEFAULT_MAX_CONCURRENT_PER_SOURCE
    # Fail closed when operator-provided state/concurrency/relay ceilings no
    # longer fit the declared process/container memory envelope. The estimator
    # deliberately scales from a hostile distinct-key RSS measurement and adds
    # independent baseline and per-handler reserves.
    memory_budget_bytes: int = _DEFAULT_PROCESS_MEMORY_BUDGET_BYTES
    # v0.20.7 (security audit M36): when set, /metrics requires a
    # Bearer token. Unauthenticated loopback access exists only when the server
    # itself is bound exclusively to loopback and proxy trust is off. A wildcard
    # listener or trusted-proxy topology requires the token even if its immediate
    # socket peer is localhost, preventing nginx from becoming an auth bypass.
    metrics_token: Optional[str] = None


# ─── in-memory store ────────────────────────────────────────────────


@dataclass
class Registration:
    pubkey: bytes
    observed_endpoint: Endpoint
    advertised_endpoints: list[Endpoint]
    nat_type: str
    capabilities: list[str]
    registered_at_ms: int
    expires_at_ms: int


class Registry:
    """Pubkey -> Registration. Bounded; evicts on insert when full.

    v0.20.7 (Bundle 51): also maintains a *blinded-token alias map*
    so the rendezvous can answer /api/v2/lookup_token queries
    without ever seeing a raw pubkey on the lookup wire. The alias
    is derived from (pubkey, current epoch) via HKDF and rotates
    per epoch — an attacker logging tokens gets nothing usable
    once the rotation window passes."""

    def __init__(self, max_entries: int):
        if type(max_entries) is not int or max_entries <= 0:
            raise ValueError("max_entries must be a positive integer")
        self.max_entries = max_entries
        self._entries: dict[bytes, Registration] = {}
        # Expiry heap makes full-capacity admission O(log N), rather than an
        # attacker-triggerable O(N) scan for every fresh pubkey. Updates leave
        # stale heap records identified by per-pubkey generations; periodic
        # compaction keeps those records bounded.
        self._expiry_heap: list[tuple[int, int, bytes]] = []
        self._expiry_generation: dict[bytes, int] = {}
        # Bundle 43/51: token (32 bytes) → pubkey (32 bytes). Each entry keeps
        # only its current previous/current/next epoch aliases so a boundary
        # query succeeds without retaining historical discovery tokens.
        self._token_index: dict[bytes, bytes] = {}
        # Reverse map: pubkey → currently indexed tokens, so refresh/removal
        # cleans the alias map without scanning every registration.
        self._tokens_for_pubkey: dict[bytes, set[bytes]] = {}
        self.evictions = 0

    def __len__(self) -> int:
        return len(self._entries)

    def get(self, pubkey: bytes) -> Optional[Registration]:
        return self._entries.get(pubkey)

    def get_by_token(self, token: bytes) -> Optional[Registration]:
        """v0.20.7 (Bundle 51): blinded-token lookup. Returns the
        Registration whose pubkey was previously aliased to this
        token, or None if no such alias exists / the alias is
        stale."""
        pub = self._token_index.get(token)
        if pub is None:
            return None
        return self._entries.get(pub)

    def upsert(self, reg: Registration) -> None:
        # If we'd exceed capacity, evict the oldest-expiring entry.
        if reg.pubkey not in self._entries and len(self._entries) >= self.max_entries:
            victim = self._pop_earliest_current()
            if victim is None:
                # Defensive repair for impossible internal drift: rebuilding
                # from authoritative entries is safer than admitting past cap.
                self._rebuild_expiry_heap()
                victim = self._pop_earliest_current()
            if victim is None:
                raise RuntimeError("registry expiry index is inconsistent")
            self._remove_entry(victim)
            self.evictions += 1
        # Replace the prior epoch aliases before publishing the refreshed
        # registration. Otherwise a device that remains online indefinitely
        # accumulates three aliases per epoch and every historical blinded
        # token remains valid until the registration finally disappears.
        self._cleanup_token_aliases(reg.pubkey)
        self._entries[reg.pubkey] = reg
        generation = self._expiry_generation.get(reg.pubkey, 0) + 1
        self._expiry_generation[reg.pubkey] = generation
        heapq.heappush(self._expiry_heap, (reg.expires_at_ms, generation, reg.pubkey))
        self._compact_expiry_heap_if_needed()
        # v0.20.7 (Bundle 51): compute blinded tokens for the
        # current + previous + next epochs so a query at any time
        # within the rotation window finds the entry. 1-hour
        # default epoch (rdz_blind.DEFAULT_EPOCH_SECONDS); 3 epochs
        # = 3 hours of token coverage. New aliases on each upsert
        # so rotated tokens supersede old ones in the index.
        from one_link import rdz_blind as _rb

        current = _rb.current_epoch_id()
        for delta in (-1, 0, 1):
            token = _rb.derive_blinded_token(
                peer_pub=reg.pubkey,
                epoch_id=max(0, current + delta),
            )
            self._token_index[token] = reg.pubkey
            self._tokens_for_pubkey.setdefault(reg.pubkey, set()).add(token)

    def remove(self, pubkey: bytes) -> bool:
        return self._remove_entry(pubkey)

    def _remove_entry(self, pubkey: bytes) -> bool:
        present = self._entries.pop(pubkey, None) is not None
        if not present:
            return False
        self._expiry_generation.pop(pubkey, None)
        self._cleanup_token_aliases(pubkey)
        if not self._entries:
            self._expiry_heap.clear()
        return True

    def _pop_earliest_current(self) -> bytes | None:
        while self._expiry_heap:
            expires_at_ms, generation, pubkey = heapq.heappop(self._expiry_heap)
            current = self._entries.get(pubkey)
            if (
                current is not None
                and current.expires_at_ms == expires_at_ms
                and self._expiry_generation.get(pubkey) == generation
            ):
                return pubkey
        return None

    def _rebuild_expiry_heap(self) -> None:
        self._expiry_heap = [
            (registration.expires_at_ms, self._expiry_generation[pubkey], pubkey)
            for pubkey, registration in self._entries.items()
        ]
        heapq.heapify(self._expiry_heap)

    def _compact_expiry_heap_if_needed(self) -> None:
        if len(self._expiry_heap) > max(64, 4 * len(self._entries)):
            self._rebuild_expiry_heap()

    def _cleanup_token_aliases(self, pubkey: bytes) -> None:
        tokens = self._tokens_for_pubkey.pop(pubkey, set())
        for t in tokens:
            # A cryptographic collision is fantastically unlikely, but this
            # ownership check also makes mocked/fault-injected collisions
            # deterministic: cleaning one pubkey must never delete another
            # pubkey's current alias.
            if self._token_index.get(t) == pubkey:
                self._token_index.pop(t, None)

    def evict_expired(self, now_ms_value: int) -> int:
        evicted = 0
        while self._expiry_heap and self._expiry_heap[0][0] <= now_ms_value:
            expires_at_ms, generation, pubkey = heapq.heappop(self._expiry_heap)
            current = self._entries.get(pubkey)
            if (
                current is None
                or current.expires_at_ms != expires_at_ms
                or self._expiry_generation.get(pubkey) != generation
            ):
                continue
            self._remove_entry(pubkey)
            evicted += 1
        self._compact_expiry_heap_if_needed()
        return evicted


# ─── token-bucket rate limiter ──────────────────────────────────────


class _RateLimiter:
    """Fixed-state token bucket with a hard ceiling on attacker keys.

    Keeping one timestamp for every accepted request makes the nominal key cap
    misleading: an attacker can fill every key to its per-minute allowance.
    Each bucket instead retains only ``(available_tokens, last_activity)``.
    """

    def __init__(
        self,
        rate_per_min: int,
        window_s: float = 60.0,
        max_keys: int = _DEFAULT_MAX_ATTACKER_STATE_KEYS,
    ):
        self.rate = int(rate_per_min)
        self.window_s = float(window_s)
        self.max_keys = int(max_keys)
        self._hits: dict[str, tuple[float, float]] = {}

    def admit(self, key: str) -> bool:
        now = time.monotonic()
        state = self._hits.get(key)
        if state is None:
            # Fail closed for an unknown identity while the map is full.
            # Evicting a live bucket here would let a distinct-key flood reset
            # the quota of whichever client happened to be oldest. The
            # periodic inactivity sweep reopens capacity after one window.
            if len(self._hits) >= self.max_keys:
                return False
            available = float(self.rate)
        else:
            previous_available, previous_at = state
            elapsed = max(0.0, now - previous_at)
            available = min(
                float(self.rate),
                previous_available + elapsed * (self.rate / self.window_s),
            )
        if available < 1.0:
            self._hits[key] = (available, now)
            return False
        self._hits[key] = (available - 1.0, now)
        return True

    async def sweep(self) -> int:
        """Drop keys with no live tokens. Returns dropped count.

        v0.20.7 (H25): chunked + async-yielding so a sweep over a
        large dict doesn't stall the event loop. Walks at most
        _SWEEP_CHUNK keys before yielding."""
        cutoff = time.monotonic() - self.window_s
        dead: list[str] = []
        seen = 0
        # Snapshot keys so iteration is stable while we mutate.
        for k in list(self._hits.keys()):
            state = self._hits.get(k)
            if state is None:
                continue
            if state[1] < cutoff:
                dead.append(k)
            seen += 1
            if seen % _SWEEP_CHUNK == 0:
                await asyncio.sleep(0)
        for k in dead:
            self._hits.pop(k, None)
        return len(dead)


# ─── metrics ────────────────────────────────────────────────────────


@dataclass
class Metrics:
    started_at_ms: int = field(default_factory=now_ms)
    registers_total: int = 0
    register_rejects_total: int = 0
    lookups_total: int = 0
    lookup_misses_total: int = 0
    revokes_total: int = 0
    rate_limit_rejects_total: int = 0
    # v0.5.5
    relay_listeners_total: int = 0
    relay_listener_rejects_total: int = 0
    relay_sessions_total: int = 0
    relay_session_rejects_total: int = 0
    relay_bytes_forwarded: int = 0
    relay_forward_failures_total: int = 0
    relay_forward_overloads_total: int = 0
    relay_forward_global_overloads_total: int = 0
    relay_forward_global_control_overloads_total: int = 0
    relay_idle_expirations_total: int = 0


# ─── relay session state ───────────────────────────────────────────


class _RelayForwardError(ConnectionError):
    """Sticky terminal error from one server-side forwarding queue."""


class _RelayGlobalBudgetOverload(BufferError):
    """The process-wide relay forwarding budget refused one payload."""


def _relay_frame_metadata(buf: bytes) -> tuple[int, bytes, int]:
    """Validate a relay frame without copying its potentially 1 MiB payload."""

    header_bytes = 1 + SESSION_ID_BYTES
    if not isinstance(buf, bytes):
        raise ValueError("frame must be immutable bytes")
    if len(buf) < header_bytes:
        raise ValueError(f"frame too short: {len(buf)}")
    frame_type = buf[0]
    if frame_type not in (FRAME_DATA, FRAME_CLOSE):
        raise ValueError(f"unknown frame type: {frame_type:#04x}")
    payload_bytes = len(buf) - header_bytes
    if frame_type == FRAME_CLOSE and payload_bytes:
        raise ValueError("close frame must not carry payload")
    if frame_type == FRAME_DATA and payload_bytes > DATA_FRAME_MAX_BYTES:
        raise ValueError(f"data frame payload too large: {payload_bytes} > {DATA_FRAME_MAX_BYTES}")
    return frame_type, bytes(memoryview(buf)[1:header_bytes]), payload_bytes


_RelayBudgetCategory = Literal["current", "queued", "control", "teardown"]
_RELAY_DATA_BUDGET_CATEGORIES = frozenset({"current", "queued"})


@dataclass(frozen=True)
class _RelayBudgetRecord:
    owner: object
    size: int
    category: _RelayBudgetCategory


class _RelayForwardBudget:
    """Exact app-owned relay-payload accounting for one server process.

    The event loop is single-threaded, so acquisition/release is synchronous
    and atomic with respect to every relay handler.  Each successful
    acquisition creates one explicit lease.  The lease follows the payload as
    ownership moves from a receive handler to a queue and then to its sender;
    cancellation and teardown release that same lease exactly once.

    This is deliberately fail-fast for DATA.  Waiting for global capacity in
    a multiplexed listener receive loop would let one stalled session
    head-of-line block unrelated sessions on that listener.  The responsible
    session is instead closed and every other listener/session keeps running.
    """

    def __init__(self, limit_bytes: int, control_reserve_bytes: int) -> None:
        if type(limit_bytes) is not int or type(control_reserve_bytes) is not int:
            raise ValueError("relay forwarding budget limits must be integers")
        self._limit_bytes = limit_bytes
        self._control_reserve_bytes = control_reserve_bytes
        if self._limit_bytes <= 0:
            raise ValueError("relay forwarding global budget must be positive")
        if not 0 < self._control_reserve_bytes < self._limit_bytes:
            raise ValueError(
                "relay forwarding control reserve must be positive and smaller "
                "than the global budget"
            )
        self._next_token = 1
        self._records: dict[int, _RelayBudgetRecord] = {}
        self._used_bytes = 0
        self._peak_bytes = 0
        self._used_by_category: dict[_RelayBudgetCategory, int] = {
            "current": 0,
            "queued": 0,
            "control": 0,
            "teardown": 0,
        }
        self._peak_by_category: dict[_RelayBudgetCategory, int] = {
            "current": 0,
            "queued": 0,
            "control": 0,
            "teardown": 0,
        }
        self._used_by_owner: dict[object, int] = {}
        self._data_denials_total = 0
        self._control_denials_total = 0

    def try_acquire(
        self,
        size: int,
        *,
        owner: object,
        category: _RelayBudgetCategory,
    ) -> _RelayBudgetLease | None:
        if type(size) is not int or size <= 0:
            raise ValueError("relay forwarding reservation size must be positive")
        if category not in self._used_by_category:
            raise ValueError(f"unknown relay forwarding budget category: {category!r}")
        try:
            hash(owner)
        except TypeError as exc:
            raise ValueError("relay forwarding budget owner must be hashable") from exc
        is_data = category in _RELAY_DATA_BUDGET_CATEGORIES
        ceiling = self.data_limit_bytes if is_data else self._limit_bytes
        if size > ceiling or self._used_bytes > ceiling - size:
            if is_data:
                self._data_denials_total += 1
            else:
                self._control_denials_total += 1
            return None

        token = self._next_token
        self._next_token += 1
        self._records[token] = _RelayBudgetRecord(
            owner=owner,
            size=size,
            category=category,
        )
        self._used_bytes += size
        self._peak_bytes = max(self._peak_bytes, self._used_bytes)
        self._used_by_category[category] += size
        self._peak_by_category[category] = max(
            self._peak_by_category[category],
            self._used_by_category[category],
        )
        self._used_by_owner[owner] = self._used_by_owner.get(owner, 0) + size
        self._assert_invariants()
        return _RelayBudgetLease(self, token)

    def _release(self, token: int) -> None:
        record = self._records.get(token)
        if record is None:
            raise RuntimeError(f"unknown relay forwarding budget lease: {token}")
        category_bytes = self._used_by_category[record.category]
        prior_owner_bytes = self._used_by_owner.get(record.owner, 0)
        if category_bytes < record.size:
            raise RuntimeError("relay forwarding category accounting underflow")
        if prior_owner_bytes < record.size:
            raise RuntimeError("relay forwarding owner accounting underflow")
        owner_bytes = prior_owner_bytes - record.size
        self._records.pop(token)
        self._used_bytes -= record.size
        self._used_by_category[record.category] = category_bytes - record.size
        if owner_bytes:
            self._used_by_owner[record.owner] = owner_bytes
        else:
            self._used_by_owner.pop(record.owner, None)
        self._assert_invariants()

    def _reclassify(self, token: int, category: _RelayBudgetCategory) -> None:
        if category not in self._used_by_category:
            raise ValueError(f"unknown relay forwarding budget category: {category!r}")
        record = self._records.get(token)
        if record is None:
            raise RuntimeError(f"unknown relay forwarding budget lease: {token}")
        if record.category == category:
            return
        if (record.category in _RELAY_DATA_BUDGET_CATEGORIES) != (
            category in _RELAY_DATA_BUDGET_CATEGORIES
        ):
            raise RuntimeError("relay payload lease cannot cross data/control classes")
        replacement = _RelayBudgetRecord(
            owner=record.owner,
            size=record.size,
            category=category,
        )
        self._used_by_category[record.category] -= record.size
        self._used_by_category[category] += record.size
        self._peak_by_category[category] = max(
            self._peak_by_category[category],
            self._used_by_category[category],
        )
        self._records[token] = replacement
        self._assert_invariants()

    def _record_for(self, token: int) -> _RelayBudgetRecord:
        record = self._records.get(token)
        if record is None:
            raise RuntimeError(f"unknown relay forwarding budget lease: {token}")
        return record

    def _assert_invariants(self, *, full: bool = False) -> None:
        if self._used_bytes < 0 or self._used_bytes > self._limit_bytes:
            raise RuntimeError("relay forwarding global accounting escaped its bounds")
        if any(value < 0 for value in self._used_by_category.values()):
            raise RuntimeError("relay forwarding category accounting underflow")
        if self._used_bytes != sum(self._used_by_category.values()):
            raise RuntimeError("relay forwarding category accounting mismatch")
        # Full scans are intentionally reserved for status/audit reads.  The
        # acquisition hot path must stay O(1) even with tens of thousands of
        # simultaneous sessions; otherwise the safety accounting itself is a
        # CPU-amplification vector.
        if full:
            if self._used_bytes != sum(self._used_by_owner.values()):
                raise RuntimeError("relay forwarding owner accounting mismatch")
            if self._used_bytes != sum(record.size for record in self._records.values()):
                raise RuntimeError("relay forwarding lease accounting mismatch")

    @property
    def limit_bytes(self) -> int:
        return self._limit_bytes

    @property
    def data_limit_bytes(self) -> int:
        return self._limit_bytes - self._control_reserve_bytes

    @property
    def control_reserve_bytes(self) -> int:
        return self._control_reserve_bytes

    @property
    def used_bytes(self) -> int:
        return self._used_bytes

    @property
    def peak_bytes(self) -> int:
        return self._peak_bytes

    @property
    def active_leases(self) -> int:
        return len(self._records)

    @property
    def data_denials_total(self) -> int:
        return self._data_denials_total

    @property
    def control_denials_total(self) -> int:
        return self._control_denials_total

    def snapshot(self) -> dict[str, int]:
        self._assert_invariants(full=True)
        largest_owner = max(self._used_by_owner.values(), default=0)
        return {
            "limit_bytes": self._limit_bytes,
            "data_limit_bytes": self.data_limit_bytes,
            "control_reserve_bytes": self._control_reserve_bytes,
            "used_bytes": self._used_bytes,
            "peak_bytes": self._peak_bytes,
            "current_bytes": self._used_by_category["current"],
            "queued_bytes": self._used_by_category["queued"],
            "control_bytes": self._used_by_category["control"],
            "teardown_bytes": self._used_by_category["teardown"],
            "current_peak_bytes": self._peak_by_category["current"],
            "queued_peak_bytes": self._peak_by_category["queued"],
            "control_peak_bytes": self._peak_by_category["control"],
            "teardown_peak_bytes": self._peak_by_category["teardown"],
            "active_leases": len(self._records),
            "active_owners": len(self._used_by_owner),
            "largest_owner_bytes": largest_owner,
            "data_denials_total": self._data_denials_total,
            "control_denials_total": self._control_denials_total,
        }


class _RelayBudgetLease:
    """Move-only-in-spirit lease for one exact relay payload allocation."""

    __slots__ = ("_budget", "_token", "_released")

    def __init__(self, budget: _RelayForwardBudget, token: int) -> None:
        self._budget = budget
        self._token = int(token)
        self._released = False

    @property
    def budget(self) -> _RelayForwardBudget:
        return self._budget

    @property
    def size(self) -> int:
        return self._budget._record_for(self._token).size

    @property
    def owner(self) -> object:
        return self._budget._record_for(self._token).owner

    @property
    def category(self) -> _RelayBudgetCategory:
        return self._budget._record_for(self._token).category

    @property
    def released(self) -> bool:
        return self._released

    def reclassify(self, category: _RelayBudgetCategory) -> None:
        if self._released:
            raise RuntimeError("cannot reclassify a released relay budget lease")
        self._budget._reclassify(self._token, category)

    def release(self) -> bool:
        if self._released:
            return False
        self._budget._release(self._token)
        self._released = True
        return True


_RelayEnqueueOutcome = Literal["accepted", "local_overload", "global_overload"]


class _RelayForwardQueue:
    """Per-session ordered, byte-bounded, single-sender forwarder.

    One destination listener WebSocket multiplexes all connector sessions.
    Its receive task must only decode and synchronously admit frames; a slow
    connector is isolated behind this worker instead of head-of-line blocking
    every other session.
    """

    def __init__(
        self,
        send: Callable[[bytes], Awaitable[object]],
        *,
        timeout_s: float,
        buffer_limit_bytes: int,
        queue_max_items: int,
        on_sent: Callable[[int], None],
        process_budget: _RelayForwardBudget,
        budget_owner: object,
    ) -> None:
        if not math.isfinite(timeout_s) or timeout_s <= 0:
            raise ValueError("relay forward timeout must be finite and positive")
        if buffer_limit_bytes < 9:
            raise ValueError("relay forward queue byte limit is too small")
        if queue_max_items < 2:
            raise ValueError("relay forward queue needs a reserved terminal slot")
        self._send = send
        self._timeout_s = float(timeout_s)
        self._buffer_limit_bytes = int(buffer_limit_bytes)
        self._data_queue_max_items = int(queue_max_items) - 1
        self._on_sent = on_sent
        self._process_budget = process_budget
        self._budget_owner = budget_owner
        self._queue: asyncio.Queue[tuple[bytes, int, _RelayBudgetLease] | None] = asyncio.Queue(
            maxsize=queue_max_items
        )
        self._pending_bytes = 0
        self._pending_items = 0
        self._accepting = True
        self._terminal_error: BaseException | None = None
        self._worker_task: asyncio.Task[None] = asyncio.create_task(self._worker())

    def try_enqueue(
        self,
        frame: bytes,
        *,
        payload_bytes: int,
        current_lease: _RelayBudgetLease | None = None,
    ) -> _RelayEnqueueOutcome:
        if payload_bytes < 0 or payload_bytes > len(frame):
            raise ValueError("invalid relay forward payload accounting")
        if not self._accepting or self._terminal_error is not None:
            return "local_overload"
        if (
            len(frame) > self._buffer_limit_bytes
            or self._pending_bytes + len(frame) > self._buffer_limit_bytes
            or self._pending_items >= self._data_queue_max_items
        ):
            return "local_overload"

        lease: _RelayBudgetLease | None
        if current_lease is not None:
            if current_lease.budget is not self._process_budget:
                raise ValueError("relay queue received a lease from a different budget")
            if current_lease.owner is not self._budget_owner:
                raise ValueError("relay queue received a lease for a different session")
            if current_lease.size != len(frame) or current_lease.category != "current":
                raise ValueError("relay queue received an incompatible current-frame lease")
            lease = current_lease
        else:
            lease = self._process_budget.try_acquire(
                len(frame),
                owner=self._budget_owner,
                category="queued",
            )
            if lease is None:
                return "global_overload"
        if lease is None:
            raise RuntimeError("relay queue lease invariant failed")

        try:
            owned_frame = bytes(frame)
        except BaseException:
            if current_lease is None:
                lease.release()
            raise
        if current_lease is not None:
            lease.reclassify("queued")
        self._pending_bytes += len(frame)
        self._pending_items += 1
        try:
            self._queue.put_nowait((owned_frame, int(payload_bytes), lease))
        except BaseException:
            self._pending_bytes -= len(frame)
            self._pending_items -= 1
            if current_lease is not None:
                lease.reclassify("current")
            else:
                lease.release()
            raise
        return "accepted"

    def finish(self) -> bool:
        """Queue ordered EOF after all admitted DATA without awaiting."""
        if not self._accepting or self._terminal_error is not None:
            return False
        self._accepting = False
        self._queue.put_nowait(None)
        return True

    async def _worker(self) -> None:
        current: tuple[bytes, int, _RelayBudgetLease] | None = None
        current_is_item = False
        try:
            while True:
                current = await self._queue.get()
                current_is_item = True
                if current is None:
                    self._queue.task_done()
                    current_is_item = False
                    return
                frame, payload_bytes, lease = current
                lease.reclassify("current")
                try:
                    await asyncio.wait_for(self._send(frame), timeout=self._timeout_s)
                except Exception as exc:
                    terminal = _RelayForwardError(
                        f"relay session forward failed: {type(exc).__name__}: {exc}"
                    )
                    terminal.__cause__ = exc
                    self._terminal_error = terminal
                    raise terminal
                self._pending_bytes -= len(frame)
                self._pending_items -= 1
                self._queue.task_done()
                lease.release()
                current_is_item = False
                current = None
                self._on_sent(payload_bytes)
        finally:
            if current_is_item:
                if current is None:
                    raise RuntimeError("relay forward queue item invariant failed")
                frame, _payload_bytes, lease = current
                self._pending_bytes -= len(frame)
                self._pending_items -= 1
                self._queue.task_done()
                lease.release()
            while True:
                try:
                    abandoned = self._queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
                if abandoned is not None:
                    frame, _payload_bytes, lease = abandoned
                    self._pending_bytes -= len(frame)
                    self._pending_items -= 1
                    lease.release()
                self._queue.task_done()
            self._pending_bytes = 0
            self._pending_items = 0
            self._accepting = False

    async def abort(self) -> None:
        self._accepting = False
        if not self._worker_task.done():
            self._worker_task.cancel()
        with contextlib.suppress(BaseException):
            await self._worker_task

    @property
    def task(self) -> asyncio.Task[None]:
        return self._worker_task

    @property
    def pending_bytes(self) -> int:
        return self._pending_bytes

    @property
    def pending_items(self) -> int:
        return self._pending_items

    @property
    def terminal_error(self) -> BaseException | None:
        return self._terminal_error


@dataclass
class _RelayListener:
    """A destination peer that has authenticated and is now waiting
    for incoming connector sessions."""

    pubkey: bytes
    ws: web.WebSocketResponse
    routing_mode: str = "legacy_public_destination_v1"
    routing_keys: set[bytes] = field(default_factory=set)
    route_auth_pubs: dict[bytes, bytes] = field(default_factory=dict)
    route_expiries_ms: dict[bytes, int] = field(default_factory=dict)
    sessions: dict[bytes, "_RelaySession"] = field(default_factory=dict)
    reserved_sessions: int = 0
    teardown_count: int = 0
    budget_owner: object = field(default_factory=object)


@dataclass
class _RelaySession:
    """A paired connector↔listener session multiplexed over the
    listener's single WebSocket. Each gets a unique session_id; both
    sides see only that id, never the other side's pubkey."""

    session_id: bytes
    listener_pubkey: bytes
    connector_ws: web.WebSocketResponse
    listener_ws: web.WebSocketResponse  # the listener's WS — server forwards to it tagged
    last_activity_at: float = field(default_factory=time.monotonic)
    listener_to_connector: _RelayForwardQueue | None = None
    closing: bool = False
    close_task: asyncio.Task[None] | None = None
    budget_owner: object = field(default_factory=object)


# ─── server app ─────────────────────────────────────────────────────


def _estimated_process_memory_bytes(config: ServerConfig) -> int:
    """Return the fail-closed memory envelope for an admitted configuration.

    The reference probe populated 50,000 registrations, their three blinded
    aliases, all six rate-limiter maps, the relay nonce map, and the signed
    replay cache.  Scale that measured RSS delta by the number of logical map
    slots configured here, add a 25% allocator/platform margin, and then add
    independent reserves for the interpreter, in-flight handlers, and relay
    payload leases.  Integer ceiling division ensures the estimate never
    rounds an attacker-controlled allocation down.
    """

    measured_slots = _MEASURED_HOSTILE_STATE_KEYS * (
        _MEASURED_REGISTRY_SLOTS_PER_KEY + _MEASURED_AUXILIARY_MAPS
    )
    configured_slots = (
        config.max_registrations * _MEASURED_REGISTRY_SLOTS_PER_KEY
        + config.max_attacker_state_keys * _MEASURED_AUXILIARY_MAPS
        + (
            config.relay_max_route_keys * _RELAY_ROUTE_STATE_SLOTS_PER_KEY
            if config.enable_relay
            else 0
        )
    )
    scaled_state_numerator = (
        _MEASURED_HOSTILE_STATE_RSS_BYTES * configured_slots * _MEASURED_STATE_SAFETY_NUMERATOR
    )
    scaled_state_denominator = measured_slots * _MEASURED_STATE_SAFETY_DENOMINATOR
    scaled_state_bytes = (
        scaled_state_numerator + scaled_state_denominator - 1
    ) // scaled_state_denominator
    handler_bytes = config.max_concurrent_connections * _CONCURRENT_HANDLER_RESERVE_BYTES
    relay_bytes = config.relay_forward_global_budget_bytes if config.enable_relay else 0
    return _PROCESS_BASE_RESERVE_BYTES + scaled_state_bytes + handler_bytes + relay_bytes


def _validate_server_config(config: ServerConfig) -> None:
    """Reject unsafe or internally contradictory service limits."""

    if not isinstance(config.host, str) or not config.host.strip():
        raise ValueError("host must be non-empty text")
    if type(config.port) is not int or not 0 <= config.port <= 65_535:
        raise ValueError("port must be an integer from 0 through 65535")
    if type(config.enable_relay) is not bool:
        raise ValueError("enable_relay must be a boolean")
    if type(config.trust_proxy_headers) is not bool:
        raise ValueError("trust_proxy_headers must be a boolean")

    positive_ints = {
        "max_registrations": config.max_registrations,
        "max_attacker_state_keys": config.max_attacker_state_keys,
        "rate_per_ip_per_min": config.rate_per_ip_per_min,
        "rate_register_per_pubkey_per_min": config.rate_register_per_pubkey_per_min,
        "max_advertised_endpoints": config.max_advertised_endpoints,
        "relay_connect_per_ip_per_min": config.relay_connect_per_ip_per_min,
        "relay_max_route_keys": config.relay_max_route_keys,
        "rate_lookup_per_ip_per_min": config.rate_lookup_per_ip_per_min,
        "rate_new_pubkey_register_per_ip_per_min": (config.rate_new_pubkey_register_per_ip_per_min),
        "rate_listener_replace_per_pubkey_per_min": (
            config.rate_listener_replace_per_pubkey_per_min
        ),
        "max_concurrent_connections": config.max_concurrent_connections,
        "max_concurrent_per_source": config.max_concurrent_per_source,
        "memory_budget_bytes": config.memory_budget_bytes,
    }
    for name, value in positive_ints.items():
        if type(value) is not int or value <= 0:
            raise ValueError(f"{name} must be a positive integer")
    if config.max_concurrent_per_source > config.max_concurrent_connections:
        raise ValueError(
            "max_concurrent_per_source must not exceed max_concurrent_connections"
        )
    for name in (
        "rate_per_ip_per_min",
        "rate_register_per_pubkey_per_min",
        "relay_connect_per_ip_per_min",
        "rate_lookup_per_ip_per_min",
        "rate_new_pubkey_register_per_ip_per_min",
        "rate_listener_replace_per_pubkey_per_min",
    ):
        if getattr(config, name) > _MAX_RATE_PER_MINUTE:
            raise ValueError(f"{name} must not exceed {_MAX_RATE_PER_MINUTE}")
    if (
        type(config.eviction_interval_s) not in (int, float)
        or isinstance(config.eviction_interval_s, bool)
        or not math.isfinite(config.eviction_interval_s)
        or config.eviction_interval_s <= 0
    ):
        raise ValueError("eviction_interval_s must be finite and positive")

    for name, numeric_value in {
        "relay_session_idle_s": config.relay_session_idle_s,
        "relay_forward_timeout_s": config.relay_forward_timeout_s,
    }.items():
        if (
            type(numeric_value) not in (int, float)
            or isinstance(numeric_value, bool)
            or not math.isfinite(numeric_value)
            or numeric_value <= 0
        ):
            raise ValueError(f"{name} must be finite and positive")
    exact_ints = {
        "relay_max_sessions_per_listener": config.relay_max_sessions_per_listener,
        "relay_forward_queue_limit_bytes": config.relay_forward_queue_limit_bytes,
        "relay_forward_queue_max_items": config.relay_forward_queue_max_items,
        "relay_forward_global_budget_bytes": config.relay_forward_global_budget_bytes,
        "relay_forward_control_reserve_bytes": config.relay_forward_control_reserve_bytes,
    }
    for name, value in exact_ints.items():
        if type(value) is not int:
            raise ValueError(f"{name} must be an integer")
    if config.relay_max_sessions_per_listener <= 0:
        raise ValueError("relay_max_sessions_per_listener must be positive")
    if config.relay_forward_queue_limit_bytes < _RELAY_DATA_FRAME_WIRE_MAX_BYTES:
        raise ValueError("relay_forward_queue_limit_bytes must hold a maximum DATA frame")
    if config.relay_forward_queue_max_items < 2:
        raise ValueError("relay_forward_queue_max_items must be at least two")
    if config.relay_forward_global_budget_bytes <= 0:
        raise ValueError("relay_forward_global_budget_bytes must be positive")
    if config.relay_forward_control_reserve_bytes < CONTROL_FRAME_MAX_BYTES:
        raise ValueError("relay_forward_control_reserve_bytes must hold a maximum control frame")
    if config.relay_forward_control_reserve_bytes >= config.relay_forward_global_budget_bytes:
        raise ValueError(
            "relay_forward_control_reserve_bytes must be smaller than the global budget"
        )
    data_capacity = (
        config.relay_forward_global_budget_bytes - config.relay_forward_control_reserve_bytes
    )
    minimum_data_capacity = (
        config.relay_forward_queue_limit_bytes + 2 * _RELAY_DATA_FRAME_WIRE_MAX_BYTES
    )
    if data_capacity < minimum_data_capacity:
        raise ValueError(
            "relay forwarding global DATA capacity must hold the configured per-session "
            "queue plus one maximum received frame and its rewritten outbound copy"
        )
    required_memory_bytes = _estimated_process_memory_bytes(config)
    if required_memory_bytes > config.memory_budget_bytes:
        raise ValueError(
            "configured attacker state, connection cap, and relay budget require "
            f"at least {required_memory_bytes} process bytes, exceeding "
            f"memory_budget_bytes={config.memory_budget_bytes}; reduce the ceilings "
            "or raise both the declared budget and the external container/service limit"
        )
    token = config.metrics_token
    if token is not None:
        if not isinstance(token, str):
            raise ValueError("metrics_token must be text")
        if not token.isascii():
            raise ValueError("metrics_token must be ASCII Bearer-token text")
        encoded_token = token.encode("ascii")
        if len(encoded_token) < 32 or len(encoded_token) > 4096:
            raise ValueError("metrics_token must contain 32 to 4096 ASCII bytes")
        token_without_padding = token.rstrip("=")
        if not token_without_padding or any(
            char not in _BEARER_TOKEN_ALPHABET for char in token_without_padding
        ):
            raise ValueError("metrics_token must use HTTP Bearer-token characters")
        if "=" in token_without_padding:
            raise ValueError("metrics_token padding is permitted only at the end")


class RendezvousApp:
    def __init__(self, config: ServerConfig):
        _validate_server_config(config)
        self.config = config
        self.registry = Registry(max_entries=config.max_registrations)
        limiter_keys = config.max_attacker_state_keys
        self.rate_per_ip = _RateLimiter(
            rate_per_min=config.rate_per_ip_per_min,
            max_keys=limiter_keys,
        )
        self.rate_register_per_pubkey = _RateLimiter(
            rate_per_min=config.rate_register_per_pubkey_per_min,
            max_keys=limiter_keys,
        )
        # v0.20.7 (security audit H24): /lookup-specific per-IP cap.
        self.rate_lookup_per_ip = _RateLimiter(
            rate_per_min=config.rate_lookup_per_ip_per_min,
            max_keys=limiter_keys,
        )
        # v0.20.7 (security audit H26): per-IP NEW-pubkey register cap.
        self.rate_new_pubkey_per_ip = _RateLimiter(
            rate_per_min=config.rate_new_pubkey_register_per_ip_per_min,
            max_keys=limiter_keys,
        )
        # v0.20.7 (security audit M31): per-pubkey listener-slot
        # replacement cap.
        self.rate_listener_replace_per_pubkey = _RateLimiter(
            rate_per_min=config.rate_listener_replace_per_pubkey_per_min,
            max_keys=limiter_keys,
        )
        # v0.5.5: relay-side rate limit + state.
        self.rate_relay_connect_per_ip = _RateLimiter(
            rate_per_min=config.relay_connect_per_ip_per_min,
            max_keys=limiter_keys,
        )
        self._relay_listeners: dict[bytes, _RelayListener] = {}
        self._relay_route_lock = asyncio.Lock()
        self._relay_teardown_tasks: set[asyncio.Task[None]] = set()
        # These caps count individual replay values, not merely identities.
        # A per-pubkey deque would still allow one authorized attacker to retain
        # an unbounded number of unique signatures/nonces inside the window.
        self._relay_listen_nonces: dict[tuple[bytes, bytes], int] = {}
        self._signed_replay_cache: dict[tuple[str, bytes, bytes], int] = {}
        self.metrics = Metrics()
        self._relay_forward_budget = _RelayForwardBudget(
            config.relay_forward_global_budget_bytes,
            config.relay_forward_control_reserve_bytes,
        )
        self._eviction_task: asyncio.Task | None = None
        # v0.20.7 (security audit M33): global concurrent-connection
        # gate. Uses a plain counter (asyncio is single-threaded so
        # check-then-increment without an await is atomic) instead of
        # asyncio.Semaphore so we can fail-fast at the cap rather than
        # block the request task. Configuration validation requires a finite,
        # positive ceiling so this counter participates in the memory envelope.
        self._max_concurrent: int = config.max_concurrent_connections
        self._concurrent: int = 0
        # In-flight handlers per source address. Entries exist only while a
        # handler is running, so the map never exceeds the global cap.
        self._max_concurrent_per_source: int = config.max_concurrent_per_source
        self._concurrent_by_source: dict[str, int] = {}
        # v0.20.7 (security audit M35): HMAC key for IP-in-logs. The
        # raw IP shows up at DEBUG; INFO and above use the HMAC tag so
        # log-pipeline operators don't hold raw client IPs by accident.
        # Re-seeded every process restart — log correlation across
        # restarts is intentionally not preserved.
        self._log_ip_secret: bytes = secrets.token_bytes(32)

    @web.middleware
    async def _concurrency_middleware(self, request: web.Request, handler):
        """v0.20.7 (security audit M33): global concurrent-connection
        cap. Refuses fast at the ceiling so fan-out attacks from many
        source IPs can't exhaust fds / asyncio task state. WebSocket
        handlers count toward the cap for the lifetime of the WS,
        which is exactly the period that holds the resources we care
        about."""
        source = self._rate_identity(request)
        held = self._concurrent_by_source.get(source, 0)
        if held >= self._max_concurrent_per_source:
            return web.json_response(
                {"error": "too many connections from this address"}, status=429
            )
        if self._concurrent >= self._max_concurrent:
            return web.json_response({"error": "server at capacity"}, status=503)
        self._concurrent += 1
        self._concurrent_by_source[source] = held + 1
        try:
            return await handler(request)
        finally:
            self._concurrent -= 1
            remaining = self._concurrent_by_source.get(source, 1) - 1
            if remaining > 0:
                self._concurrent_by_source[source] = remaining
            else:
                self._concurrent_by_source.pop(source, None)

    @staticmethod
    def _browser_cors_contract(path: str) -> tuple[str, ...] | None:
        """Return allowed methods for the public browser rendezvous API.

        Presence writes are signed and lookups are already public, so exposing
        these exact routes to credential-free browser fetches does not widen
        authority. Metrics and relay upgrades are deliberately excluded.
        """

        if path in {"/api/v1/register", "/api/v1/revoke"}:
            return ("POST",)
        if path.startswith("/api/v1/lookup/") or path.startswith("/api/v2/lookup_token/"):
            return ("GET",)
        return None

    @web.middleware
    async def _browser_cors_middleware(self, request: web.Request, handler):
        allowed_methods = self._browser_cors_contract(request.path)
        origin = request.headers.get("Origin")
        if allowed_methods is None or origin is None:
            return await handler(request)

        if request.method == "OPTIONS":
            requested_method = request.headers.get("Access-Control-Request-Method", "").upper()
            requested_headers = {
                item.strip().lower()
                for item in request.headers.get("Access-Control-Request-Headers", "").split(",")
                if item.strip()
            }
            if requested_method not in allowed_methods or not requested_headers <= {"content-type"}:
                return web.Response(status=403, text="CORS preflight rejected")
            if not self._rate_check_ip(request):
                return web.Response(status=429, text="rate limited")
            response = web.Response(status=204)
            response.headers["Access-Control-Max-Age"] = "600"
        else:
            try:
                response = await handler(request)
            except web.HTTPException as exc:
                # Attach below, then re-raise: returning an HTTPException as a
                # response is deprecated by aiohttp. Protocol errors
                # (malformed JSON, body ceiling, read deadline) still retain
                # the same narrow CORS contract as ordinary responses.
                response = exc

        # Wildcard is intentional: these routes accept no cookies or browser
        # credentials, writes require a device signature, and lookups are
        # unauthenticated protocol operations. Never add Allow-Credentials.
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = ", ".join(allowed_methods)
        response.headers["Access-Control-Allow-Headers"] = "Content-Type"
        if isinstance(response, web.HTTPException):
            raise response
        return response

    def make_app(self) -> web.Application:
        app = web.Application(
            # WebSocket messages have their own per-response max_msg_size.
            # Keeping this at 2 MiB let concurrent register/revoke requests
            # allocate 256x the protocol body ceiling before _read_json could
            # reject them.
            client_max_size=MAX_REQUEST_BYTES,
            middlewares=[self._concurrency_middleware, self._browser_cors_middleware],
        )
        app.router.add_post("/api/v1/register", self._handle_register)
        app.router.add_get("/api/v1/lookup/{pubkey_b64}", self._handle_lookup)
        # v0.20.7 (Bundle 51): blinded-token lookup. The rendezvous
        # never sees the raw pubkey on this path — it uses an
        # HKDF-derived per-epoch token. Daemons compute the same
        # token from (peer_pub, epoch) and look up by it.
        app.router.add_get(
            "/api/v2/lookup_token/{token_b64}",
            self._handle_lookup_token,
        )
        app.router.add_post("/api/v1/revoke", self._handle_revoke)
        app.router.add_get("/health", self._handle_health)
        app.router.add_get("/metrics", self._handle_metrics)
        # v0.5.5: relay endpoints. Off unless config.enable_relay.
        if self.config.enable_relay:
            app.router.add_get("/api/v1/relay/listen", self._handle_relay_listen)
            app.router.add_get("/api/v2/relay/listen", self._handle_relay_listen)
            app.router.add_get(
                "/api/v1/relay/connect/{dst_pubkey_b64}",
                self._handle_relay_connect,
            )
            app.router.add_get(
                "/api/v2/relay/connect/{route_tag_b64}",
                self._handle_relay_connect,
            )
        app.on_startup.append(self._on_startup)
        app.on_shutdown.append(self._on_shutdown)
        app.on_cleanup.append(self._on_cleanup)
        return app

    async def _on_startup(self, _app: web.Application) -> None:
        self._eviction_task = asyncio.create_task(self._eviction_loop())

    async def _on_shutdown(self, _app: web.Application) -> None:
        """Close every live relay transport before aiohttp drains handlers.

        ``AppRunner.cleanup()`` first runs application shutdown callbacks and
        only then waits for request handlers.  A relay listener handler is an
        intentionally long-lived WebSocket, so merely waiting for handlers
        leaves both ends of every active relay socket alive until aiohttp's
        shutdown timeout (and, on Windows, until a later garbage collection).
        Close the application-owned sessions and listener sockets here so
        handlers observe EOF immediately and all proactor transports are
        released while their event loop is still running.
        """

        async def _close_listener(listener: _RelayListener) -> None:
            closes = [
                self._schedule_relay_session_close(listener, session_id)
                for session_id in list(listener.sessions)
            ]
            await asyncio.gather(
                *(task for task in closes if task is not None),
                return_exceptions=True,
            )
            with contextlib.suppress(Exception):
                await self._close_relay_websocket(
                    listener.ws,
                    owner=listener.budget_owner,
                    code=1001,
                    message=b"relay server shutting down",
                    operation="relay listener shutdown close",
                )
            self._unregister_relay_listener(listener)

        await asyncio.gather(
            *(_close_listener(listener) for listener in self._unique_relay_listeners()),
            return_exceptions=True,
        )
        while self._relay_teardown_tasks:
            await asyncio.gather(*list(self._relay_teardown_tasks), return_exceptions=True)

    async def _on_cleanup(self, _app: web.Application) -> None:
        if self._eviction_task:
            self._eviction_task.cancel()
            with contextlib.suppress(BaseException):
                await self._eviction_task
            self._eviction_task = None
        while self._relay_teardown_tasks:
            await asyncio.gather(*list(self._relay_teardown_tasks), return_exceptions=True)

    def _unique_relay_listeners(self) -> tuple[_RelayListener, ...]:
        """Return each listener WebSocket once even when many tags map to it."""

        unique: dict[int, _RelayListener] = {}
        for listener in self._relay_listeners.values():
            unique[id(listener)] = listener
        return tuple(unique.values())

    def _unregister_relay_listener(self, listener: _RelayListener) -> None:
        for routing_key in tuple(listener.routing_keys or {listener.pubkey}):
            if self._relay_listeners.get(routing_key) is listener:
                self._relay_listeners.pop(routing_key, None)
        listener.routing_keys.clear()
        listener.route_auth_pubs.clear()
        listener.route_expiries_ms.clear()

    async def _expire_blinded_relay_routes(self, current_ms: int) -> int:
        """Remove expired tags and retire listeners that stopped refreshing."""

        expired = 0
        for listener in self._unique_relay_listeners():
            if listener.routing_mode != "pairwise_blinded_v1":
                continue
            for routing_key, expiry_ms in tuple(listener.route_expiries_ms.items()):
                if expiry_ms > current_ms:
                    continue
                if self._relay_listeners.get(routing_key) is listener:
                    self._relay_listeners.pop(routing_key, None)
                listener.routing_keys.discard(routing_key)
                listener.route_auth_pubs.pop(routing_key, None)
                listener.route_expiries_ms.pop(routing_key, None)
                expired += 1
            if not listener.routing_keys and not listener.ws.closed:
                with contextlib.suppress(Exception):
                    await self._close_relay_websocket(
                        listener.ws,
                        owner=listener.budget_owner,
                        code=4008,
                        message=b"all blinded relay routes expired",
                        operation="expired blinded relay listener close",
                    )
        return expired

    async def _install_blinded_listener_routes(
        self,
        listener: _RelayListener,
        route_auth,
    ) -> None:
        """Atomically validate ownership continuity and replace route tags."""

        incoming_auth = {route.route_tag: route.auth_public for route in route_auth.routes}
        incoming_expiry = {
            route.route_tag: route.expires_at_ms for route in route_auth.routes
        }
        incoming_keys = set(incoming_auth)
        async with self._relay_route_lock:
            other_key_count = sum(
                1
                for mapped_listener in self._relay_listeners.values()
                if mapped_listener is not listener
            )
            if other_key_count + len(incoming_keys) > self.config.relay_max_route_keys:
                raise ValueError("relay routing table is at its bounded capacity")

            priors: dict[int, _RelayListener] = {}
            replacement_key_by_prior: dict[int, bytes] = {}
            for routing_key, auth_public in incoming_auth.items():
                prior = self._relay_listeners.get(routing_key)
                if prior is None or prior is listener:
                    continue
                prior_auth_public = prior.route_auth_pubs.get(routing_key)
                if (
                    prior.routing_mode != "pairwise_blinded_v1"
                    or prior_auth_public is None
                    or not secrets.compare_digest(prior_auth_public, auth_public)
                ):
                    raise ValueError(
                        "routing tag is already held by different epoch authority"
                    )
                priors[id(prior)] = prior
                replacement_key_by_prior[id(prior)] = routing_key

            for prior_id, prior in priors.items():
                rate_key = replacement_key_by_prior[prior_id].hex()
                if not self.rate_listener_replace_per_pubkey.admit(rate_key):
                    raise ValueError("blinded listener replacement rate-limited")

            for prior in priors.values():
                with contextlib.suppress(Exception):
                    await self._close_relay_websocket(
                        prior.ws,
                        owner=prior.budget_owner,
                        code=4003,
                        message=b"replaced by authenticated blinded listener",
                        operation="replaced blinded relay listener close",
                    )
                replacement_closes = [
                    self._schedule_relay_session_close(prior, sid)
                    for sid in list(prior.sessions)
                ]
                await asyncio.gather(
                    *(task for task in replacement_closes if task is not None),
                    return_exceptions=True,
                )

            for obsolete in tuple(listener.routing_keys - incoming_keys):
                if self._relay_listeners.get(obsolete) is listener:
                    self._relay_listeners.pop(obsolete, None)
            listener.routing_keys = incoming_keys
            listener.route_auth_pubs = incoming_auth
            listener.route_expiries_ms = incoming_expiry
            for routing_key in incoming_keys:
                self._relay_listeners[routing_key] = listener

    async def _eviction_loop(self) -> None:
        try:
            while True:
                await asyncio.sleep(self.config.eviction_interval_s)
                evicted = self.registry.evict_expired(now_ms())
                # v0.20.7 (security audit H25): all sweeps are now
                # async + chunked so the eviction tick yields the
                # event loop frequently even with millions of keys.
                await self.rate_per_ip.sweep()
                await self.rate_register_per_pubkey.sweep()
                await self.rate_lookup_per_ip.sweep()
                await self.rate_new_pubkey_per_ip.sweep()
                await self.rate_listener_replace_per_pubkey.sweep()
                await self.rate_relay_connect_per_ip.sweep()
                await self._sweep_relay_listen_nonces()
                await self._sweep_signed_replay_cache()
                await self._expire_blinded_relay_routes(now_ms())
                if evicted:
                    log.debug("evicted %d expired registrations", evicted)
        except asyncio.CancelledError:
            return

    # ─── request helpers ────────────────────────────────────────────

    @staticmethod
    def _canonical_ip(value: object) -> str | None:
        """Return one stable textual key for an IPv4/IPv6 address."""

        try:
            parsed = ipaddress.ip_address(str(value))
        except ValueError:
            return None
        if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
            return str(parsed.ipv4_mapped)
        return str(parsed)

    def _client_ip(self, request: web.Request) -> str:
        """Best-effort remote IP.

        X-Forwarded-For is trusted only when the operator explicitly
        enables trust_proxy_headers. Directly exposed servers must use
        the socket peer address so clients cannot spoof rate-limit
        identities.

        v0.20.7 (security audit M34): when trust_proxy_headers is
        enabled, take the LAST entry in XFF (the next-hop attested by
        the proxy), not the first (the client-supplied value when
        nginx uses the default `proxy_add_x_forwarded_for`). Validate
        the result via ipaddress; on parse failure fall back to the
        socket peer rather than trusting an attacker-shaped string.
        """
        peer = request.transport.get_extra_info("peername") if request.transport else None
        peer_ip = self._canonical_ip(peer[0]) if peer else None
        peer_ip = peer_ip or "unknown"
        xff = request.headers.get("X-Forwarded-For")
        if self.config.trust_proxy_headers and xff:
            # Last comma-token = proxy-attested next hop.
            parts = [p.strip() for p in xff.split(",") if p.strip()]
            if parts:
                candidate = parts[-1]
                canonical = self._canonical_ip(candidate)
                return canonical or peer_ip
        return peer_ip

    def _rate_identity(self, request: web.Request) -> str:
        """Return a stable abuse-control identity for the request source.

        IPv6 hosts commonly control many addresses inside one routed /64. Keying
        quotas on every full address would let one host reset all per-IP limits
        and churn the bounded limiter maps by rotating interface identifiers.
        Preserve IPv4 granularity and group native IPv6 at /64; the full address
        is still used for the observed endpoint.
        """

        client_ip = self._client_ip(request)
        try:
            parsed = ipaddress.ip_address(client_ip)
        except ValueError:
            return client_ip
        if isinstance(parsed, ipaddress.IPv6Address):
            return str(ipaddress.ip_network((parsed, 64), strict=False))
        return str(parsed)

    def _metrics_client_ip(self, request: web.Request) -> str | None:
        """Return a strictly attested client IP for the metrics trust gate.

        Rate limiting may conservatively fall back to the socket peer when a
        trusted proxy sends malformed metadata. Metrics authorization cannot:
        the socket peer is commonly nginx on 127.0.0.1, which would convert a
        missing/malformed XFF header into an external localhost bypass.
        """

        peer = request.transport.get_extra_info("peername") if request.transport else None
        peer_ip = str(peer[0]) if peer else ""
        if self.config.trust_proxy_headers:
            forwarded = request.headers.get("X-Forwarded-For", "")
            parts = [part.strip() for part in forwarded.split(",") if part.strip()]
            if not parts:
                return None
            candidate = parts[-1]
        else:
            candidate = peer_ip
        return self._canonical_ip(candidate)

    @staticmethod
    def _route_log_label(request: web.Request) -> str:
        """Return a route template that never embeds a pubkey or token."""

        route = getattr(request.match_info, "route", None)
        resource = getattr(route, "resource", None)
        canonical = getattr(resource, "canonical", None)
        if isinstance(canonical, str) and canonical:
            return canonical
        return "<unmatched>"

    def _ip_log_id(self, ip: str) -> str:
        """v0.20.7 (security audit M35): HMAC tag for IP-in-logs.

        Returns first 12 hex chars of HMAC-SHA256(secret, ip). The
        secret is per-process so cross-restart correlation is broken,
        but a single instance can still match same-IP behavior across
        log lines for incident response. Operators who want the raw
        IP can flip log-level to DEBUG.
        """
        try:
            mac = hmac.new(self._log_ip_secret, ip.encode("utf-8"), hashlib.sha256).digest()
            return mac[:6].hex()
        except Exception:
            return "?"

    def _admit_relay_listen_nonce(self, pubkey: bytes, timestamp_ms: int, nonce: bytes) -> bool:
        """Admit a nonce once while bounding all retained nonce values."""
        from one_link.relay_proto import REPLAY_WINDOW_MS

        del timestamp_ms  # validity is checked by the caller; retain admission time for ordering
        admitted_at = now_ms()
        cutoff = admitted_at - REPLAY_WINDOW_MS
        key = (bytes(pubkey), bytes(nonce))
        if key in self._relay_listen_nonces:
            return False
        if len(self._relay_listen_nonces) >= self.config.max_attacker_state_keys:
            with contextlib.suppress(StopIteration):
                oldest = next(iter(self._relay_listen_nonces))
                if self._relay_listen_nonces[oldest] < cutoff:
                    self._relay_listen_nonces.pop(oldest, None)
        if len(self._relay_listen_nonces) >= self.config.max_attacker_state_keys:
            return False
        self._relay_listen_nonces[key] = admitted_at
        return True

    async def _sweep_relay_listen_nonces(self) -> int:
        from one_link.relay_proto import REPLAY_WINDOW_MS

        cutoff = now_ms() - REPLAY_WINDOW_MS
        dead: list[tuple[bytes, bytes]] = []
        seen = 0
        for key, admitted_at in list(self._relay_listen_nonces.items()):
            if admitted_at < cutoff:
                dead.append(key)
            seen += 1
            if seen % _SWEEP_CHUNK == 0:
                await asyncio.sleep(0)
        for key in dead:
            self._relay_listen_nonces.pop(key, None)
        return len(dead)

    def _admit_signed_message_once(
        self, kind: str, pubkey: bytes, timestamp_ms: int, signature: bytes
    ) -> bool:
        """Reject exact signed request replays inside the replay window."""
        from one_link.rendezvous_proto import REPLAY_WINDOW_MS

        del (
            timestamp_ms
        )  # caller validates signed time; local admission time is monotonic in the map
        admitted_at = now_ms()
        cutoff = admitted_at - REPLAY_WINDOW_MS
        key = (kind, bytes(pubkey), bytes(signature))
        if key in self._signed_replay_cache:
            return False
        if len(self._signed_replay_cache) >= self.config.max_attacker_state_keys:
            with contextlib.suppress(StopIteration):
                oldest = next(iter(self._signed_replay_cache))
                if self._signed_replay_cache[oldest] < cutoff:
                    self._signed_replay_cache.pop(oldest, None)
        if len(self._signed_replay_cache) >= self.config.max_attacker_state_keys:
            return False
        self._signed_replay_cache[key] = admitted_at
        return True

    async def _sweep_signed_replay_cache(self) -> int:
        from one_link.rendezvous_proto import REPLAY_WINDOW_MS

        cutoff = now_ms() - REPLAY_WINDOW_MS
        dead: list[tuple[str, bytes, bytes]] = []
        seen = 0
        for key, admitted_at in list(self._signed_replay_cache.items()):
            if admitted_at < cutoff:
                dead.append(key)
            seen += 1
            if seen % _SWEEP_CHUNK == 0:
                await asyncio.sleep(0)
        for key in dead:
            self._signed_replay_cache.pop(key, None)
        return len(dead)

    def _client_port(self, request: web.Request) -> int:
        peer = request.transport.get_extra_info("peername") if request.transport else None
        if peer:
            return int(peer[1])
        return 0

    def _rate_check_ip(self, request: web.Request) -> bool:
        ip = self._rate_identity(request)
        ok = self.rate_per_ip.admit(ip)
        if not ok:
            self.metrics.rate_limit_rejects_total += 1
            # v0.20.7 (security audit M35): HMAC tag at INFO; raw IP
            # only at DEBUG. log-pipeline operators stop accidentally
            # retaining raw client IPs.
            log.info(
                "rate-limited iphash=%s on %s",
                self._ip_log_id(ip),
                self._route_log_label(request),
            )
            log.debug(
                "rate-limited raw-ip=%s on %s",
                ip,
                self._route_log_label(request),
            )
        return ok

    async def _read_json(self, request: web.Request) -> dict:
        # v0.20.7 (security audit M32): wrap the body read in
        # asyncio.wait_for so a slowloris client (1 byte / 30s) can't
        # hold a connection open for hours. aiohttp does not enforce
        # a per-request body deadline by default; this is the missing
        # ceiling.
        try:
            body = await asyncio.wait_for(request.read(), timeout=_REQUEST_READ_TIMEOUT_S)
        except asyncio.TimeoutError:
            raise web.HTTPRequestTimeout(text="body read timed out")
        if len(body) > MAX_REQUEST_BYTES:
            raise web.HTTPRequestEntityTooLarge(max_size=MAX_REQUEST_BYTES, actual_size=len(body))
        try:
            d = bounded_json_loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as e:
            raise web.HTTPBadRequest(text=f"invalid json: {e}")
        if not isinstance(d, dict):
            raise web.HTTPBadRequest(text="body must be a JSON object")
        return d

    # ─── handlers ───────────────────────────────────────────────────

    async def _handle_register(self, request: web.Request) -> web.Response:
        if not self._rate_check_ip(request):
            return web.Response(status=429, text="rate limited")
        try:
            payload = await self._read_json(request)
            req = RegisterReq.from_wire(payload)
        except web.HTTPException:
            self.metrics.register_rejects_total += 1
            raise
        except ValueError as e:
            self.metrics.register_rejects_total += 1
            return web.Response(status=400, text=f"bad request: {e}")

        if not timestamp_within_replay_window(req.timestamp_ms):
            self.metrics.register_rejects_total += 1
            return web.Response(status=400, text="timestamp out of replay window")

        try:
            req.verify()
        except ValueError:
            self.metrics.register_rejects_total += 1
            return web.Response(status=401, text="signature does not verify")
        if not self._admit_signed_message_once(
            "register", req.pubkey, req.timestamp_ms, req.signature
        ):
            self.metrics.register_rejects_total += 1
            return web.Response(status=409, text="replayed register")

        # Per-pubkey rate limit kicks in only AFTER signature verifies,
        # so an attacker without the key can't burn through a victim's
        # quota with garbage signatures.
        pubkey_b64_for_rate = req.pubkey.hex()
        if not self.rate_register_per_pubkey.admit(pubkey_b64_for_rate):
            self.metrics.rate_limit_rejects_total += 1
            return web.Response(status=429, text="too many registrations for this pubkey")

        # v0.20.7 (security audit H26): per-IP NEW-pubkey limit.
        # Per-pubkey rate alone doesn't catch an attacker minting fresh
        # keys (Ed25519 keypair generation is cheap). Without this separate
        # limit, one source can churn every configured registry slot despite
        # the per-key quota. The shipped 10/min ceiling slows that flush.
        is_new = self.registry.get(req.pubkey) is None
        if is_new:
            ip = self._rate_identity(request)
            if not self.rate_new_pubkey_per_ip.admit(ip):
                self.metrics.rate_limit_rejects_total += 1
                self.metrics.register_rejects_total += 1
                return web.Response(
                    status=429,
                    text="too many new-pubkey registrations from this IP",
                )

        # Cap advertised endpoints (defense-in-depth; proto already caps).
        if len(req.advertised_endpoints) > self.config.max_advertised_endpoints:
            self.metrics.register_rejects_total += 1
            return web.Response(status=400, text="too many advertised endpoints")

        observed = Endpoint(host=self._client_ip(request), port=self._client_port(request))
        now = now_ms()
        expires_at = now + req.ttl_s * 1000

        reg = Registration(
            pubkey=req.pubkey,
            observed_endpoint=observed,
            advertised_endpoints=list(req.advertised_endpoints),
            nat_type=req.nat_type,
            capabilities=list(req.capabilities),
            registered_at_ms=now,
            expires_at_ms=expires_at,
        )
        self.registry.upsert(reg)
        self.metrics.registers_total += 1

        ack = RegisterAck(
            observed_host=observed.host,
            observed_port=observed.port,
            server_time_ms=now,
            expires_at_ms=expires_at,
        )
        return web.json_response(ack.to_wire())

    async def _handle_lookup(self, request: web.Request) -> web.Response:
        if not self._rate_check_ip(request):
            return web.Response(status=429, text="rate limited")
        # v0.20.7 (security audit H24): /lookup-specific cap on top of
        # the global per-IP limit. Lookup is unauthenticated and the
        # response is 15-30x the request, so it's a reflection-friendly
        # endpoint without this stricter ceiling.
        ip = self._rate_identity(request)
        if not self.rate_lookup_per_ip.admit(ip):
            self.metrics.rate_limit_rejects_total += 1
            log.info(
                "lookup rate-limited iphash=%s",
                self._ip_log_id(ip),
            )
            return web.Response(status=429, text="lookup rate limited")
        from one_link.rendezvous_proto import _b64d  # type: ignore

        try:
            pubkey = _b64d(
                request.match_info["pubkey_b64"],
                expected_size=32,
                name="pubkey_b64",
            )
        except ValueError:
            return web.Response(status=400, text="invalid pubkey_b64")

        reg = self.registry.get(pubkey)
        now = now_ms()
        if reg is None or reg.expires_at_ms <= now:
            if reg is not None:
                self.registry.remove(pubkey)
            self.metrics.lookups_total += 1
            self.metrics.lookup_misses_total += 1
            return web.Response(status=404, text="not registered")

        # External audit 2026-05-18 ES-17: cap the response size so the
        # /lookup endpoint can't be used as a 15-30× UDP-style reflection
        # vector. Per-IP rate limit doesn't help a distributed source
        # (10k IPs × 30/min × 1-2KB amplifies to 75-150 MB/s reflected).
        # By bounding endpoint count + caps count we make the response
        # ~5-10× the request, not 15-30×. The cap is high enough that
        # legitimate clients (which typically advertise 2-3 endpoints
        # at most: LAN, WAN, optional relay) see no functional change.
        ack = LookupAck(
            pubkey=reg.pubkey,
            observed_endpoint=reg.observed_endpoint,
            advertised_endpoints=list(reg.advertised_endpoints)[:_LOOKUP_MAX_ADVERTISED_ENDPOINTS],
            nat_type=reg.nat_type,
            capabilities=list(reg.capabilities)[:_LOOKUP_MAX_CAPABILITIES],
            expires_at_ms=reg.expires_at_ms,
            server_time_ms=now,
        )
        self.metrics.lookups_total += 1
        return web.json_response(ack.to_wire())

    async def _handle_lookup_token(self, request: web.Request) -> web.Response:
        """v0.20.7 (Bundle 51): blinded-token lookup. Same rate-limit
        story as v1; the wire never carries a raw pubkey."""
        if not self._rate_check_ip(request):
            return web.Response(status=429, text="rate limited")
        ip = self._rate_identity(request)
        if not self.rate_lookup_per_ip.admit(ip):
            self.metrics.rate_limit_rejects_total += 1
            log.info(
                "lookup_token rate-limited iphash=%s",
                self._ip_log_id(ip),
            )
            return web.Response(status=429, text="lookup rate limited")
        from one_link.rendezvous_proto import _b64d  # type: ignore

        try:
            token = _b64d(
                request.match_info["token_b64"],
                expected_size=32,
                name="token_b64",
            )
        except ValueError:
            return web.Response(status=400, text="invalid token_b64")
        reg = self.registry.get_by_token(token)
        now = now_ms()
        if reg is None or reg.expires_at_ms <= now:
            self.metrics.lookups_total += 1
            self.metrics.lookup_misses_total += 1
            return web.Response(status=404, text="not registered")
        ack = LookupAck(
            pubkey=reg.pubkey,  # the recipient learns the pubkey;
            # the rendezvous never sent it on
            # the *lookup* wire (only the alias)
            observed_endpoint=reg.observed_endpoint,
            advertised_endpoints=list(reg.advertised_endpoints)[:_LOOKUP_MAX_ADVERTISED_ENDPOINTS],
            nat_type=reg.nat_type,
            capabilities=list(reg.capabilities)[:_LOOKUP_MAX_CAPABILITIES],
            expires_at_ms=reg.expires_at_ms,
            server_time_ms=now,
        )
        self.metrics.lookups_total += 1
        return web.json_response(ack.to_wire())

    async def _handle_revoke(self, request: web.Request) -> web.Response:
        if not self._rate_check_ip(request):
            return web.Response(status=429, text="rate limited")
        try:
            payload = await self._read_json(request)
            req = RevokeReq.from_wire(payload)
        except web.HTTPException:
            raise
        except ValueError as e:
            return web.Response(status=400, text=f"bad request: {e}")

        if not timestamp_within_replay_window(req.timestamp_ms):
            return web.Response(status=400, text="timestamp out of replay window")
        try:
            req.verify()
        except ValueError:
            return web.Response(status=401, text="signature does not verify")
        if not self._admit_signed_message_once(
            "revoke", req.pubkey, req.timestamp_ms, req.signature
        ):
            return web.Response(status=409, text="replayed revoke")

        removed = self.registry.remove(req.pubkey)
        self.metrics.revokes_total += 1
        return web.Response(
            status=200 if removed else 404,
            text="revoked" if removed else "not registered",
        )

    async def _handle_health(self, request: web.Request) -> web.Response:
        # Public liveness must not duplicate private metrics or provide an
        # unmetered attack-feedback endpoint. Container checks remain far
        # below the ordinary per-IP budget.
        if not self._rate_check_ip(request):
            return web.Response(status=429, text="rate limited")
        return web.json_response({"ok": True})

    async def _handle_metrics(self, request: web.Request) -> web.Response:
        # v0.20.7 (security audit M36): /metrics is operational
        # telemetry. Exposing it to attackers gives them a feedback
        # signal while they tune an attack (registry_evictions_total,
        # rate_limit_rejects_total, relay_listeners_active). Gate it.
        if not self._rate_check_ip(request):
            return web.Response(status=429, text="rate limited")
        client_ip = self._metrics_client_ip(request)
        is_loopback = False
        if client_ip is not None:
            is_loopback = ipaddress.ip_address(client_ip).is_loopback
        listener_is_loopback = self.config.host.lower() == "localhost"
        if not listener_is_loopback:
            listener_ip = self._canonical_ip(self.config.host)
            listener_is_loopback = bool(
                listener_ip and ipaddress.ip_address(listener_ip).is_loopback
            )
        unauthenticated_local = (
            is_loopback and listener_is_loopback and not self.config.trust_proxy_headers
        )
        token = self.config.metrics_token
        auth = request.headers.get("Authorization", "")
        scheme, separator, supplied = auth.partition(" ")
        if not separator or scheme.lower() != "bearer":
            supplied = ""
        token_authorized = bool(token is not None and hmac.compare_digest(supplied, token))
        if not unauthenticated_local and not token_authorized:
            if token is None:
                return web.Response(
                    status=403,
                    text="metrics endpoint is private; configure a metrics "
                    "token file for wildcard, non-loopback, or proxy access",
                )
            return web.Response(
                status=401,
                text="unauthorized",
                headers={"WWW-Authenticate": "Bearer"},
            )
        relay_listeners = self._unique_relay_listeners()
        blinded_listeners = tuple(
            listener
            for listener in relay_listeners
            if listener.routing_mode == "pairwise_blinded_v1"
        )
        legacy_listeners = tuple(
            listener
            for listener in relay_listeners
            if listener.routing_mode == "legacy_public_destination_v1"
        )
        return web.json_response(
            {
                "started_at_ms": self.metrics.started_at_ms,
                "uptime_ms": now_ms() - self.metrics.started_at_ms,
                "registrations": len(self.registry),
                "registry_evictions_total": self.registry.evictions,
                "registers_total": self.metrics.registers_total,
                "register_rejects_total": self.metrics.register_rejects_total,
                "lookups_total": self.metrics.lookups_total,
                "lookup_misses_total": self.metrics.lookup_misses_total,
                "revokes_total": self.metrics.revokes_total,
                "rate_limit_rejects_total": self.metrics.rate_limit_rejects_total,
                "relay_enabled": self.config.enable_relay,
                "relay_listeners_active": len(relay_listeners),
                "relay_routes_active": len(self._relay_listeners),
                "relay_blinded_listeners_active": len(blinded_listeners),
                "relay_legacy_identity_listeners_active": len(legacy_listeners),
                "relay_destination_identity_exposure": bool(legacy_listeners),
                "relay_sessions_active": sum(
                    len(listener.sessions) for listener in relay_listeners
                ),
                "relay_sessions_reserved": sum(
                    listener.reserved_sessions for listener in relay_listeners
                ),
                "relay_session_teardowns_active": sum(
                    listener.teardown_count for listener in relay_listeners
                ),
                "relay_listeners_total": self.metrics.relay_listeners_total,
                "relay_listener_rejects_total": self.metrics.relay_listener_rejects_total,
                "relay_sessions_total": self.metrics.relay_sessions_total,
                "relay_session_rejects_total": self.metrics.relay_session_rejects_total,
                "relay_bytes_forwarded": self.metrics.relay_bytes_forwarded,
                "relay_forward_failures_total": self.metrics.relay_forward_failures_total,
                "relay_forward_overloads_total": self.metrics.relay_forward_overloads_total,
                "relay_forward_global_overloads_total": (
                    self.metrics.relay_forward_global_overloads_total
                ),
                "relay_forward_global_control_overloads_total": (
                    self.metrics.relay_forward_global_control_overloads_total
                ),
                "relay_forward_budget": self._relay_forward_budget.snapshot(),
                "relay_idle_expirations_total": self.metrics.relay_idle_expirations_total,
            }
        )

    # ─── relay (v0.5.5) ───────────────────────────────────────────

    @staticmethod
    def _relay_origin_rejection(request: web.Request) -> web.Response | None:
        """Block browser-initiated relay upgrades.

        One Link's native relay clients do not send Origin. Browsers do and
        cannot suppress it, so this closes cross-site drive-by quota abuse
        without pretending Origin authenticates a dedicated network client.
        """

        if "Origin" in request.headers:
            return web.Response(
                status=403,
                text="browser-origin relay upgrades are not accepted",
            )
        return None

    def _record_relay_global_overload(
        self,
        *,
        category: _RelayBudgetCategory,
    ) -> None:
        self.metrics.relay_forward_overloads_total += 1
        self.metrics.relay_forward_global_overloads_total += 1
        if category in {"control", "teardown"}:
            self.metrics.relay_forward_global_control_overloads_total += 1

    def _acquire_relay_payload(
        self,
        size: int,
        *,
        owner: object,
        category: _RelayBudgetCategory,
    ) -> _RelayBudgetLease:
        lease = self._relay_forward_budget.try_acquire(
            size,
            owner=owner,
            category=category,
        )
        if lease is None:
            self._record_relay_global_overload(category=category)
            raise _RelayGlobalBudgetOverload("process-wide relay forwarding byte budget exhausted")
        return lease

    async def _send_relay_json(
        self,
        ws: web.WebSocketResponse,
        message: dict[str, object],
        *,
        owner: object,
        category: Literal["control", "teardown"],
        operation: str,
    ) -> None:
        # ensure_ascii makes one Python character exactly one UTF-8 wire byte;
        # the reservation therefore equals the complete text-frame payload.
        text = json.dumps(
            message,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        if len(text) > CONTROL_FRAME_MAX_BYTES:
            raise ValueError("relay control message exceeds protocol ceiling")
        lease = self._acquire_relay_payload(
            len(text),
            owner=owner,
            category=category,
        )
        try:
            await self._relay_call_with_deadline(
                ws.send_str(text),
                operation=operation,
            )
        finally:
            lease.release()

    async def _send_relay_binary_control(
        self,
        ws: web.WebSocketResponse,
        frame: bytes,
        *,
        owner: object,
        operation: str,
    ) -> None:
        lease = self._acquire_relay_payload(
            len(frame),
            owner=owner,
            category="teardown",
        )
        try:
            await self._relay_call_with_deadline(
                ws.send_bytes(frame),
                operation=operation,
            )
        finally:
            lease.release()

    @staticmethod
    def _abort_relay_websocket(ws: web.WebSocketResponse) -> None:
        """Fail closed without allocating another application control frame."""

        request = getattr(ws, "_req", None)
        transport = getattr(request, "transport", None)
        if transport is not None:
            transport.abort()

    async def _close_relay_websocket(
        self,
        ws: web.WebSocketResponse,
        *,
        owner: object,
        code: int,
        message: bytes,
        operation: str,
    ) -> None:
        message = bytes(message[:120])
        try:
            lease = self._acquire_relay_payload(
                2 + len(message),
                owner=owner,
                category="teardown",
            )
        except _RelayGlobalBudgetOverload:
            self._abort_relay_websocket(ws)
            raise
        try:
            await self._relay_call_with_deadline(
                ws.close(code=code, message=message),
                operation=operation,
            )
        finally:
            lease.release()

    async def _handle_relay_listen(self, request: web.Request) -> web.StreamResponse:
        """Destination side of the relay.

        Flow:
          1. Open WebSocket.
          2. V2 requires a bounded route-set authorization: rotating,
             self-certifying tags signed by their epoch keys. V1 migration
             requires the historical identity-key ListenAuth. Bad auth closes
             with 4001.
          3. V2 atomically installs the opaque route set after ownership and
             capacity checks. V1 takes the identity-keyed slot and may replace
             its prior listener under the replacement limiter.
          4. Server now demuxes incoming connector sessions onto
             this WebSocket.

        Frames received from the listener:
          - binary: `[type][session_id][payload]`. type=DATA → forward
            payload to the connector for that session_id. type=CLOSE →
            terminate the session.
          - text: protocol error after the initial authentication message.

        Frames sent to the listener:
          - binary DATA frames from connectors (server prepends
            session_id so listener can demux).
          - text JSON: `{"t":"incoming","session_id":...}` when a new
            connector arrives.
          - text JSON: `{"t":"session_closed","session_id":...}` when
            a connector disconnects.
        """
        from one_link.relay_proto import (
            ListenAuth,
            timestamp_within_replay_window,
        )
        from one_link.relay_routing import ROUTE_AUTH_MAX_BYTES, RouteListenAuth

        blinded_route = request.path == "/api/v2/relay/listen"

        origin_rejection = self._relay_origin_rejection(request)
        if origin_rejection is not None:
            self.metrics.relay_listener_rejects_total += 1
            return origin_rejection

        ip = self._rate_identity(request)
        if not self.rate_per_ip.admit(ip):
            self.metrics.rate_limit_rejects_total += 1
            return web.Response(status=429, text="rate limited")

        ws = web.WebSocketResponse(
            max_msg_size=max(DATA_FRAME_MAX_BYTES + 64, CONTROL_FRAME_MAX_BYTES),
            heartbeat=_RELAY_WEBSOCKET_HEARTBEAT_S,
            compress=False,
        )
        await ws.prepare(request)

        # Step 2: read the auth blob with a strict deadline.
        try:
            first = await asyncio.wait_for(ws.receive(), timeout=10.0)
        except asyncio.TimeoutError:
            self.metrics.relay_listener_rejects_total += 1
            await ws.close(code=4002, message=b"auth timeout")
            return ws
        if first.type != aiohttp.WSMsgType.TEXT:
            self.metrics.relay_listener_rejects_total += 1
            await ws.close(code=4001, message=b"expected text auth")
            return ws
        auth_wire_limit = ROUTE_AUTH_MAX_BYTES if blinded_route else CONTROL_FRAME_MAX_BYTES
        if len(first.data.encode("utf-8")) > auth_wire_limit:
            self.metrics.relay_listener_rejects_total += 1
            await ws.close(code=4001, message=b"auth message too large")
            return ws
        try:
            auth_doc = bounded_json_loads(first.data)
            if not isinstance(auth_doc, dict):
                raise ValueError("relay listen auth must be an object")
            if blinded_route:
                route_auth = RouteListenAuth.from_wire(auth_doc)
                if auth_doc.get("t") != "route_listen_auth":
                    raise ValueError("initial route auth must not be a refresh")
                route_auth.verify()
                nonce_owner = route_auth.routes_digest
                auth_timestamp_ms = route_auth.timestamp_ms
                auth_nonce = route_auth.nonce
            else:
                auth = ListenAuth.from_wire(auth_doc)
                if not timestamp_within_replay_window(auth.timestamp_ms):
                    raise ValueError("timestamp out of window")
                auth.verify()
                nonce_owner = auth.pubkey
                auth_timestamp_ms = auth.timestamp_ms
                auth_nonce = auth.nonce
        except (json.JSONDecodeError, ValueError) as e:
            self.metrics.relay_listener_rejects_total += 1
            await ws.close(code=4001, message=f"bad auth: {e}".encode("utf-8")[:120])
            return ws
        if not self._admit_relay_listen_nonce(
            nonce_owner, auth_timestamp_ms, auth_nonce
        ):
            self.metrics.relay_listener_rejects_total += 1
            await ws.close(code=4001, message=b"replayed listen auth nonce")
            return ws

        # Step 3: claim listener slot, kicking any prior one.
        if blinded_route:
            listener = _RelayListener(
                pubkey=route_auth.routes[0].route_tag,
                ws=ws,
                routing_mode="pairwise_blinded_v1",
            )
            try:
                await self._install_blinded_listener_routes(listener, route_auth)
            except ValueError as exc:
                self.metrics.relay_listener_rejects_total += 1
                await ws.close(
                    code=4003,
                    message=str(exc).encode("utf-8")[:120],
                )
                return ws
        else:
            prior = self._relay_listeners.get(auth.pubkey)
            if prior is not None and prior.ws is not ws:
                # Legacy migration mode retains its identity-keyed takeover
                # limiter. New production clients never register this route.
                if not self.rate_listener_replace_per_pubkey.admit(auth.pubkey.hex()):
                    self.metrics.relay_listener_rejects_total += 1
                    await ws.close(
                        code=4003,
                        message=b"listener slot replacement rate-limited",
                    )
                    return ws
                with contextlib.suppress(Exception):
                    await self._close_relay_websocket(
                        prior.ws,
                        owner=prior.budget_owner,
                        code=4003,
                        message=b"replaced by newer listener",
                        operation="replaced relay listener WebSocket close",
                    )
                replacement_closes = [
                    self._schedule_relay_session_close(prior, sid)
                    for sid in list(prior.sessions)
                ]
                await asyncio.gather(
                    *(task for task in replacement_closes if task is not None),
                    return_exceptions=True,
                )
            listener = _RelayListener(
                pubkey=auth.pubkey,
                ws=ws,
                routing_keys={auth.pubkey},
            )
            self._relay_listeners[auth.pubkey] = listener
        self.metrics.relay_listeners_total += 1
        log.info("relay: authenticated %s listener registered", listener.routing_mode)

        # Step 4: forward demuxed traffic.
        try:
            async for msg in ws:
                if msg.type == aiohttp.WSMsgType.BINARY:
                    try:
                        frame_type, frame_session_id, payload_bytes = _relay_frame_metadata(
                            msg.data
                        )
                    except ValueError as e:
                        log.debug("relay: closing listener after invalid frame: %s", e)
                        with contextlib.suppress(Exception):
                            await self._close_relay_websocket(
                                ws,
                                owner=listener.budget_owner,
                                code=1002,
                                message=b"invalid relay frame",
                                operation="invalid relay listener close",
                            )
                        break
                    sess = listener.sessions.get(frame_session_id)
                    if sess is None or sess.closing:
                        # Session unknown — listener lagging behind; drop.
                        continue
                    try:
                        current_lease: _RelayBudgetLease | None = self._acquire_relay_payload(
                            len(msg.data),
                            owner=sess.budget_owner,
                            category="current",
                        )
                    except _RelayGlobalBudgetOverload:
                        self._schedule_relay_session_close(
                            listener,
                            frame_session_id,
                            code=4502,
                            message=b"relay process forwarding budget overloaded",
                        )
                        continue
                    try:
                        if frame_type == FRAME_DATA:
                            forwarder = sess.listener_to_connector
                            outcome: _RelayEnqueueOutcome = "local_overload"
                            if forwarder is not None:
                                outcome = forwarder.try_enqueue(
                                    msg.data,
                                    payload_bytes=payload_bytes,
                                    current_lease=current_lease,
                                )
                            if outcome == "accepted":
                                # Ownership moved atomically into the queue.
                                current_lease = None
                            else:
                                self.metrics.relay_forward_overloads_total += 1
                                if outcome == "global_overload":
                                    self.metrics.relay_forward_global_overloads_total += 1
                                self._schedule_relay_session_close(
                                    listener,
                                    frame_session_id,
                                    code=4502,
                                    message=b"relay session forward queue overloaded",
                                )
                        elif frame_type == FRAME_CLOSE:
                            forwarder = sess.listener_to_connector
                            if forwarder is None or not forwarder.finish():
                                self._schedule_relay_session_close(
                                    listener,
                                    frame_session_id,
                                )
                    finally:
                        if current_lease is not None:
                            current_lease.release()
                elif msg.type == aiohttp.WSMsgType.TEXT:
                    if listener.routing_mode != "pairwise_blinded_v1":
                        with contextlib.suppress(Exception):
                            await self._close_relay_websocket(
                                ws,
                                owner=listener.budget_owner,
                                code=1003,
                                message=b"unexpected relay text frame",
                                operation="unexpected relay listener text close",
                            )
                        break
                    try:
                        if len(msg.data.encode("utf-8")) > ROUTE_AUTH_MAX_BYTES:
                            raise ValueError("route refresh exceeds wire limit")
                        refresh_doc = bounded_json_loads(msg.data)
                        if (
                            not isinstance(refresh_doc, dict)
                            or refresh_doc.get("t") != "route_refresh"
                        ):
                            raise ValueError("expected route_refresh control frame")
                        refresh_auth = RouteListenAuth.from_wire(refresh_doc)
                        refresh_auth.verify()
                        if not self._admit_relay_listen_nonce(
                            refresh_auth.routes_digest,
                            refresh_auth.timestamp_ms,
                            refresh_auth.nonce,
                        ):
                            raise ValueError("replayed route refresh nonce")
                        await self._install_blinded_listener_routes(
                            listener, refresh_auth
                        )
                    except (json.JSONDecodeError, ValueError) as exc:
                        self.metrics.relay_listener_rejects_total += 1
                        with contextlib.suppress(Exception):
                            await self._close_relay_websocket(
                                ws,
                                owner=listener.budget_owner,
                                code=4001,
                                message=f"invalid route refresh: {exc}".encode("utf-8")[:120],
                                operation="invalid blinded relay refresh close",
                            )
                        break
                elif msg.type in (
                    aiohttp.WSMsgType.CLOSE,
                    aiohttp.WSMsgType.ERROR,
                    aiohttp.WSMsgType.CLOSED,
                ):
                    break
        finally:
            # Tear down all sessions tied to this listener.
            closes = [
                self._schedule_relay_session_close(listener, sid) for sid in list(listener.sessions)
            ]
            await asyncio.gather(
                *(task for task in closes if task is not None),
                return_exceptions=True,
            )
            # Unhook only keys still owned by this listener. A newer
            # authenticated replacement may already own an overlapping tag.
            self._unregister_relay_listener(listener)
        return ws

    async def _handle_relay_connect(self, request: web.Request) -> web.StreamResponse:
        """Source side of the relay.

        Flow:
          1. V2 URL specifies an opaque route tag and requires a fresh signed
             connector proof before session allocation. V1 migration embeds
             dst_pubkey_b64 and has no source-side route proof.
          2. Look up the corresponding listener slot. If absent, return 404.
          3. Allocate a new session_id and notify the listener with
             a text JSON `{"t":"incoming","session_id":...}`.
          4. Forward connector binary frames (already prefixed with
             type+session_id by the connector) to the listener
             verbatim.
          5. On connector close → send CLOSE frame to listener and
             clean up.
        """
        from one_link.relay_proto import (
            make_incoming_msg,
            make_ready_msg,
            new_session_id,
        )
        from one_link.relay_routing import RouteConnectAuth
        from one_link.rendezvous_proto import _b64d  # type: ignore

        blinded_route = "route_tag_b64" in request.match_info

        origin_rejection = self._relay_origin_rejection(request)
        if origin_rejection is not None:
            self.metrics.relay_session_rejects_total += 1
            return origin_rejection

        ip = self._rate_identity(request)
        # Two limiters: the global per-IP, and a connect-specific one.
        if not self.rate_per_ip.admit(ip) or not self.rate_relay_connect_per_ip.admit(ip):
            self.metrics.rate_limit_rejects_total += 1
            return web.Response(status=429, text="rate limited")

        try:
            route_field = "route_tag_b64" if blinded_route else "dst_pubkey_b64"
            routing_key = _b64d(
                request.match_info[route_field],
                expected_size=32,
                name=route_field,
            )
        except ValueError:
            return web.Response(status=400, text="invalid relay route")

        listener = self._relay_listeners.get(routing_key)
        if listener is None:
            self.metrics.relay_session_rejects_total += 1
            return web.Response(status=404, text="destination not listening")
        if blinded_route:
            route_expiry = listener.route_expiries_ms.get(routing_key)
            route_auth_public = listener.route_auth_pubs.get(routing_key)
            if (
                listener.routing_mode != "pairwise_blinded_v1"
                or route_expiry is None
                or route_auth_public is None
                or route_expiry <= now_ms()
            ):
                if self._relay_listeners.get(routing_key) is listener:
                    self._relay_listeners.pop(routing_key, None)
                listener.routing_keys.discard(routing_key)
                listener.route_expiries_ms.pop(routing_key, None)
                listener.route_auth_pubs.pop(routing_key, None)
                self.metrics.relay_session_rejects_total += 1
                return web.Response(status=404, text="blinded relay route expired")
        if (
            len(listener.sessions) + listener.reserved_sessions + listener.teardown_count
            >= self.config.relay_max_sessions_per_listener
        ):
            self.metrics.relay_session_rejects_total += 1
            return web.Response(status=503, text="listener at session cap")

        # Reserve before the WebSocket upgrade. ws.prepare() awaits and can
        # admit arbitrarily many concurrent request tasks unless in-flight
        # upgrades count against the same cap as established sessions.
        listener.reserved_sessions += 1
        reservation_held = True

        ws = web.WebSocketResponse(
            max_msg_size=DATA_FRAME_MAX_BYTES + 64,
            heartbeat=_RELAY_WEBSOCKET_HEARTBEAT_S,
            compress=False,
        )
        try:
            await ws.prepare(request)
            if self._relay_listeners.get(routing_key) is not listener or listener.ws.closed:
                self.metrics.relay_session_rejects_total += 1
                with contextlib.suppress(Exception):
                    await self._close_relay_websocket(
                        ws,
                        owner=listener.budget_owner,
                        code=4040,
                        message=b"destination listener changed",
                        operation="stale relay connector WebSocket close",
                    )
                return ws

            if blinded_route:
                try:
                    proof_msg = await asyncio.wait_for(
                        ws.receive(), timeout=_RELAY_AUTH_TIMEOUT_S
                    )
                    if proof_msg.type != aiohttp.WSMsgType.TEXT:
                        raise ValueError("expected blinded connector text proof")
                    if len(proof_msg.data.encode("utf-8")) > CONTROL_FRAME_MAX_BYTES:
                        raise ValueError("blinded connector proof exceeds wire limit")
                    proof = RouteConnectAuth.from_wire(
                        bounded_json_loads(proof_msg.data)
                    )
                    if route_auth_public is None or route_expiry is None:
                        raise ValueError("blinded route authority disappeared")
                    proof.verify(
                        expected_route_tag=routing_key,
                        expected_auth_public=route_auth_public,
                        expires_at_ms=route_expiry,
                    )
                    if not self._admit_relay_listen_nonce(
                        routing_key, proof.timestamp_ms, proof.nonce
                    ):
                        raise ValueError("replayed blinded connector nonce")
                except (asyncio.TimeoutError, json.JSONDecodeError, ValueError) as exc:
                    self.metrics.relay_session_rejects_total += 1
                    with contextlib.suppress(Exception):
                        await self._close_relay_websocket(
                            ws,
                            owner=listener.budget_owner,
                            code=4001,
                            message=f"invalid connector proof: {exc}".encode("utf-8")[:120],
                            operation="invalid blinded relay connector close",
                        )
                    return ws

            sid = new_session_id()
            while sid in listener.sessions:
                sid = new_session_id()
            sess = _RelaySession(
                session_id=sid,
                listener_pubkey=routing_key,
                connector_ws=ws,
                listener_ws=listener.ws,
            )
            listener.sessions[sid] = sess
            listener.reserved_sessions -= 1
            reservation_held = False
        finally:
            if reservation_held:
                listener.reserved_sessions -= 1

        def _forward_completed(payload_bytes: int) -> None:
            if listener.sessions.get(sid) is sess and not sess.closing:
                sess.last_activity_at = time.monotonic()
                self.metrics.relay_bytes_forwarded += payload_bytes

        async def _send_to_connector(frame_bytes: bytes) -> None:
            await sess.connector_ws.send_bytes(frame_bytes)

        forwarder = _RelayForwardQueue(
            _send_to_connector,
            timeout_s=self.config.relay_forward_timeout_s,
            buffer_limit_bytes=self.config.relay_forward_queue_limit_bytes,
            queue_max_items=self.config.relay_forward_queue_max_items,
            on_sent=_forward_completed,
            process_budget=self._relay_forward_budget,
            budget_owner=sess.budget_owner,
        )
        sess.listener_to_connector = forwarder

        def _forwarder_done(completed: asyncio.Task[None]) -> None:
            if sess.closing or listener.sessions.get(sid) is not sess:
                return
            if completed.cancelled():
                self._schedule_relay_session_close(
                    listener,
                    sid,
                    code=4501,
                    message=b"relay forward worker cancelled",
                )
                return
            error = completed.exception()
            if error is not None:
                self.metrics.relay_forward_failures_total += 1
                log.warning(
                    "relay: listener-to-connector forward failed: %s",
                    error,
                )
                self._schedule_relay_session_close(
                    listener,
                    sid,
                    code=4501,
                    message=b"relay forwarding failed",
                )
                return
            # Ordered CLOSE sentinel drained after every preceding DATA.
            self._schedule_relay_session_close(listener, sid)

        forwarder.task.add_done_callback(_forwarder_done)
        self.metrics.relay_sessions_total += 1

        # Tell both sides the session is open.
        try:
            await self._send_relay_json(
                ws,
                make_ready_msg(sid),
                owner=sess.budget_owner,
                category="control",
                operation="relay ready signal",
            )
            # READY must be ordered before INCOMING. Once the listener sees
            # INCOMING it may immediately emit DATA; sending READY first
            # guarantees the connector's handshake control remains its first
            # WebSocket message even under adversarial scheduling.
            await self._send_relay_json(
                listener.ws,
                make_incoming_msg(sid),
                owner=sess.budget_owner,
                category="control",
                operation="relay incoming signal",
            )
        except Exception:
            await self._close_relay_session(
                listener,
                sid,
                code=4500,
                message=b"could not signal both sides",
            )
            return ws

        close_code = 1000
        close_message = b"session closed"
        try:
            while True:
                # A listener→connector frame can refresh last_activity_at
                # while this task is waiting.  Re-check after timeout before
                # expiring so active one-way downloads are never killed.
                remaining = self.config.relay_session_idle_s - (
                    time.monotonic() - sess.last_activity_at
                )
                if remaining <= 0:
                    self.metrics.relay_idle_expirations_total += 1
                    close_code = 4008
                    close_message = b"relay session idle timeout"
                    break
                try:
                    msg = await asyncio.wait_for(ws.receive(), timeout=remaining)
                except asyncio.TimeoutError:
                    if time.monotonic() - sess.last_activity_at >= self.config.relay_session_idle_s:
                        self.metrics.relay_idle_expirations_total += 1
                        close_code = 4008
                        close_message = b"relay session idle timeout"
                        break
                    continue
                if msg.type == aiohttp.WSMsgType.BINARY:
                    try:
                        frame_type, _claimed_session_id, payload_bytes = _relay_frame_metadata(
                            msg.data
                        )
                    except ValueError as e:
                        log.debug("relay: closing connector after invalid frame: %s", e)
                        close_code = 1002
                        close_message = b"invalid relay frame"
                        break
                    try:
                        incoming_lease = self._acquire_relay_payload(
                            len(msg.data),
                            owner=sess.budget_owner,
                            category="current",
                        )
                    except _RelayGlobalBudgetOverload:
                        close_code = 4502
                        close_message = b"relay process forwarding budget overloaded"
                        break
                    outgoing_lease: _RelayBudgetLease | None = None
                    try:
                        try:
                            outgoing_lease = self._acquire_relay_payload(
                                len(msg.data),
                                owner=sess.budget_owner,
                                category="current",
                            )
                        except _RelayGlobalBudgetOverload:
                            close_code = 4502
                            close_message = b"relay process forwarding budget overloaded"
                            break

                        # Force the server-allocated session id without making
                        # a second payload slice.  The bytearray allocation is
                        # made only after its exact lease was acquired.
                        forwarded = bytearray(msg.data)
                        forwarded[0] = frame_type
                        forwarded[1 : 1 + SESSION_ID_BYTES] = sid
                        try:
                            await self._relay_call_with_deadline(
                                # aiohttp accepts bytearray at runtime (and
                                # forwards it without an additional payload
                                # allocation), although its public annotation
                                # is narrower than that runtime contract.
                                listener.ws.send_bytes(cast(bytes, forwarded)),
                                operation="connector-to-listener forward",
                            )
                        except Exception as exc:
                            self.metrics.relay_forward_failures_total += 1
                            log.warning(
                                "relay: connector-to-listener forward failed: %s",
                                exc,
                            )
                            close_code = 4501
                            close_message = b"relay forwarding failed"
                            # A failed/timeout send on the shared listener WS
                            # leaves every multiplexed session's wire outcome
                            # uncertain. Close this session first (which closes
                            # the connector concurrently with its listener
                            # notification), then retire the listener socket so
                            # it reconnects cleanly.
                            await self._close_relay_session(
                                listener,
                                sid,
                                code=close_code,
                                message=close_message,
                            )
                            with contextlib.suppress(Exception):
                                await self._close_relay_websocket(
                                    listener.ws,
                                    owner=sess.budget_owner,
                                    code=4501,
                                    message=b"relay listener forwarding failed",
                                    operation="failed relay listener WebSocket close",
                                )
                            break
                        sess.last_activity_at = time.monotonic()
                        if frame_type == FRAME_DATA:
                            self.metrics.relay_bytes_forwarded += payload_bytes
                        if frame_type == FRAME_CLOSE:
                            break
                    finally:
                        if outgoing_lease is not None:
                            outgoing_lease.release()
                        incoming_lease.release()
                elif msg.type == aiohttp.WSMsgType.TEXT:
                    close_code = 1003
                    close_message = b"unexpected relay text frame"
                    break
                elif msg.type in (
                    aiohttp.WSMsgType.CLOSE,
                    aiohttp.WSMsgType.ERROR,
                    aiohttp.WSMsgType.CLOSED,
                ):
                    break
        finally:
            await self._close_relay_session(
                listener,
                sid,
                code=close_code,
                message=close_message,
            )
        return ws

    async def _relay_call_with_deadline(
        self,
        awaitable: Awaitable[object],
        *,
        operation: str,
    ) -> object:
        """Await one relay WS operation under the configured deadline."""
        try:
            return await asyncio.wait_for(
                awaitable,
                timeout=self.config.relay_forward_timeout_s,
            )
        except asyncio.TimeoutError as exc:
            raise TimeoutError(
                f"{operation} exceeded {self.config.relay_forward_timeout_s:.3f}s"
            ) from exc

    def _schedule_relay_session_close(
        self,
        listener: _RelayListener,
        session_id: bytes,
        *,
        code: int = 1000,
        message: bytes = b"session closed",
    ) -> asyncio.Task[None] | None:
        """Start at most one off-loop teardown task for a relay session."""
        sess = listener.sessions.get(session_id)
        if sess is None:
            return None
        if sess.closing:
            return sess.close_task
        sess.closing = True
        task = asyncio.create_task(
            self._close_relay_session(
                listener,
                session_id,
                code=code,
                message=message,
            )
        )
        sess.close_task = task
        self._relay_teardown_tasks.add(task)

        def _done(completed: asyncio.Task[None]) -> None:
            self._relay_teardown_tasks.discard(completed)
            if sess.close_task is completed:
                sess.close_task = None
            if completed.cancelled():
                return
            error = completed.exception()
            if error is not None:
                log.warning("relay session teardown failed: %s", error)

        task.add_done_callback(_done)
        return task

    async def _close_relay_session(
        self,
        listener: _RelayListener,
        session_id: bytes,
        *,
        code: int = 1000,
        message: bytes = b"session closed",
    ) -> None:
        """Tear down a session: notify both sides, drop state."""
        sess = listener.sessions.pop(session_id, None)
        if sess is None:
            return
        # The popped session still owns a handler, queue worker, connector,
        # and bounded network deadlines. Count it against admission until all
        # of those resources are actually released; otherwise rapid churn can
        # accumulate arbitrarily many teardown tasks behind a nominal cap.
        listener.teardown_count += 1
        try:
            sess.closing = True
            if sess.listener_to_connector is not None:
                await sess.listener_to_connector.abort()
            from one_link.relay_proto import (
                encode_close_frame,
                make_session_closed_msg,
            )

            async def _notify_listener() -> None:
                # Text JSON keeps listener-side demultiplexing unambiguous.
                with contextlib.suppress(Exception):
                    await self._send_relay_json(
                        listener.ws,
                        make_session_closed_msg(session_id),
                        owner=sess.budget_owner,
                        category="teardown",
                        operation="relay listener close notification",
                    )

            async def _close_connector() -> None:
                try:
                    with contextlib.suppress(Exception):
                        await self._send_relay_binary_control(
                            sess.connector_ws,
                            encode_close_frame(session_id),
                            owner=sess.budget_owner,
                            operation="relay connector close frame",
                        )
                finally:
                    with contextlib.suppress(Exception):
                        await self._close_relay_websocket(
                            sess.connector_ws,
                            owner=sess.budget_owner,
                            code=code,
                            message=message,
                            operation="relay connector WebSocket close",
                        )

            # Notify both sides concurrently. A dead listener must never
            # delay closing the connector (or vice versa) for a full deadline.
            await asyncio.gather(_notify_listener(), _close_connector())
        finally:
            listener.teardown_count -= 1


# ─── CLI entrypoint ─────────────────────────────────────────────────


def _read_metrics_token_file(path_value: str) -> str:
    path = Path(path_value)
    try:
        before = path.lstat()
    except OSError as exc:
        raise ValueError(f"cannot stat metrics token file: {exc}") from exc
    if path.is_symlink() or not stat.S_ISREG(before.st_mode):
        raise ValueError("metrics token file must be a regular non-symlink file")
    if before.st_size <= 0 or before.st_size > 4097:
        raise ValueError("metrics token file must contain at most 4096 bytes")
    flags = os.O_RDONLY | int(getattr(os, "O_NOFOLLOW", 0))
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != before.st_dev
            or opened.st_ino != before.st_ino
            or opened.st_size != before.st_size
        ):
            raise ValueError("metrics token file changed identity while opening")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            raw = handle.read(4098)
        after = os.fstat(fd)
        if len(raw) > 4097 or len(raw) != opened.st_size:
            raise ValueError("metrics token file changed size while reading")
        if (
            after.st_dev != opened.st_dev
            or after.st_ino != opened.st_ino
            or after.st_size != opened.st_size
            or after.st_mtime_ns != opened.st_mtime_ns
        ):
            raise ValueError("metrics token file changed while reading")
    finally:
        os.close(fd)
    token_raw = raw[:-2] if raw.endswith(b"\r\n") else (raw[:-1] if raw.endswith(b"\n") else raw)
    if b"\r" in token_raw or b"\n" in token_raw:
        raise ValueError("metrics token file must contain exactly one token")
    try:
        token = token_raw.decode("utf-8", "strict")
    except UnicodeError as exc:
        raise ValueError("metrics token file must be valid UTF-8") from exc
    return token


def _parse_args(argv: Optional[list[str]] = None) -> ServerConfig:
    p = argparse.ArgumentParser(description="One Link rendezvous server")
    p.add_argument("--host", default="0.0.0.0")  # nosec B104
    p.add_argument("--port", type=int, default=7118)
    p.add_argument(
        "--max-registrations",
        type=int,
        default=_DEFAULT_MAX_REGISTRATIONS,
    )
    p.add_argument(
        "--max-attacker-state-keys",
        type=int,
        default=_DEFAULT_MAX_ATTACKER_STATE_KEYS,
        help="per-map cap for attacker-controlled IP/pubkey/nonce/replay keys",
    )
    p.add_argument("--rate-per-ip-per-min", type=int, default=120)
    p.add_argument("--rate-register-per-pubkey-per-min", type=int, default=30)
    p.add_argument(
        "--enable-relay",
        action="store_true",
        help="enable encrypted relay endpoints (uses more bandwidth)",
    )
    p.add_argument(
        "--relay-connect-per-ip-per-min",
        type=int,
        default=60,
        help="rate limit on relay connect attempts per source IP",
    )
    p.add_argument(
        "--relay-max-sessions-per-listener",
        type=int,
        default=32,
        help="max concurrent sessions one listener can multiplex",
    )
    p.add_argument(
        "--relay-max-route-keys",
        type=int,
        default=_DEFAULT_RELAY_ROUTE_KEYS,
        help="global cap on blinded relay route tags across all listeners",
    )
    p.add_argument(
        "--relay-session-idle-s",
        type=float,
        default=300.0,
        help="close a relay session after this many seconds with no traffic",
    )
    p.add_argument(
        "--relay-forward-timeout-s",
        type=float,
        default=30.0,
        help="deadline for each WebSocket forward/send operation",
    )
    p.add_argument(
        "--relay-forward-queue-limit-bytes",
        type=int,
        default=4 * (1024 * 1024 + 9),
        help="per-session listener-to-connector queued-byte ceiling",
    )
    p.add_argument(
        "--relay-forward-queue-max-items",
        type=int,
        default=64,
        help="per-session listener-to-connector queue item ceiling",
    )
    p.add_argument(
        "--relay-forward-global-budget-bytes",
        type=int,
        default=_RELAY_FORWARD_GLOBAL_BUDGET_BYTES,
        help="process-wide relay forwarding payload-memory ceiling",
    )
    p.add_argument(
        "--relay-forward-control-reserve-bytes",
        type=int,
        default=_RELAY_FORWARD_CONTROL_RESERVE_BYTES,
        help="global relay budget tail reserved for control and teardown",
    )
    p.add_argument(
        "--trust-proxy-headers",
        action="store_true",
        help="trust X-Forwarded-For from a controlled reverse proxy",
    )
    # v0.20.7 (security audit Bundle 2):
    p.add_argument(
        "--rate-lookup-per-ip-per-min",
        type=int,
        default=30,
        help="lookup-specific per-IP rate (separate from global)",
    )
    p.add_argument(
        "--rate-new-pubkey-register-per-ip-per-min",
        type=int,
        default=10,
        help="per-IP cap on NEW-pubkey registrations (anti registry-flush)",
    )
    p.add_argument(
        "--rate-listener-replace-per-pubkey-per-min",
        type=int,
        default=2,
        help="per-pubkey cap on relay listener slot replacements",
    )
    p.add_argument(
        "--max-concurrent-connections",
        type=int,
        default=_DEFAULT_MAX_CONCURRENT_CONNECTIONS,
        help="finite global cap on in-flight HTTP and WebSocket handlers",
    )
    p.add_argument(
        "--max-concurrent-per-source",
        type=int,
        default=_DEFAULT_MAX_CONCURRENT_PER_SOURCE,
        help="how many of those handlers one source address may hold at a time",
    )
    p.add_argument(
        "--memory-budget-bytes",
        type=int,
        default=_DEFAULT_PROCESS_MEMORY_BUDGET_BYTES,
        help=(
            "declared process/container memory envelope; startup fails if the "
            "configured attacker-state, connection, and relay ceilings exceed it"
        ),
    )
    metrics_group = p.add_mutually_exclusive_group()
    metrics_group.add_argument(
        "--metrics-token",
        type=str,
        default=None,
        help="Bearer secret for private /metrics access (prefer --metrics-token-file)",
    )
    metrics_group.add_argument(
        "--metrics-token-file",
        type=str,
        default=None,
        help="read the /metrics Bearer secret from a bounded regular file",
    )
    p.add_argument(
        "--log-level",
        default="INFO",
        choices=("DEBUG", "INFO", "WARNING", "ERROR"),
    )
    args = p.parse_args(argv)
    metrics_token = args.metrics_token
    if args.metrics_token_file:
        try:
            metrics_token = _read_metrics_token_file(args.metrics_token_file)
        except ValueError as exc:
            p.error(str(exc))
    config = ServerConfig(
        host=args.host,
        port=args.port,
        max_registrations=args.max_registrations,
        max_attacker_state_keys=args.max_attacker_state_keys,
        rate_per_ip_per_min=args.rate_per_ip_per_min,
        rate_register_per_pubkey_per_min=args.rate_register_per_pubkey_per_min,
        enable_relay=args.enable_relay,
        relay_connect_per_ip_per_min=args.relay_connect_per_ip_per_min,
        relay_max_sessions_per_listener=args.relay_max_sessions_per_listener,
        relay_max_route_keys=args.relay_max_route_keys,
        relay_session_idle_s=args.relay_session_idle_s,
        relay_forward_timeout_s=args.relay_forward_timeout_s,
        relay_forward_queue_limit_bytes=args.relay_forward_queue_limit_bytes,
        relay_forward_queue_max_items=args.relay_forward_queue_max_items,
        relay_forward_global_budget_bytes=args.relay_forward_global_budget_bytes,
        relay_forward_control_reserve_bytes=args.relay_forward_control_reserve_bytes,
        trust_proxy_headers=args.trust_proxy_headers,
        rate_lookup_per_ip_per_min=args.rate_lookup_per_ip_per_min,
        rate_new_pubkey_register_per_ip_per_min=args.rate_new_pubkey_register_per_ip_per_min,
        rate_listener_replace_per_pubkey_per_min=args.rate_listener_replace_per_pubkey_per_min,
        max_concurrent_connections=args.max_concurrent_connections,
        max_concurrent_per_source=args.max_concurrent_per_source,
        memory_budget_bytes=args.memory_budget_bytes,
        metrics_token=metrics_token,
    )
    try:
        _validate_server_config(config)
    except ValueError as exc:
        p.error(str(exc))
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    return config


async def _serve_forever(config: ServerConfig) -> None:
    rdz = RendezvousApp(config)
    app = rdz.make_app()
    # aiohttp's default AccessLogger records the raw request target. Rendezvous
    # lookup paths carry public keys and blinded discovery tokens, so the
    # service must never enable that logger accidentally at INFO level. All
    # application logging above uses canonical route templates instead.
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, host=config.host, port=config.port)
    await site.start()
    log.info("rendezvous listening on %s:%d", config.host, config.port)

    stop = asyncio.Event()

    def _stop_handler():
        log.info("shutdown signal received")
        stop.set()

    loop = asyncio.get_running_loop()
    for sig in (getattr(signal, "SIGTERM", None), getattr(signal, "SIGINT", None)):
        if sig is not None:
            try:
                loop.add_signal_handler(sig, _stop_handler)
            except NotImplementedError:
                # Windows: signal handlers via add_signal_handler aren't
                # supported. Fall back to default handlers; KeyboardInterrupt
                # will propagate via asyncio.run.
                pass

    try:
        await stop.wait()
    finally:
        await runner.cleanup()


def main(argv: Optional[list[str]] = None) -> int:
    config = _parse_args(argv)
    try:
        asyncio.run(_serve_forever(config))
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
