"""mDNS peer discovery using zeroconf (async).

Each daemon advertises a `_onelink._tcp.local.` service whose name is the
device's short_id. TXT record carries the full Ed25519 public-key hex so
peers can pin identity at first contact.

Browsing returns a live registry of known peers keyed by short_id.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import errno
import ipaddress
import logging
import os
import socket
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Callable

from one_link.fault_observability import report_best_effort_failure
from one_link.platform_guard import install_windows_platform_fastpath

if TYPE_CHECKING:
    # zeroconf is imported lazily off the event loop; surface the
    # type names to the type checker so module-level annotations
    # resolve without paying the runtime import cost.
    from zeroconf.asyncio import (
        AsyncServiceBrowser,
        AsyncServiceInfo,
        AsyncZeroconf,
    )

_DEFAULT_SERVICE_TYPE = "_onelink._tcp.local."


def _resolve_service_type() -> str:
    """The mDNS service type this daemon advertises + browses.

    Defaults to ``_onelink._tcp.local.`` so every real install shares one
    discovery namespace. ONE_LINK_MDNS_SERVICE_TYPE overrides it, which
    lets an isolated cohort (a test swarm, or a private "household" that
    doesn't want to cross-discover other One Link daemons on the same
    LAN) advertise + browse a private scope. Both the register and the
    browse side read this same value, so an overriding daemon only ever
    sees peers on its own type.

    The override must be a valid DNS-SD type: the application-protocol
    label (between the leading underscore and ``._tcp``) is capped at 15
    chars by RFC 6335, so an out-of-spec value silently falls back to
    the default rather than breaking discovery entirely.
    """
    raw = (os.environ.get("ONE_LINK_MDNS_SERVICE_TYPE") or "").strip()
    if not raw:
        return _DEFAULT_SERVICE_TYPE
    if not raw.endswith("._tcp.local.") or not raw.startswith("_"):
        return _DEFAULT_SERVICE_TYPE
    proto_label = raw[1:].split(".", 1)[0]  # between leading "_" and "._tcp"
    if not (1 <= len(proto_label) <= 15) or not proto_label.replace("-", "").isalnum():
        return _DEFAULT_SERVICE_TYPE
    return raw


# Resolved once at import. Daemons are spawned as fresh processes, so a
# subprocess that sets ONE_LINK_MDNS_SERVICE_TYPE picks it up here.
SERVICE_TYPE = _resolve_service_type()
ZEROCONF_IMPORT_TIMEOUT_S = 3.0

# Per-interface send failures that mean "this NIC cannot carry mDNS right
# now" -- a VPN that just dropped, a virtual/VM interface with no route, a
# laptop between networks. One Link handles all of them: it keeps announcing
# on the interfaces that do work.
_UNREACHABLE_INTERFACE_ERRNOS = frozenset(
    getattr(errno, name)
    for name in ("EHOSTUNREACH", "ENETUNREACH", "ENETDOWN", "EADDRNOTAVAIL")
    if hasattr(errno, name)
)


class _QuietUnreachableInterfaceFilter(logging.Filter):
    """Keep zeroconf's per-interface send warnings; drop their tracebacks.

    zeroconf logs these with ``exc_info``, so a routine condition prints a
    full ``Traceback (most recent call last)`` into the user's daemon log.
    That is alarming for something One Link has already handled, and it is
    not only cosmetic: the release gate that scans a frozen daemon's log for
    tracebacks reads it as a crash, so a CI host with one unroutable virtual
    interface fails a build in which nothing actually went wrong.

    The record is NOT suppressed. The warning still says which socket and
    address failed and why -- only the stack, which describes zeroconf's
    internals rather than anything actionable, is removed.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        exc_info = record.exc_info
        if not exc_info:
            return True
        exc = exc_info[1]
        if isinstance(exc, OSError) and exc.errno in _UNREACHABLE_INTERFACE_ERRNOS:
            record.exc_info = None
            record.exc_text = None
        return True


def _quiet_zeroconf_unreachable_interfaces() -> None:
    """Install the filter once on the zeroconf logger.

    Attaching to ``zeroconf`` alone is sufficient, and that is a fact about
    the library rather than an assumption: every module in the package calls
    ``getLogger(__name__.split(".", maxsplit=1)[0])``, so they all emit
    through this one logger and no child loggers exist. The distinction
    matters -- a filter on a logger is NOT consulted for records emitted by
    its descendants, so if zeroconf ever logged through ``zeroconf.asyncio``
    this would silently stop working.
    """
    zc_log = logging.getLogger("zeroconf")
    for existing in zc_log.filters:
        if isinstance(existing, _QuietUnreachableInterfaceFilter):
            return
    zc_log.addFilter(_QuietUnreachableInterfaceFilter())

log = logging.getLogger("one_link.discovery")


def _load_zeroconf_modules():
    """Import zeroconf off the event loop.

    On Windows, zeroconf -> ifaddr/aiohttp dependencies can query WMI via
    platform.* during import. If WMI is unhealthy, that import can hang before
    One Link even publishes its control socket. Running it in a worker with a
    timeout lets the daemon stay useful even when mDNS is unavailable.
    """
    install_windows_platform_fastpath()

    from zeroconf import IPVersion
    from zeroconf.asyncio import (
        AsyncServiceBrowser,
        AsyncServiceInfo,
        AsyncZeroconf,
    )

    return IPVersion, AsyncServiceBrowser, AsyncServiceInfo, AsyncZeroconf


def _valid_pub_hex(value: str) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


@dataclass
class Peer:
    short_id: str
    hostname: str
    address: str
    port: int
    ed_pub_hex: str
    # v0.5.4: rendezvous URLs the peer is advertising via mDNS TXT.
    # Other daemons on the same Wi-Fi pick this up so a household
    # only needs ONE device to know about a rendezvous — the rest
    # auto-discover. Stored as a list of strings; never None
    # (empty list when the peer didn't advertise any).
    rendezvous_urls: list[str] = field(default_factory=list)
    # v0.7.3: compact `<os>-<kind>` device tag advertised by the peer
    # (e.g. "macos-laptop", "windows-desktop", "linux-server"). Empty
    # when the peer is on a pre-v0.7.3 build that didn't advertise.
    device_kind: str = ""


@dataclass
class Registry:
    peers: dict[str, Peer] = field(default_factory=dict)
    on_change: Callable[[], None] | None = None
    self_ed_pub_hex: str = ""
    local_addresses: set[str] = field(default_factory=set)
    # v0.20.7 (security audit L1): predicate that tells the registry
    # whether an existing pubkey is "trusted" (pinned via SAS pair).
    # If set and an upsert would swap the pub-hex for an existing
    # short_id from a trusted-pubkey to a different one, the swap is
    # refused and an audit warning is logged. Daemon installs this
    # at startup so the registry can defend against an mDNS attacker
    # who advertises a victim's short_id with a different pub.
    is_pinned_pubkey: Callable[[str], bool] | None = None

    def upsert(self, peer: Peer) -> None:
        if not _valid_pub_hex(peer.ed_pub_hex):
            self.peers.pop(peer.short_id, None)
            return
        # Some mDNS stacks can echo our own service under a changed name after
        # restarts. The public key is the durable identity; never list our own
        # key as a peer just because the service name differs.
        if self.self_ed_pub_hex and peer.ed_pub_hex == self.self_ed_pub_hex:
            self.peers.pop(peer.short_id, None)
            return
        if peer.address in self.local_addresses:
            self.peers.pop(peer.short_id, None)
            return
        # v0.20.7 (security audit L1): refuse a swap of the pub-hex
        # for an existing short_id when the existing pub is already
        # pinned. Without this, a LAN attacker who advertises the
        # victim's short_id with a different pub silently replaces
        # the registry entry; the channel-handshake key-pinning then
        # blocks impersonation, but the UI may still surface the
        # attacker's pub during pair-flow display.
        existing = self.peers.get(peer.short_id)
        if (
            existing is not None
            and existing.ed_pub_hex
            and peer.ed_pub_hex
            and existing.ed_pub_hex != peer.ed_pub_hex
            and self.is_pinned_pubkey is not None
        ):
            try:
                if self.is_pinned_pubkey(existing.ed_pub_hex):
                    log.warning(
                        "discovery: refusing pub-hex swap for short_id=%s "
                        "(existing pub is pinned)",
                        peer.short_id,
                    )
                    return
            except Exception as exc:
                # This predicate is the security boundary that prevents an
                # mDNS advertiser from replacing a paired identity. If the
                # trust lookup is unavailable, retain the known entry and
                # retry on the next advertisement.
                log.error(
                    "discovery: pinned-key lookup failed for short_id=%s; "
                    "refusing pub-hex swap (fail-closed): %s",
                    peer.short_id,
                    exc,
                )
                return
        # mDNS can briefly surface multiple service names for the same device
        # after restarts. The public key is the durable identity; keep the
        # newest advertisement and remove older aliases so the UI does not
        # fill with duplicates.
        if peer.ed_pub_hex:
            for sid, existing in list(self.peers.items()):
                if sid != peer.short_id and existing.ed_pub_hex == peer.ed_pub_hex:
                    self.peers.pop(sid, None)
        self.peers[peer.short_id] = peer
        if self.on_change:
            self.on_change()

    def remove(self, short_id: str) -> None:
        if self.peers.pop(short_id, None) is not None and self.on_change:
            self.on_change()

    def find(self, needle: str) -> Peer | None:
        """Resolve ``needle`` to one peer, or ``None``.

        A short-ID prefix that fits more than one device is refused rather
        than resolved to whichever device was registered first. Use
        :meth:`candidates` to see every match.
        """
        matches = self.candidates(needle)
        if not matches:
            return None
        if needle not in self.peers:
            by_prefix = sum(1 for p in matches if p.short_id.startswith(needle))
            if by_prefix > 1:
                return None
        return matches[0]

    def candidates(self, needle: str) -> list[Peer]:
        """Return peer matches in safest order.

        Short IDs are stable and unambiguous, so exact/prefix identity matches
        beat hostname matches. Hostnames are human-friendly but many devices on
        one test machine share the same name, and stale mDNS records can linger.
        """
        if not needle:
            return []
        if needle in self.peers:
            return [self.peers[needle]]

        lowered = needle.lower()
        seen: set[str] = set()
        out: list[Peer] = []
        for p in self.peers.values():
            if p.short_id.startswith(needle):
                out.append(p)
                seen.add(p.short_id)
        for p in self.peers.values():
            if p.short_id in seen:
                continue
            if p.hostname.lower() == lowered:
                out.append(p)
                seen.add(p.short_id)
        return out

    def list(self) -> list[Peer]:
        return sorted(self.peers.values(), key=lambda p: p.hostname)


def _is_lan_safe_address(addr: str) -> bool:
    """v0.20.7 (security audit H5): refuse mDNS announcements whose
    advertised address is not a private / link-local / loopback IPv4.

    mDNS (RFC 6762) is link-local-only by spec, so a record that
    points at a public IP is either misconfigured or a steering
    attack. Without this check, a LAN attacker can advertise
    `_onelink._tcp.local.` with any public IP and our outbound
    dial / TCP-probe traffic gets redirected to that host. The
    channel handshake's mutual auth catches impersonation, but a
    pure DoS / outbound-traffic-redirector primitive remains.
    """
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return bool(ip.is_private or ip.is_link_local or ip.is_loopback)


def _info_to_peer(info: AsyncServiceInfo, self_short_id: str) -> Peer | None:
    if not info.addresses:
        return None
    addr = socket.inet_ntoa(info.addresses[0])
    if not _is_lan_safe_address(addr):
        log.debug(
            "mDNS: rejecting non-LAN address %s for service %s",
            addr, info.name,
        )
        return None
    props = {
        (k.decode() if isinstance(k, bytes) else k): (
            v.decode() if isinstance(v, bytes) else v
        )
        for k, v in (info.properties or {}).items()
    }
    short_id = props.get("sid") or info.name.split(".", 1)[0]
    if short_id == self_short_id:
        return None
    pub = props.get("pub", "") or ""
    if not _valid_pub_hex(pub):
        return None
    server = info.server.rstrip(".") if info.server else "?"
    # v0.5.4: parse "rdz" TXT field — comma-separated rendezvous URLs.
    # Limit to a small count to keep TXT records bounded and resist
    # malicious peers spamming junk URLs into the mDNS scope.
    rdz_raw = props.get("rdz") or ""
    rdz_urls: list[str] = []
    if rdz_raw:
        for u in rdz_raw.split(","):
            u = u.strip().rstrip("/")
            if u and (u.startswith("http://") or u.startswith("https://")):
                rdz_urls.append(u)
                if len(rdz_urls) >= 8:
                    break
    return Peer(
        short_id=short_id,
        hostname=props.get("host", server) or "",
        address=addr,
        port=info.port or 0,
        ed_pub_hex=pub or "",
        rendezvous_urls=rdz_urls,
        # v0.7.3: device kind ("macos-laptop", etc). Bounded length;
        # we don't trust arbitrary strings inside the UI but the
        # /api/peers serializer + display path treats it as opaque text.
        device_kind=(props.get("kind") or "")[:32],
    )


class _AsyncListener:
    """Sync ServiceListener that schedules async work on the daemon loop."""

    def __init__(
        self,
        registry: Registry,
        self_short_id: str,
        zc: AsyncZeroconf,
        loop: asyncio.AbstractEventLoop,
    ):
        self.registry = registry
        self.self_short_id = self_short_id
        self.zc = zc
        self.loop = loop
        self.service_to_short_id: dict[str, str] = {}
        self._resolve_futures: set[concurrent.futures.Future[None]] = set()
        # ``run_coroutine_threadsafe`` exposes a concurrent Future whose
        # cancellation can complete before the loop-owned Task has actually
        # observed ``CancelledError``. Track the real Tasks as well so shutdown
        # can drain resolver cleanup rather than only draining the proxy.
        self._resolve_tasks: set[asyncio.Task[None]] = set()
        self._closing = False

    def _schedule_resolve(self, type_: str, name: str) -> None:
        async def _tracked_resolve() -> None:
            task = asyncio.current_task()
            if task is None:
                raise RuntimeError("mDNS resolver is not running in an asyncio task")
            self._resolve_tasks.add(task)
            try:
                if not self._closing:
                    await self._resolve(type_, name)
            finally:
                self._resolve_tasks.discard(task)

        resolve_coro = _tracked_resolve()
        if self._closing:
            resolve_coro.close()
            return
        try:
            future = asyncio.run_coroutine_threadsafe(
                resolve_coro,
                self.loop,
            )
        except RuntimeError as exc:
            # Zeroconf invokes this listener from its callback thread. During
            # shutdown the event loop can close between notification and
            # scheduling; surface that race instead of leaking an un-awaited
            # coroutine and silently retaining a stale registry entry.
            resolve_coro.close()
            log.debug("mDNS: could not schedule resolve for %s: %s", name, exc)
            return

        def _resolve_done(done) -> None:
            try:
                done.result()
            except concurrent.futures.CancelledError:
                return
            except Exception as exc:
                # Exceptions raised by a coroutine submitted with
                # run_coroutine_threadsafe otherwise remain trapped in the
                # Future forever. That made broken resolution look exactly
                # like a peer that had disappeared from the LAN.
                log.warning("mDNS: resolve failed for %s: %s", name, exc)

        self._resolve_futures.add(future)

        def _tracked_resolve_done(
            done: concurrent.futures.Future[None],
        ) -> None:
            self._resolve_futures.discard(done)
            _resolve_done(done)

        future.add_done_callback(_tracked_resolve_done)

    async def _resolve(self, type_: str, name: str) -> None:
        from zeroconf.asyncio import AsyncServiceInfo

        info = AsyncServiceInfo(type_, name)
        ok = await info.async_request(self.zc.zeroconf, timeout=2000)
        if not ok or self._closing:
            return
        peer = _info_to_peer(info, self.self_short_id)
        if peer:
            self.service_to_short_id[name] = peer.short_id
            self.registry.upsert(peer)

    async def stop(self) -> None:
        """Cancel and drain every resolver submitted from callback threads."""
        self._closing = True
        # Admit callbacks queued by ``run_coroutine_threadsafe`` before the
        # closing flag became visible. Their wrapper observes ``_closing`` and
        # registers the loop-owned Task, allowing an exact drain below.
        await asyncio.sleep(0)
        tasks = tuple(self._resolve_tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        pending = tuple(self._resolve_futures)
        for future in pending:
            future.cancel()
        if pending:
            await asyncio.gather(
                *(asyncio.wrap_future(future) for future in pending),
                return_exceptions=True,
            )
        self._resolve_futures.clear()

    def add_service(self, _zc, type_: str, name: str) -> None:
        self._schedule_resolve(type_, name)

    def update_service(self, _zc, type_: str, name: str) -> None:
        self._schedule_resolve(type_, name)

    def remove_service(self, _zc, _type, name: str) -> None:
        sid = self.service_to_short_id.pop(name, None) or name.split(".", 1)[0]
        self.registry.remove(sid)


class Discovery:
    def __init__(
        self,
        short_id: str,
        hostname: str,
        port: int,
        ed_pub_hex: str,
        rendezvous_urls: list[str] | None = None,
        device_kind: str = "",
        announce_details: bool = True,
    ):
        self.short_id = short_id
        self.hostname = hostname
        # When False the announcement carries only the short ID and public
        # key, which a peer needs to authenticate its dial: no display name,
        # no device kind, no rendezvous URLs.
        self.announce_details = bool(announce_details)
        self.port = port
        self.ed_pub_hex = ed_pub_hex
        # v0.5.4: rendezvous URLs we advertise in our mDNS TXT record
        # so other daemons on this LAN auto-discover them.
        self.rendezvous_urls: list[str] = list(rendezvous_urls or [])
        # v0.7.3: compact device kind (e.g. "macos-laptop"). Empty
        # string means "don't advertise".
        self.device_kind: str = (device_kind or "")[:32]
        self.registry = Registry(self_ed_pub_hex=ed_pub_hex)
        self._zc: AsyncZeroconf | None = None
        self._info: AsyncServiceInfo | None = None
        self._browser: AsyncServiceBrowser | None = None
        self._listener: _AsyncListener | None = None

    @property
    def is_running(self) -> bool:
        """Whether zeroconf advertisement/browsing owns live resources."""
        return self._zc is not None

    async def start(self) -> None:
        if self._zc is not None:
            return
        try:
            (
                IPVersion,
                AsyncServiceBrowser,
                AsyncServiceInfo,
                AsyncZeroconf,
            ) = await asyncio.wait_for(
                asyncio.to_thread(_load_zeroconf_modules),
                timeout=ZEROCONF_IMPORT_TIMEOUT_S,
            )
        except Exception as e:
            log.warning("mDNS discovery disabled: zeroconf import timed out or failed: %s", e)
            return

        loop = asyncio.get_running_loop()
        # Before the first announcement, so no unroutable-interface traceback
        # can reach the log.
        _quiet_zeroconf_unreachable_interfaces()
        self._zc = AsyncZeroconf(ip_version=IPVersion.V4Only)
        local_ip = _best_local_ipv4()
        allow_same_host = str(os.environ.get("ONE_LINK_ALLOW_SAME_HOST_PEERS") or "").lower()
        if allow_same_host in ("1", "true", "yes"):
            self.registry.local_addresses = set()
        else:
            self.registry.local_addresses = {
                local_ip,
                "127.0.0.1",
                "::1",
                "localhost",
            }
        properties = self._txt_properties()
        self._info = AsyncServiceInfo(
            type_=SERVICE_TYPE,
            name=f"{self.short_id}.{SERVICE_TYPE}",
            addresses=[socket.inet_aton(local_ip)],
            port=self.port,
            properties=properties,
            server=f"{self.short_id}.local.",
        )
        await self._zc.async_register_service(self._info, allow_name_change=True)
        self._listener = _AsyncListener(
            self.registry, self.short_id, self._zc, loop
        )
        self._browser = AsyncServiceBrowser(
            self._zc.zeroconf,
            SERVICE_TYPE,
            listener=self._listener,
        )

    def _txt_properties(self) -> dict[str, str]:
        """The TXT record this device announces.

        Always the short ID and the public key. The display name, device
        kind and rendezvous URLs are included only when ``announce_details``
        is set. The rendezvous list is capped: an oversized record can be
        dropped by routers (8 URLs of about 64 characters is 512 bytes).
        """
        properties: dict[str, str] = {
            "sid": self.short_id,
            "host": self.hostname if self.announce_details else self.short_id,
            "pub": self.ed_pub_hex,
            "v": "0.0.1",
        }
        if self.announce_details:
            rdz_value = ",".join(self.rendezvous_urls[:8])
            if rdz_value:
                properties["rdz"] = rdz_value
            if self.device_kind:
                properties["kind"] = self.device_kind
        return properties

    async def update_rendezvous_urls(self, urls: list[str]) -> None:
        """v0.5.4: live-update the advertised rendezvous URLs in the
        mDNS TXT record without re-registering the service. Called
        whenever the daemon's rendezvous_urls setting changes."""
        self.rendezvous_urls = list(urls or [])
        if self._zc is None or self._info is None:
            return
        # AsyncServiceInfo.properties is a dict; building a new one
        # and re-registering is the supported path.
        new_props = self._txt_properties()
        # `update_service` re-broadcasts the TXT record without
        # cycling the service registration (which would briefly remove
        # us from peers' registries and surface as a flap).
        from zeroconf.asyncio import AsyncServiceInfo

        local_ip = _best_local_ipv4()
        self._info = AsyncServiceInfo(
            type_=SERVICE_TYPE,
            name=f"{self.short_id}.{SERVICE_TYPE}",
            addresses=[socket.inet_aton(local_ip)],
            port=self.port,
            properties=new_props,
            server=f"{self.short_id}.local.",
        )
        try:
            await self._zc.async_update_service(self._info)
        except Exception as exc:
            # Keep the desired URLs in memory so a subsequent update can
            # retry, but do not make a stale TXT advertisement invisible to
            # operators troubleshooting a missing route.
            log.warning(
                "mDNS: rendezvous TXT update failed; peers may retain stale routes: %s",
                exc,
            )

    async def prune_unreachable(self, *, timeout: float = 0.6) -> int:
        """TCP-probe every peer in the registry; remove any that don't accept
        a connection within `timeout` seconds. Returns count removed.

        Catches the "ghost peer" case where mDNS broadcasts (cached by the
        OS or a network device) outlive the daemon that announced them.
        """
        peers = list(self.registry.peers.values())
        if not peers:
            return 0
        removed = 0
        for p in list(peers):
            if not _valid_pub_hex(p.ed_pub_hex) or p.address in self.registry.local_addresses:
                self.registry.remove(p.short_id)
                removed += 1
        peers = [
            p for p in peers
            if _valid_pub_hex(p.ed_pub_hex)
            and p.address not in self.registry.local_addresses
        ]
        if not peers:
            return removed

        async def _probe(p: Peer) -> tuple[Peer, bool]:
            try:
                fut = asyncio.open_connection(p.address, p.port)
                reader, writer = await asyncio.wait_for(fut, timeout=timeout)
                try:
                    writer.close()
                    await writer.wait_closed()
                except (OSError, RuntimeError) as exc:
                    report_best_effort_failure(
                        log,
                        "peer_probe_writer_close",
                        exc,
                        level=logging.DEBUG,
                    )
                return p, True
            except (asyncio.TimeoutError, OSError):
                return p, False

        results = await asyncio.gather(*(_probe(p) for p in peers), return_exceptions=False)
        for peer, ok in results:
            if not ok:
                self.registry.remove(peer.short_id)
                removed += 1
        return removed

    async def stop(self) -> None:
        try:
            if self._browser:
                await self._browser.async_cancel()
        except Exception as exc:
            log.debug("mDNS: browser cancellation failed during shutdown: %s", exc)
        if self._listener is not None:
            await self._listener.stop()
        try:
            if self._info and self._zc:
                await self._zc.async_unregister_service(self._info)
        except Exception as exc:
            # A failed goodbye can leave resolvers displaying the endpoint
            # until its TTL expires. Shutdown remains best-effort, but the
            # stale-route source must be diagnosable.
            log.warning(
                "mDNS: service unregister failed; advertisement may remain until TTL: %s",
                exc,
            )
        try:
            if self._zc:
                await self._zc.async_close()
        except Exception as exc:
            log.debug("mDNS: zeroconf close failed during shutdown: %s", exc)
        self._zc = None
        self._info = None
        self._browser = None
        self._listener = None


def _best_local_ipv4() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()
