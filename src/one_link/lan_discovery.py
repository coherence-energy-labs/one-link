"""Best-effort multi-modal discovery of devices visible on local interfaces.

No discovery method can enumerate every local device: client isolation,
firewalls, sleeping devices, IPv6-only paths, privacy-address rotation,
permissions, missing commands, and non-advertising hosts all create blind
spots. Names, vendor, kind, and model are bounded heuristics unless the device
itself supplies authenticated evidence.

Five protocols, all open-standard, all local-only:

  1. mDNS / Bonjour browse-everything (RFC 6762/6763). Built on
     python-zeroconf which we already use for our own service
     advertisement. We browse a curated set of common service types
     (AirPlay, AirDrop discoverability, AirDroid, IPP printing,
     Chromecast/DIAL, Steam in-home streaming, SSH, SMB, etc.) and
     correlate the portfolio per host to infer device kind.

  2. ARP table sweep — every device that has spoken to your gateway
     in the kernel's ARP cache. Catches devices that don't advertise
     anything but are otherwise on the network. Cross-platform via
     `arp -a` on Windows and `ip neigh` / `arp -an` on UNIX.

  3. SSDP / UPnP (RFC standard) — smart TVs, speakers, media
     servers, gateways, IoT.

  4. NetBIOS name-service — Windows machines + their friendly
     names. We send the standard \\x21 query to the broadcast
     address on UDP/137 and parse responses.

  5. TCP fingerprinting probe — for unknown hosts, attempt a
     non-intrusive probe of a few well-known ports (22/80/443/445)
     and read banners. Gives us "this responds on 445" → "Windows
     machine" / "responds on 22 with OpenSSH" → "*nix box".

Everything correlates by (IP, MAC). OUI vendor lookup ships INSIDE
One Link via a bundled, gzipped subset of the IEEE OUI registry
(no calls to macvendors.com / wireshark.org / corp lookup services).

The scanners are intended for local-interface addresses and bundled data; they
do not intentionally call a third-party lookup service. That source-level
boundary and the application's best-effort outbound-event log are not
packet-capture proof that an OS resolver, proxy, dependency, or compromised local
device made no outside connection.
"""
from __future__ import annotations

import asyncio
import gzip
import ipaddress
import logging
import os
import re
import socket
import subprocess
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

from one_link import task_refs
from one_link.bounded_resolver import resolve_bounded
from one_link.process_security import (
    hidden_creationflags,
    resolve_argv,
    trusted_process_env,
)
from one_link.fault_observability import report_best_effort_failure

log = logging.getLogger("one_link.lan_discovery")


# ── Public data shape ──────────────────────────────────────────────


@dataclass
class DiscoveredDevice:
    """One device, fused from every protocol that saw it.

    Fields are populated incrementally as each scanner adds data.
    `confidence` is the merged score across scanners (1.0 = strong
    multi-protocol corroboration; 0.3 = only one weak signal).
    """
    # Identification.
    ip: str = ""
    mac: str = ""                       # lowercase, colons; empty if unknown
    hostname: str = ""                  # friendly name from mDNS / NetBIOS / SMB
    vendor: str = ""                    # OUI-derived ("Apple, Inc.", "Samsung")
    # Inferred kind: "phone" / "tablet" / "mobile" / "laptop" / "desktop" /
    # "tv" / "speaker" / "printer" / "router" / "iot" / "unknown".
    # "mobile" means privacy-masked phone/tablet candidate. The UI
    # uses this to filter "pairable" (phone/laptop/tablet/mobile/
    # desktop) vs "other gear".
    kind: str = "unknown"
    # Best-guess model string, e.g. "iPhone15,3" or "MacBookPro18,3".
    model: str = ""
    # Whether this device is already running One Link (i.e., shows
    # up in the existing _onelink._tcp.local. mDNS browse).
    is_one_link_peer: bool = False
    # mDNS service types the device advertises. The PORTFOLIO is
    # diagnostic ("_airplay + _raop + _companion-link" = Apple).
    mdns_services: list[str] = field(default_factory=list)
    # Open TCP ports seen during probing. Empty if no probe ran.
    open_ports: list[int] = field(default_factory=list)
    # Each scanner that contributed evidence ("mdns", "arp",
    # "ssdp", "netbios", "tcp_probe"). The UI surfaces this so the
    # user can see "we know about this from 3 different sources."
    sources: list[str] = field(default_factory=list)
    # Confidence: 0.0 ("we only saw a MAC in ARP, nothing else")
    # to 1.0 ("multi-protocol corroboration, vendor + kind both
    # firm"). Heuristic, not statistical.
    confidence: float = 0.0
    # SSDP/UPnP device-description URL the device advertised (e.g.
    # http://192.168.1.91:1400/xml/device_description.xml). When
    # present we fetch the XML locally to extract authoritative
    # friendlyName / manufacturer / modelName / modelNumber.
    ssdp_location: str = ""


# ── OUI vendor database ────────────────────────────────────────────
#
# Bundled inside One Link so we never call out to a corp lookup
# service. The file lives at `data/oui_prefixes.txt.gz`. Format is
# one line per prefix:  AABBCC<TAB>Vendor Name
# We only bundle ~2,500 of the most common consumer prefixes —
# enough to identify >99% of devices a normal home user will see.

_OUI_PATH = (
    Path(__file__).parent / "data" / "oui_prefixes.txt.gz"
)
_OUI_CACHE: Optional[dict[str, str]] = None


def _load_oui_table() -> dict[str, str]:
    """Read the bundled OUI prefix table into a dict. Cached after
    first call. Falls back to a tiny built-in subset if the file is
    missing so the daemon still functions (just less specific).
    """
    global _OUI_CACHE
    if _OUI_CACHE is not None:
        return _OUI_CACHE
    table: dict[str, str] = {}
    try:
        if _OUI_PATH.is_file():
            with gzip.open(_OUI_PATH, "rt", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "\t" in line:
                        pfx, vendor = line.split("\t", 1)
                    elif " " in line:
                        pfx, vendor = line.split(None, 1)
                    else:
                        continue
                    pfx = pfx.replace(":", "").replace("-", "").lower()
                    if len(pfx) >= 6:
                        table[pfx[:6]] = vendor.strip()
    except Exception as e:
        log.warning("OUI table load failed (%s); using fallback", e)
    if not table:
        # Minimum viable fallback: the major consumer prefixes.
        # Better to identify SOMETHING than nothing. Will be
        # replaced by the bundled file when present.
        table = _MINIMAL_OUI_FALLBACK
    _OUI_CACHE = table
    return table


# Minimum-viable hardcoded fallback — covers the top ~50 consumer
# vendor prefixes. Used when the bundled OUI file isn't present
# (developer-mode source-tree run without the data file built).
_MINIMAL_OUI_FALLBACK = {
    # Apple (a few of the many they own; real bundle has ~1000)
    "000393": "Apple, Inc.",
    "0017f2": "Apple, Inc.",
    "001451": "Apple, Inc.",
    "0019e3": "Apple, Inc.",
    "001b63": "Apple, Inc.",
    "001ec2": "Apple, Inc.",
    "0021e9": "Apple, Inc.",
    "002241": "Apple, Inc.",
    "002332": "Apple, Inc.",
    "002436": "Apple, Inc.",
    "00254b": "Apple, Inc.",
    "0025bc": "Apple, Inc.",
    "002608": "Apple, Inc.",
    "002612": "Apple, Inc.",
    "00264a": "Apple, Inc.",
    "00265e": "Apple, Inc.",
    "0026b0": "Apple, Inc.",
    "0026bb": "Apple, Inc.",
    "003ee1": "Apple, Inc.",
    "1093e9": "Apple, Inc.",
    "5cf938": "Apple, Inc.",
    "ac3613": "Apple, Inc.",
    "f0d1a9": "Apple, Inc.",
    # Samsung
    "002566": "Samsung Electronics",
    "0023db": "Samsung Electronics",
    "0026e2": "Samsung Electronics",
    "00e64c": "Samsung Electronics",
    "5440ad": "Samsung Electronics",
    "78bdbc": "Samsung Electronics",
    "8425db": "Samsung Electronics",
    # Google / Nest
    "f4f5d8": "Google",
    "f8f005": "Google",
    "20df3f": "Google",
    "4cf739": "Google Nest",
    # Microsoft / Xbox / Surface
    "00125a": "Microsoft",
    "0017fa": "Microsoft",
    "0050f2": "Microsoft",
    "7c1e52": "Microsoft",
    # Amazon (Echo, Fire)
    "08bdf4": "Amazon Technologies",
    "44650d": "Amazon Technologies",
    # Roku
    "b0a737": "Roku",
    "cc6da0": "Roku",
    # Sonos
    "00ee02": "Sonos",
    "5ccea1": "Sonos",
    # TP-Link / common routers
    "00040e": "TP-Link",
    "001e64": "TP-Link",
    # Raspberry Pi
    "b827eb": "Raspberry Pi Foundation",
    "dca632": "Raspberry Pi Trading",
    "e45f01": "Raspberry Pi Foundation",
}


def is_locally_administered_mac(mac: str) -> bool:
    """Return True if the MAC has the locally-administered bit set
    (bit 1 of the first byte). These are randomized MACs used for
    privacy (iOS / Android / Windows random MAC) — they don't match
    a real OUI even if the first three bytes happen to collide with
    one in the registry. We must skip OUI lookup for these or we
    publish nonsense vendor labels."""
    if not mac:
        return False
    key = mac.replace(":", "").replace("-", "").lower()
    if len(key) < 2:
        return False
    try:
        first_byte = int(key[:2], 16)
    except ValueError:
        return False
    # Bit 1 = locally administered. Universally-administered MACs
    # (the ones the IEEE actually issues) have this bit clear.
    return bool(first_byte & 0b10)


def vendor_for_mac(mac: str) -> str:
    """OUI lookup. Returns vendor name or "" if unknown. Skips
    randomized / locally-administered MACs entirely (they don't
    correspond to a real vendor even if they happen to collide with
    a registered prefix)."""
    if not mac:
        return ""
    if is_locally_administered_mac(mac):
        return ""
    key = mac.replace(":", "").replace("-", "").lower()[:6]
    table = _load_oui_table()
    return table.get(key, "")


# ── ARP table ──────────────────────────────────────────────────────


_ARP_LINE_RE = re.compile(
    r"^\s*"
    r"(?P<ip>\d+\.\d+\.\d+\.\d+)"
    r"\s+"
    r"(?:[a-z-]+\s+)?"          # state on Linux ("ether"), interface name etc.
    r"(?P<mac>[0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})"
)


def scan_arp_table(timeout_s: float = 2.0) -> list[DiscoveredDevice]:
    """Read the kernel's ARP table and return one DiscoveredDevice
    per (IP, MAC) pair. Cheap — no network packets sent."""
    cmds: list[list[str]]
    if os.name == "nt":
        cmds = [["arp", "-a"]]
    else:
        cmds = [["ip", "neigh"], ["arp", "-an"]]

    seen: dict[str, DiscoveredDevice] = {}
    for cmd in cmds:
        try:
            argv = resolve_argv(cmd, system_tool=True)
            res = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=timeout_s,
                creationflags=hidden_creationflags(),
                cwd=str(Path(argv[0]).parent),
                env=trusted_process_env(),
                check=False,
                shell=False,
            )
        except (OSError, ValueError, subprocess.SubprocessError):
            continue
        if res.returncode != 0:
            continue
        for line in (res.stdout or "").splitlines():
            m = _ARP_LINE_RE.search(line)
            if not m:
                continue
            ip = m.group("ip")
            mac = m.group("mac").lower().replace("-", ":")
            # Skip multicast / broadcast / unspecified / link-local
            # so the discovery list only contains real peer
            # candidates. 224.0.0.0/4 = IPv4 multicast block.
            try:
                ip_obj = ipaddress.ip_address(ip)
                if (
                    ip_obj.is_multicast
                    or ip_obj.is_unspecified
                    or ip in ("255.255.255.255",)
                    or mac.startswith("ff:ff")
                    or mac.startswith("01:00:5e")   # IPv4 multicast MAC
                    or mac.startswith("33:33")      # IPv6 multicast MAC
                    or mac in ("00:00:00:00:00:00",)
                ):
                    continue
            except ValueError:
                continue
            key = ip
            if key in seen:
                seen[key].mac = seen[key].mac or mac
            else:
                seen[key] = DiscoveredDevice(
                    ip=ip,
                    mac=mac,
                    vendor=vendor_for_mac(mac),
                    sources=["arp"],
                    confidence=0.4,
                )
    return list(seen.values())


# ── mDNS browse-everything ─────────────────────────────────────────


# Service types we browse. Carefully chosen — broad enough to catch
# Apple / Google / Microsoft devices + media gear, narrow enough not
# to flood the network with browse traffic.
_INTERESTING_MDNS_SERVICES = [
    # Apple-y
    "_companion-link._tcp.local.",      # Continuity / Handoff
    "_airdrop._tcp.local.",             # AirDrop peer discovery
    "_airplay._tcp.local.",             # AirPlay (TVs, speakers, Apple TVs)
    "_raop._tcp.local.",                # Remote Audio Output (AirPlay v1)
    "_homekit._tcp.local.",             # HomeKit accessories
    "_apple-mobdev2._tcp.local.",       # iOS device tether
    "_sleep-proxy._udp.local.",         # Bonjour Sleep Proxy (Mac wake)
    "_rfb._tcp.local.",                 # Screen sharing (Apple Remote Desktop)
    # Generic
    "_ipp._tcp.local.",                 # Printers (IPP)
    "_ipps._tcp.local.",                # Secure IPP
    "_printer._tcp.local.",
    "_smb._tcp.local.",                 # Windows / Samba shares
    "_ssh._tcp.local.",                 # SSH server
    "_http._tcp.local.",                # Generic web service
    "_googlecast._tcp.local.",          # Chromecast
    "_steam._tcp.local.",               # Steam in-home streaming
    "_spotify-connect._tcp.local.",     # Spotify Connect speakers
    "_workstation._tcp.local.",         # Linux/Avahi workstations
    "_device-info._tcp.local.",         # Generic device info
]


async def scan_mdns_browse_all(
    timeout_s: float = 5.0,
) -> list[DiscoveredDevice]:
    """Browse multiple mDNS service types in parallel. Returns one
    DiscoveredDevice per host, with merged service list. Same host
    seen via _airplay + _raop + _companion-link becomes ONE
    device record with all three services in `mdns_services`."""
    try:
        from zeroconf import ServiceStateChange
        from zeroconf.asyncio import (
            AsyncServiceBrowser, AsyncServiceInfo, AsyncZeroconf,
        )
    except Exception as e:
        log.warning("zeroconf unavailable: %s", e)
        return []

    # Second zeroconf entry point in the package: the same unroutable-
    # interface tracebacks would otherwise reach the log from here.
    from one_link.discovery import _quiet_zeroconf_unreachable_interfaces

    _quiet_zeroconf_unreachable_interfaces()
    aio = AsyncZeroconf()
    # Key by IP (the only stable cross-protocol identifier).
    by_ip: dict[str, DiscoveredDevice] = {}

    async def _on_service(zc, st, name, state_change):
        try:
            info = AsyncServiceInfo(st, name)
            ok = await info.async_request(zc, timeout=1500)
            if not ok:
                return
            addrs = info.parsed_addresses() or []
            if not addrs:
                return
            ip = addrs[0]
            dev = by_ip.get(ip)
            if dev is None:
                dev = DiscoveredDevice(ip=ip, sources=["mdns"], confidence=0.6)
                by_ip[ip] = dev
            if "mdns" not in dev.sources:
                dev.sources.append("mdns")
            # Merge service type.
            stype_short = st.replace("._tcp.local.", "").replace("._udp.local.", "")
            if stype_short not in dev.mdns_services:
                dev.mdns_services.append(stype_short)
            # Hostname.
            srv_name = (info.server or "").rstrip(".")
            if srv_name and not dev.hostname:
                # Strip trailing .local. so the UI gets just "Alex's-iPhone"
                dev.hostname = srv_name.rsplit(".local", 1)[0].rsplit(".", 1)[0]
            # TXT records may carry model info. Apple devices set
            # "model" / "md" to identifiers like iPhone15,2; we
            # decode those into the human product name via the
            # bundled Apple model table.
            try:
                txt = info.properties or {}
                for k, v in txt.items():
                    k_s = k.decode("utf-8", "replace") if isinstance(k, bytes) else str(k)
                    v_s = v.decode("utf-8", "replace") if isinstance(v, bytes) else (str(v) if v else "")
                    k_l = k_s.lower()
                    if k_l in ("model", "md", "device") and not dev.model:
                        # Decode Apple identifier if it looks like one
                        # (PrefixDigit,Digit pattern).
                        if "," in v_s and v_s.split(",")[0][-1].isdigit():
                            dev.model = decode_apple_model(v_s)
                        else:
                            dev.model = v_s
            except (AttributeError, IndexError, TypeError, UnicodeError, ValueError) as exc:
                report_best_effort_failure(
                    log, "mdns_txt_parse", exc, level=logging.DEBUG
                )
        except Exception as exc:
            # This is a third-party callback boundary. Keep the other service
            # browsers alive, but retain enough context to distinguish a
            # resolver failure from a genuinely absent device.
            report_best_effort_failure(
                log, "mdns_service_resolve", exc, level=logging.DEBUG
            )
            return

    # Synchronous wrapper that zeroconf can call from its callback thread.
    # zeroconf >=0.130 passes args as kwargs (zeroconf=, service_type=,
    # name=, state_change=); accept **kw to stay forward compatible.
    def _on_state_change_sync(zeroconf=None, service_type=None, name=None,
                              state_change=None, **_kw):
        zc = zeroconf
        st = service_type
        # Fail closed on every event except an explicit Added notification.
        # Falling through when the enum import/comparison failed caused
        # Removed notifications to be resolved and re-added as stale devices.
        if state_change is not ServiceStateChange.Added:
            return
        if zc is None or st is None or name is None:
            return
        task_refs.spawn(_on_service(zc, st, name, state_change))

    browsers = []
    for st in _INTERESTING_MDNS_SERVICES:
        try:
            b = AsyncServiceBrowser(
                aio.zeroconf, st, handlers=[_on_state_change_sync],
            )
            browsers.append(b)
        except Exception as exc:
            report_best_effort_failure(
                log, "mdns_browser_setup", exc, level=logging.DEBUG
            )
            continue

    if not browsers:
        log.warning("mDNS scan could not start a browser for any service type")

    await asyncio.sleep(timeout_s)

    for b in browsers:
        try:
            await b.async_cancel()
        except Exception as exc:
            report_best_effort_failure(
                log, "mdns_browser_cancel", exc, level=logging.DEBUG
            )
    try:
        await aio.async_close()
    except Exception as exc:
        report_best_effort_failure(
            log, "mdns_scanner_close", exc, level=logging.DEBUG
        )

    return list(by_ip.values())


# ── SSDP / UPnP discovery ──────────────────────────────────────────


def scan_ssdp(timeout_s: float = 2.5) -> list[DiscoveredDevice]:
    """Send an M-SEARCH probe and collect responses. Identifies smart
    TVs, media servers, gateways, speakers."""
    msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 2\r\n"
        "ST: ssdp:all\r\n"
        "\r\n"
    ).encode("ascii")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    s.settimeout(timeout_s)
    devices: dict[str, DiscoveredDevice] = {}
    try:
        s.sendto(msg, ("239.255.255.250", 1900))
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            try:
                data, addr = s.recvfrom(4096)
            except socket.timeout:
                break
            except OSError:
                break
            ip = addr[0]
            txt = data.decode("ascii", errors="replace")
            dev = devices.get(ip)
            if dev is None:
                dev = DiscoveredDevice(
                    ip=ip, sources=["ssdp"], confidence=0.5,
                )
                devices[ip] = dev
            if "ssdp" not in dev.sources:
                dev.sources.append("ssdp")
            # Parse a few useful header values.
            for line in txt.splitlines():
                if ":" not in line:
                    continue
                k, v = line.split(":", 1)
                k = k.strip().lower()
                v = v.strip()
                if k == "server" and not dev.model:
                    dev.model = v
                elif k == "x-friendlyname" and not dev.hostname:
                    dev.hostname = v
                elif k == "location" and not dev.ssdp_location:
                    # LAN-local HTTP URL pointing at the device's
                    # UPnP description XML. Cheap to fetch.
                    if v.startswith(("http://", "https://")):
                        dev.ssdp_location = v
    except Exception as e:
        log.debug("ssdp scan error: %s", e)
    finally:
        s.close()
    return list(devices.values())


# ── NetBIOS name-service (Windows machines) ────────────────────────


def scan_netbios(broadcast: str = "", timeout_s: float = 1.5) -> list[DiscoveredDevice]:
    """Send a NetBIOS Name Service query to the broadcast address
    and parse responses. Returns a list of devices with hostname
    set to the NetBIOS name."""
    # NetBIOS NBSTAT query for the wildcard name (\x2a).
    query = bytes([
        0xA0, 0x00,           # transaction id
        0x00, 0x10,           # flags (NBSTAT)
        0x00, 0x01,           # questions
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x20, 0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x00,
        0x00, 0x21,           # NBSTAT
        0x00, 0x01,           # IN
    ])
    # Default broadcast.
    if not broadcast:
        broadcast = "255.255.255.255"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.settimeout(timeout_s)
    devices: dict[str, DiscoveredDevice] = {}
    try:
        s.sendto(query, (broadcast, 137))
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            try:
                data, addr = s.recvfrom(2048)
            except socket.timeout:
                break
            except OSError:
                break
            ip = addr[0]
            # Parse minimal NBSTAT response. Skip the 56-byte header
            # and read entries (18 bytes each) until the count
            # byte at offset 56 says we've read them all.
            if len(data) < 57:
                continue
            count = data[56]
            best_name = ""
            for i in range(count):
                start = 57 + i * 18
                if start + 16 > len(data):
                    break
                name_raw = data[start:start + 15].decode(
                    "ascii", errors="replace"
                ).strip()
                flags = data[start + 16]
                # Bit 0x80 set = group name; we want unique
                # workstation names (no top bit set).
                if name_raw and not name_raw.startswith("\x00") and not (flags & 0x80):
                    if not best_name or len(name_raw) > len(best_name):
                        best_name = name_raw
            if best_name:
                dev = DiscoveredDevice(
                    ip=ip,
                    hostname=best_name,
                    sources=["netbios"],
                    confidence=0.55,
                )
                devices[ip] = dev
    except Exception as e:
        log.debug("netbios scan error: %s", e)
    finally:
        s.close()
    return list(devices.values())


# ── Correlation + identification ───────────────────────────────────


# Hostname-pattern table. Each entry: (compiled regex, kind, vendor,
# label). The first match wins. Patterns are case-insensitive and
# anchored loosely so a partial hostname still hits. Used after
# every other signal so it's a strong tie-breaker but not the only
# decider.
import re as _re

_HOSTNAME_PATTERNS: list[tuple[_re.Pattern[str], str, str, str]] = [
    # Gaming consoles
    (_re.compile(r"^ps[3-5]?-", _re.I),       "console", "Sony",      "PlayStation"),
    (_re.compile(r"playstation", _re.I),       "console", "Sony",      "PlayStation"),
    (_re.compile(r"^xbox", _re.I),             "console", "Microsoft", "Xbox"),
    (_re.compile(r"nintendo|switch", _re.I),   "console", "Nintendo",  "Nintendo Switch"),
    # Streaming devices / smart TVs
    (_re.compile(r"^roku|roku-", _re.I),       "tv",      "Roku",      "Roku"),
    (_re.compile(r"chromecast|google-?nest-hub", _re.I), "tv", "Google", "Chromecast"),
    (_re.compile(r"appletv|apple-?tv", _re.I), "tv",      "Apple",     "Apple TV"),
    (_re.compile(r"firetv|amazon-?fire", _re.I),"tv",     "Amazon",    "Fire TV"),
    (_re.compile(r"shield-?tv", _re.I),        "tv",      "NVIDIA",    "Shield TV"),
    (_re.compile(r"\bbravia\b|sony.*tv", _re.I),"tv",     "Sony",      "Bravia TV"),
    (_re.compile(r"lg-?tv|webos", _re.I),      "tv",      "LG",        "LG TV"),
    (_re.compile(r"samsung-?tv|tizen", _re.I), "tv",      "Samsung",   "Samsung TV"),
    (_re.compile(r"vizio", _re.I),             "tv",      "Vizio",     "Vizio TV"),
    # Smart speakers
    (_re.compile(r"homepod", _re.I),           "speaker", "Apple",     "HomePod"),
    (_re.compile(r"sonos|^play[-:]?[0-9]?$|playbar|playbase|^beam|^roam|^arc-", _re.I),
                                               "speaker", "Sonos",     "Sonos"),
    (_re.compile(r"echo|alexa|^amzn-", _re.I), "speaker", "Amazon",    "Echo"),
    (_re.compile(r"google-?home|nest-?mini|nest-?audio", _re.I),
                                               "speaker", "Google",    "Google Home"),
    (_re.compile(r"bose|soundtouch", _re.I),   "speaker", "Bose",      "Bose speaker"),
    # Phones / tablets / wearables
    (_re.compile(r"iphone", _re.I),            "phone",   "Apple",     "iPhone"),
    (_re.compile(r"ipad", _re.I),              "tablet",  "Apple",     "iPad"),
    (_re.compile(r"^pixel-?\d", _re.I),        "phone",   "Google",    "Pixel"),
    (_re.compile(r"galaxy|samsung.*(s\d|note|tab)", _re.I),
                                               "phone",   "Samsung",   "Samsung Galaxy"),
    (_re.compile(r"oneplus", _re.I),           "phone",   "OnePlus",   "OnePlus"),
    (_re.compile(r"redmi|xiaomi|mi-\w", _re.I),"phone",   "Xiaomi",    "Xiaomi"),
    (_re.compile(r"applewatch|apple-?watch", _re.I),
                                               "watch",   "Apple",     "Apple Watch"),
    # Laptops / desktops
    (_re.compile(r"macbook", _re.I),           "laptop",  "Apple",     "MacBook"),
    (_re.compile(r"imac|mac-?mini|mac-?pro|mac-?studio", _re.I),
                                               "desktop", "Apple",     "Mac"),
    (_re.compile(r"^mac$|^mac[-_]", _re.I),    "laptop",  "Apple",     "Mac"),
    (_re.compile(r"surface-?(pro|book|laptop)", _re.I),
                                               "laptop",  "Microsoft", "Surface"),
    (_re.compile(r"thinkpad|legion", _re.I),   "laptop",  "Lenovo",    "ThinkPad"),
    (_re.compile(r"dell-?(xps|latitude|inspiron)", _re.I),
                                               "laptop",  "Dell",      "Dell laptop"),
    (_re.compile(r"^laptop[-_]|^lt-|^nb-", _re.I), "laptop", "",        "Laptop"),
    (_re.compile(r"^desktop[-_]|^pc-|^dt-", _re.I), "desktop", "",      "Desktop"),
    # IoT / single-board / smart home
    (_re.compile(r"raspberry|^raspberrypi|^rpi-", _re.I),
                                               "iot",     "Raspberry Pi", "Raspberry Pi"),
    (_re.compile(r"^esp[-_]?(32|8266)", _re.I),"iot",     "Espressif", "ESP32"),
    (_re.compile(r"nest|thermostat", _re.I),   "iot",     "Google Nest", "Nest"),
    (_re.compile(r"ring-?(doorbell|cam)", _re.I),"iot",   "Ring",      "Ring camera"),
    (_re.compile(r"hue-?(bridge|bulb|lamp)", _re.I),
                                               "iot",     "Philips",   "Philips Hue"),
    (_re.compile(r"ecobee|tado|honeywell", _re.I),"iot",  "",          "Smart thermostat"),
    # NAS / servers
    (_re.compile(r"synology|^ds[0-9]+|^ds-\d", _re.I),
                                               "desktop", "Synology",  "Synology NAS"),
    (_re.compile(r"qnap", _re.I),              "desktop", "QNAP",      "QNAP NAS"),
    (_re.compile(r"unraid|truenas|freenas", _re.I),
                                               "desktop", "",          "Storage server"),
    # Routers / network gear
    (_re.compile(r"^router|gateway|asus-?rt|^netgear|nighthawk|orbi", _re.I),
                                               "router",  "",          "Router"),
    (_re.compile(r"unifi|^udm|^uap|ubiquiti", _re.I),
                                               "router",  "Ubiquiti",  "Ubiquiti"),
    (_re.compile(r"eero", _re.I),              "router",  "Eero",      "Eero"),
    # Printers
    (_re.compile(r"^hp[-_]|hpinkjet|^laserjet|^officejet|envy", _re.I),
                                               "printer", "HP",        "HP printer"),
    (_re.compile(r"epson|workforce|expression", _re.I),
                                               "printer", "Epson",     "Epson printer"),
    (_re.compile(r"brother-|^brn-", _re.I),    "printer", "Brother",   "Brother printer"),
    (_re.compile(r"canon|pixma", _re.I),       "printer", "Canon",     "Canon printer"),
]


# Apple model identifier → human product name. Curated subset of the
# most common modern devices a home user would see. When mDNS TXT
# reports `model=iPhone15,2` or `md=Mac15,12`, we decode to the
# actual product name. Source: public Apple identifier registry +
# Wikipedia tables. Bundled local-only.
_APPLE_MODEL_DB: dict[str, str] = {
    # iPhones (recent — earlier models omitted for brevity)
    "iPhone11,8": "iPhone XR",
    "iPhone12,1": "iPhone 11",
    "iPhone12,3": "iPhone 11 Pro",
    "iPhone12,5": "iPhone 11 Pro Max",
    "iPhone12,8": "iPhone SE (2nd gen)",
    "iPhone13,1": "iPhone 12 mini",
    "iPhone13,2": "iPhone 12",
    "iPhone13,3": "iPhone 12 Pro",
    "iPhone13,4": "iPhone 12 Pro Max",
    "iPhone14,2": "iPhone 13 Pro",
    "iPhone14,3": "iPhone 13 Pro Max",
    "iPhone14,4": "iPhone 13 mini",
    "iPhone14,5": "iPhone 13",
    "iPhone14,6": "iPhone SE (3rd gen)",
    "iPhone14,7": "iPhone 14",
    "iPhone14,8": "iPhone 14 Plus",
    "iPhone15,2": "iPhone 14 Pro",
    "iPhone15,3": "iPhone 14 Pro Max",
    "iPhone15,4": "iPhone 15",
    "iPhone15,5": "iPhone 15 Plus",
    "iPhone16,1": "iPhone 15 Pro",
    "iPhone16,2": "iPhone 15 Pro Max",
    "iPhone17,1": "iPhone 16 Pro",
    "iPhone17,2": "iPhone 16 Pro Max",
    "iPhone17,3": "iPhone 16",
    "iPhone17,4": "iPhone 16 Plus",
    # iPads
    "iPad11,1": "iPad mini (5th gen)",
    "iPad11,3": "iPad Air (3rd gen)",
    "iPad13,1": "iPad Air (4th gen)",
    "iPad13,4": "iPad Pro 11 (3rd gen)",
    "iPad13,8": "iPad Pro 12.9 (5th gen)",
    "iPad14,1": "iPad mini (6th gen)",
    "iPad14,3": "iPad Pro 11 (4th gen)",
    "iPad14,5": "iPad Pro 12.9 (6th gen)",
    "iPad14,8": "iPad Air (5th gen)",
    # Macs (modern Apple Silicon)
    "MacBookPro17,1": "MacBook Pro 13 (M1)",
    "MacBookPro18,1": "MacBook Pro 16 (M1 Pro)",
    "MacBookPro18,3": "MacBook Pro 14 (M1 Pro)",
    "Mac14,2":  "MacBook Air 13 (M2)",
    "Mac14,7":  "MacBook Pro 13 (M2)",
    "Mac14,9":  "MacBook Pro 14 (M2 Pro)",
    "Mac15,3":  "MacBook Pro 14 (M3)",
    "Mac15,6":  "MacBook Pro 14 (M3 Pro)",
    "Mac15,12": "MacBook Air 13 (M3)",
    "Mac15,13": "MacBook Air 15 (M3)",
    "Mac16,1":  "MacBook Pro 14 (M4)",
    "Mac16,7":  "MacBook Pro 16 (M4 Pro)",
    "iMac21,1": "iMac 24 (M1)",
    "Macmini9,1": "Mac mini (M1)",
    "Macmini14,3": "Mac mini (M2)",
    # Apple Watch
    "Watch6,3": "Apple Watch Series 6",
    "Watch6,18": "Apple Watch Series 8",
    "Watch7,1": "Apple Watch Ultra",
    # Apple TV / HomePod
    "AppleTV6,2": "Apple TV 4K (2nd gen)",
    "AppleTV11,1": "Apple TV 4K (3rd gen)",
    "AudioAccessory1,1": "HomePod",
    "AudioAccessory5,1": "HomePod mini",
    "AudioAccessory6,1": "HomePod (2nd gen)",
}


def decode_apple_model(model_id: str) -> str:
    """Resolve an Apple model identifier (`iPhone15,2`) to a human
    product name (`iPhone 14 Pro`). Returns the input unchanged if
    not in the bundled table."""
    if not model_id:
        return ""
    return _APPLE_MODEL_DB.get(model_id.strip(), model_id.strip())


def apply_hostname_pattern(dev: DiscoveredDevice) -> bool:
    """Walk the hostname-pattern table. If a pattern matches the
    device's hostname, fill in `kind` (always), `vendor` (if
    empty), and `model` (if empty, from the pattern's label).
    Returns True if a pattern matched."""
    host = dev.hostname or ""
    if not host:
        return False
    for pat, kind, vendor, label in _HOSTNAME_PATTERNS:
        if pat.search(host):
            dev.kind = kind
            if not dev.vendor and vendor:
                dev.vendor = vendor
            if not dev.model and label:
                dev.model = label
            return True
    return False


# ── SSDP XML enrichment (LAN-local HTTP) ───────────────────────────
#
# When SSDP returns a `LOCATION:` header, the URL points at an XML
# document on the device itself describing its <friendlyName>,
# <manufacturer>, <modelName>. Fetching this is a pure LAN HTTP GET
# (sovereignty floor preserved — the URL lives on the same /24 as
# the daemon).


_SSDP_XML_TIMEOUT_S = 1.5


async def _fetch_ssdp_xml(url: str) -> Optional[str]:
    """Fetch a UPnP device description XML. Returns the raw body or
    None on any failure. LAN-only — refuses any URL that doesn't
    resolve to a private IP."""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        host = parsed.hostname or ""
        if not host:
            return None
        try:
            ip_obj = ipaddress.ip_address(host)
        except ValueError:
            try:
                # Bounded: an SSDP LOCATION can name a host this network
                # cannot resolve, and the wait is unbounded otherwise.
                ip_obj = ipaddress.ip_address(resolve_bounded(
                    socket.gethostbyname,
                    host,
                    default="",
                    label="LAN discovery SSDP host resolution",
                ))
            except (socket.gaierror, ValueError):
                return None
        if not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local):
            log.debug("refusing non-LAN SSDP LOCATION %s", url)
            return None
        if parsed.scheme != "http":
            return None
        port = parsed.port or 80
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        # asyncio-friendly fetch via run_in_executor + raw sockets. We
        # intentionally avoid high-level HTTP clients here; discovery
        # must stay LAN-only and small-surface.
        loop = asyncio.get_running_loop()

        def _get() -> Optional[str]:
            with socket.create_connection((str(ip_obj), port), timeout=_SSDP_XML_TIMEOUT_S) as s:
                s.settimeout(_SSDP_XML_TIMEOUT_S)
                req = (
                    f"GET {path} HTTP/1.0\r\n"
                    f"Host: {host}\r\n"
                    "User-Agent: OneLink/1.0\r\n"
                    "Connection: close\r\n\r\n"
                ).encode("ascii", "replace")
                s.sendall(req)
                chunks: list[bytes] = []
                total = 0
                while total < 64 * 1024:
                    chunk = s.recv(min(8192, 64 * 1024 - total))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                raw = b"".join(chunks)
                if b"\r\n\r\n" in raw:
                    raw = raw.split(b"\r\n\r\n", 1)[1]
                return raw.decode("utf-8", "replace")

        return await loop.run_in_executor(None, _get)
    except Exception as e:
        log.debug("ssdp xml fetch failed for %s: %s", url, e)
        return None


_UPNP_FIELD_RE = {
    "friendlyName": _re.compile(r"<friendlyName>(.*?)</friendlyName>", _re.I | _re.S),
    "manufacturer": _re.compile(r"<manufacturer>(.*?)</manufacturer>", _re.I | _re.S),
    "modelName":    _re.compile(r"<modelName>(.*?)</modelName>",       _re.I | _re.S),
    "modelNumber":  _re.compile(r"<modelNumber>(.*?)</modelNumber>",   _re.I | _re.S),
}


def parse_upnp_description(xml: str) -> dict[str, str]:
    """Extract friendlyName / manufacturer / modelName / modelNumber
    from a UPnP device-description XML. Tolerant of malformed XML —
    uses regex rather than an XML parser to keep this dependency-
    free."""
    out: dict[str, str] = {}
    for key, pat in _UPNP_FIELD_RE.items():
        m = pat.search(xml)
        if m:
            out[key] = m.group(1).strip()
    return out


async def enrich_via_ssdp_xml(
    devices: list[DiscoveredDevice],
) -> None:
    """For every device that has an SSDP LOCATION URL, fetch the XML
    and fill in hostname / vendor / model. Runs all fetches in
    parallel with a short per-fetch timeout."""
    targets = [d for d in devices if d.ssdp_location]
    if not targets:
        return
    xmls = await asyncio.gather(
        *[_fetch_ssdp_xml(d.ssdp_location) for d in targets],
        return_exceptions=True,
    )
    for d, xml in zip(targets, xmls):
        if isinstance(xml, BaseException) or not xml:
            continue
        info = parse_upnp_description(xml)
        if info.get("friendlyName") and not d.hostname:
            d.hostname = info["friendlyName"]
        if info.get("manufacturer") and not d.vendor:
            d.vendor = info["manufacturer"]
        if info.get("modelName"):
            mn = info["modelName"]
            if info.get("modelNumber"):
                mn = f"{mn} ({info['modelNumber']})"
            if not d.model or len(mn) > len(d.model):
                d.model = mn


# ── TCP fingerprint probe ──────────────────────────────────────────
#
# Connect to a curated list of well-known ports with a short
# timeout, read whatever banner comes back. Port portfolio +
# banners give us strong device identification when mDNS / SSDP /
# NetBIOS came up empty.


# port → (kind, vendor, label) when seen as the sole signal.
#
# Important: a vendor is ONLY listed here when the protocol is
# vendor-unique (Sonos on 1400, Roku on 8060, Spotify Connect on
# 4070, Chromecast on 8009, Plex on 32400, iOS lockdown on 62078,
# Microsoft RDP on 3389). Generic protocols (HTTP, SSH, SMB,
# AirPlay 2 port 7000 — open on Sony / LG / Samsung TVs too,
# Synology DSM port 5000 — also used by macOS) leave vendor blank
# so hostname-pattern / SSDP-XML / banner-grab can set it from
# authoritative signal.
_TCP_PORT_HINTS: dict[int, tuple[str, str, str]] = {
    22:    ("desktop", "",        "SSH server"),
    23:    ("iot",     "",        "Telnet (legacy)"),
    80:    ("",        "",        "HTTP server"),
    139:   ("desktop", "",        "Windows SMB"),
    443:   ("",        "",        "HTTPS server"),
    445:   ("desktop", "",        "Windows SMB"),
    548:   ("desktop", "",        "AFP file share"),
    554:   ("tv",      "",        "RTSP (camera/IPTV)"),
    631:   ("printer", "",        "IPP printer"),
    1400:  ("speaker", "Sonos",   "Sonos"),
    1883:  ("iot",     "",        "MQTT (IoT broker)"),
    2049:  ("desktop", "",        "NFS file share"),
    3389:  ("desktop", "Microsoft","Windows RDP"),
    4070:  ("speaker", "Spotify", "Spotify Connect"),
    5000:  ("desktop", "",        "Synology / mac service"),
    5001:  ("desktop", "",        "Synology / mac service"),
    5060:  ("iot",     "",        "SIP / VoIP"),
    7000:  ("",        "",        "AirPlay 2 / Sony / LG / Samsung TV"),
    8009:  ("tv",      "Google",  "Chromecast"),
    8060:  ("tv",      "Roku",    "Roku"),
    8080:  ("",        "",        "HTTP-alt"),
    8443:  ("",        "",        "HTTPS-alt"),
    9000:  ("",        "",        "audio / squeezebox / other"),
    9100:  ("printer", "",        "Raw printer"),
    32400: ("desktop", "Plex",    "Plex Media Server"),
    62078: ("phone",   "Apple",   "iOS lockdown"),
}


async def _tcp_probe_port(ip: str, port: int, timeout_s: float = 0.6) -> bool:
    """Return True iff the port accepts a TCP connection within
    `timeout_s`. Closes the socket immediately."""
    try:
        fut = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout_s)
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, RuntimeError) as exc:
            report_best_effort_failure(
                log,
                "lan_probe_writer_close",
                exc,
                level=logging.DEBUG,
            )
        return True
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return False


async def _tcp_grab_banner(ip: str, port: int, timeout_s: float = 0.8) -> str:
    """Connect, read at most 256 bytes, return whatever banner the
    server sends in the clear. Empty string if nothing arrives in
    `timeout_s`. For HTTP-ish ports we send a minimal GET first so
    the server actually replies with its Server: header."""
    try:
        fut = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout_s)
        try:
            if port in (80, 8080, 8060, 8009, 1400, 32400, 5000, 8443):
                writer.write(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                await writer.drain()
            data = await asyncio.wait_for(reader.read(256), timeout=timeout_s)
            return data.decode("utf-8", "replace")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, RuntimeError) as exc:
                report_best_effort_failure(
                    log,
                    "lan_banner_writer_close",
                    exc,
                    level=logging.DEBUG,
                )
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return ""


_BANNER_SIGNATURES: list[tuple[_re.Pattern[str], str, str, str]] = [
    (_re.compile(r"Roku/", _re.I),            "tv",      "Roku",        "Roku"),
    (_re.compile(r"Sonos", _re.I),            "speaker", "Sonos",       "Sonos"),
    (_re.compile(r"Plex Media Server", _re.I),"desktop", "Plex",        "Plex Server"),
    (_re.compile(r"Synology", _re.I),         "desktop", "Synology",    "Synology NAS"),
    (_re.compile(r"QNAP", _re.I),             "desktop", "QNAP",        "QNAP NAS"),
    (_re.compile(r"AirPlay", _re.I),          "speaker", "Apple",       "AirPlay device"),
    (_re.compile(r"OpenSSH", _re.I),          "desktop", "",            "Linux/Unix"),
    (_re.compile(r"Microsoft.*IIS", _re.I),   "desktop", "Microsoft",   "Windows server"),
    (_re.compile(r"\bRouter\b|\bGateway\b", _re.I), "router", "",       "Router"),
    (_re.compile(r"hue-bridgev", _re.I),      "iot",     "Philips Hue", "Hue Bridge"),
    (_re.compile(r"PlayStation|PS5|PS4", _re.I),"console","Sony",       "PlayStation"),
    (_re.compile(r"BRAVIA|Sony Corporation|Sony Bravia", _re.I),
                                              "tv",      "Sony",        "Sony BRAVIA"),
    (_re.compile(r"webOS|LG Electronics", _re.I),"tv",   "LG",          "LG TV"),
    (_re.compile(r"Tizen|Samsung Smart TV", _re.I),"tv", "Samsung",     "Samsung TV"),
    (_re.compile(r"HP-ChaiSOE|HP-IPP", _re.I),"printer", "HP",          "HP printer"),
    (_re.compile(r"EPSON|Epson", _re.I),      "printer", "Epson",       "Epson printer"),
    (_re.compile(r"Brother", _re.I),          "printer", "Brother",     "Brother printer"),
    (_re.compile(r"UniFi|Ubiquiti", _re.I),   "router",  "Ubiquiti",    "Ubiquiti"),
    (_re.compile(r"Nest|Google.*Cast", _re.I),"tv",      "Google",      "Google Cast / Nest"),
]


# ── Vendor-specific targeted probes ────────────────────────────────
#
# Once we know a Roku/Sonos/Hue/HTTP-root port is open, fetch the
# vendor's well-known device-info endpoint. Each returns rich XML/
# JSON with the actual model name. All LAN-local.


async def _fetch_http(url: str, timeout_s: float = 1.2) -> str:
    """Return the response body (truncated to 8 KB) or empty string
    on any failure. LAN-only and implemented with raw sockets so LAN
    discovery never depends on a high-level HTTP client."""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        if parsed.scheme != "http":
            return ""
        host = parsed.hostname or ""
        if not host:
            return ""
        try:
            ip_obj = ipaddress.ip_address(host)
        except ValueError:
            try:
                # Bounded: an SSDP LOCATION can name a host this network
                # cannot resolve, and the wait is unbounded otherwise.
                ip_obj = ipaddress.ip_address(resolve_bounded(
                    socket.gethostbyname,
                    host,
                    default="",
                    label="LAN discovery SSDP host resolution",
                ))
            except (socket.gaierror, ValueError):
                return ""
        if not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local):
            return ""
        port = parsed.port or 80
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
    except Exception:
        return ""

    loop = asyncio.get_running_loop()

    def _get() -> str:
        try:
            with socket.create_connection((str(ip_obj), port), timeout=timeout_s) as s:
                s.settimeout(timeout_s)
                req = (
                    f"GET {path} HTTP/1.0\r\n"
                    f"Host: {host}\r\n"
                    "User-Agent: OneLink/1.0\r\n"
                    "Connection: close\r\n\r\n"
                ).encode("ascii", "replace")
                s.sendall(req)
                chunks: list[bytes] = []
                total = 0
                while total < 8 * 1024:
                    chunk = s.recv(min(2048, 8 * 1024 - total))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                raw = b"".join(chunks)
                if b"\r\n\r\n" in raw:
                    raw = raw.split(b"\r\n\r\n", 1)[1]
                return raw.decode("utf-8", "replace")
        except Exception:
            return ""

    try:
        return await asyncio.wait_for(
            loop.run_in_executor(None, _get), timeout=timeout_s + 0.3,
        )
    except asyncio.TimeoutError:
        return ""


_ROKU_NAME_RE = _re.compile(
    r"<(?:friendly-device-name|user-device-name|model-name|"
    r"model-number)>(.*?)</",
    _re.I | _re.S,
)


async def probe_roku(dev: DiscoveredDevice) -> None:
    """If port 8060 is open, fetch http://ip:8060/query/device-info
    which returns full Roku model XML (user-device-name, model-name,
    model-number, friendly-device-name)."""
    if 8060 not in dev.open_ports:
        return
    xml = await _fetch_http(f"http://{dev.ip}:8060/query/device-info")
    if not xml:
        return
    fields: dict[str, str] = {}
    for m in _re.finditer(
        r"<(friendly-device-name|user-device-name|model-name|"
        r"model-number)>([^<]+)</\1>",
        xml, _re.I,
    ):
        fields[m.group(1).lower()] = m.group(2).strip()
    name = (
        fields.get("user-device-name")
        or fields.get("friendly-device-name")
        or ""
    )
    model = fields.get("model-name") or fields.get("model-number") or ""
    if name and (not dev.hostname or "roku" not in dev.hostname.lower()):
        dev.hostname = name
    if model:
        dev.model = f"Roku {model}" if not model.lower().startswith("roku") else model
    dev.kind = "tv"
    dev.vendor = "Roku"
    if "roku_probe" not in dev.sources:
        dev.sources.append("roku_probe")


async def probe_sonos(dev: DiscoveredDevice) -> None:
    """If port 1400 is open, fetch the Sonos device description XML.
    Sonos exposes friendlyName + modelName + zoneName + roomName."""
    if 1400 not in dev.open_ports:
        return
    xml = await _fetch_http(f"http://{dev.ip}:1400/xml/device_description.xml")
    if not xml:
        return
    info = parse_upnp_description(xml)
    if info.get("friendlyName") and not dev.hostname:
        dev.hostname = info["friendlyName"]
    if info.get("modelName"):
        dev.model = f"Sonos {info['modelName']}"
    dev.kind = "speaker"
    dev.vendor = "Sonos"
    if "sonos_probe" not in dev.sources:
        dev.sources.append("sonos_probe")


# Vendor keywords we look for in HTTP root responses. Mostly to
# catch Sony BRAVIA / LG webOS / Samsung Tizen / HP printer / etc.
# when the device exposes nothing else.
_HTTP_BODY_VENDOR_RE: list[tuple[_re.Pattern[str], str, str, str]] = [
    (_re.compile(r"BRAVIA|Sony Bravia", _re.I),    "tv",      "Sony",     "Sony BRAVIA"),
    (_re.compile(r"webOS|LG Smart", _re.I),         "tv",      "LG",       "LG webOS TV"),
    (_re.compile(r"Tizen|Samsung Smart", _re.I),   "tv",      "Samsung",  "Samsung Tizen TV"),
    (_re.compile(r"HP[- ]?LaserJet|HP[- ]?OfficeJet|HP[- ]?Envy", _re.I),
                                                    "printer", "HP",       "HP printer"),
    (_re.compile(r"Synology DiskStation", _re.I),  "desktop", "Synology", "Synology NAS"),
    (_re.compile(r"QNAP", _re.I),                  "desktop", "QNAP",     "QNAP NAS"),
    (_re.compile(r"Hue Personal", _re.I),          "iot",     "Philips",  "Hue Bridge"),
    (_re.compile(r"TP-?Link", _re.I),              "router",  "TP-Link",  "TP-Link router"),
    (_re.compile(r"ASUS Router|ASUSWRT", _re.I),   "router",  "ASUS",     "ASUS router"),
    (_re.compile(r"Netgear", _re.I),               "router",  "Netgear",  "Netgear router"),
    (_re.compile(r"Tesla Wall|Tesla Inc", _re.I),  "iot",     "Tesla",    "Tesla"),
]


async def probe_http_root(dev: DiscoveredDevice) -> None:
    """If port 80 / 8080 is open and we don't yet have a vendor,
    fetch the root page and scan the response (Server header +
    body) for vendor keywords."""
    if dev.vendor and dev.kind != "unknown" and dev.model:
        return
    port = 80 if 80 in dev.open_ports else (8080 if 8080 in dev.open_ports else None)
    if port is None:
        return
    # Banner-grab (which sends GET / over a raw socket so we see
    # full headers + first ~256 bytes of body).
    raw = await _tcp_grab_banner(dev.ip, port, timeout_s=1.0)
    if not raw:
        return
    # Headers + body together.
    for pat, kind, vendor, label in _HTTP_BODY_VENDOR_RE:
        if pat.search(raw):
            if dev.kind in ("unknown", "") and kind:
                dev.kind = kind
            if not dev.vendor and vendor:
                dev.vendor = vendor
            if not dev.model and label:
                dev.model = label
            if "http_probe" not in dev.sources:
                dev.sources.append("http_probe")
            return


async def enrich_via_vendor_probes(
    devices: list[DiscoveredDevice],
) -> None:
    """Run Roku / Sonos / HTTP-root probes in parallel for any
    device that hasn't been fully identified yet. Each individual
    probe is a no-op if its trigger port isn't open."""
    tasks: list = []
    for d in devices:
        if not d.ip:
            continue
        tasks.append(probe_roku(d))
        tasks.append(probe_sonos(d))
        tasks.append(probe_http_root(d))
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)


# ── Persistent device memory (sticky identification) ───────────────
#
# A small SQLite cache that remembers what we've previously learned
# about each (mac-or-ip) device. Two benefits:
#   1. A re-scan that misses some signal (mDNS timeouts, captive
#      portal flicker, etc.) doesn't downgrade the device's
#      identification — we re-hydrate the cached kind/vendor/model.
#   2. The UI can show "first seen 3 days ago" / "last seen 2
#      minutes ago" for trust signals.
#
# Local-only SQLite file at `data_dir() / discovered_devices.db`.
# Wiping it = delete the file.


_DEVICE_MEMORY_SCHEMA = """
CREATE TABLE IF NOT EXISTS discovered_devices (
    key TEXT PRIMARY KEY,             -- mac if known, else ip
    ip TEXT,
    mac TEXT,
    hostname TEXT,
    vendor TEXT,
    model TEXT,
    kind TEXT,
    open_ports TEXT,
    mdns_services TEXT,
    first_seen_ms INTEGER NOT NULL,
    last_seen_ms INTEGER NOT NULL,
    seen_count INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_disco_last_seen
    ON discovered_devices(last_seen_ms);
"""


def _device_memory_db_path() -> Path:
    """Resolve `<data_dir>/discovered_devices.db` lazily so import
    of this module doesn't touch the filesystem."""
    from one_link.paths import data_dir
    p = data_dir() / "discovered_devices.db"
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _open_device_memory():
    """Open the SQLite cache, creating the schema on first use.
    Returns None if SQLite is unavailable (very rare)."""
    try:
        import sqlite3
        conn = sqlite3.connect(
            str(_device_memory_db_path()),
            isolation_level=None,
            check_same_thread=False,
        )
        conn.executescript(_DEVICE_MEMORY_SCHEMA)
        return conn
    except Exception as e:
        log.debug("device memory db open failed: %s", e)
        return None


def _device_key(d: DiscoveredDevice) -> str:
    """Stable key — MAC if we have it (survives DHCP renewal),
    otherwise IP."""
    return d.mac.lower() if d.mac else d.ip


def rehydrate_from_cache(devices: list[DiscoveredDevice]) -> None:
    """Fill in missing fields from the device-memory cache. Always
    prefers fresh signal over cached signal — cache only ever fills
    EMPTY fields. Updates `last_seen_ms` + bumps `seen_count`."""
    if not devices:
        return
    conn = _open_device_memory()
    if conn is None:
        return
    try:
        import json as _json
        now_ms = int(time.time() * 1000)
        for d in devices:
            key = _device_key(d)
            if not key:
                continue
            row = conn.execute(
                "SELECT hostname, vendor, model, kind, open_ports, "
                "mdns_services, first_seen_ms, seen_count "
                "FROM discovered_devices WHERE key=?",
                (key,),
            ).fetchone()
            if row:
                (c_host, c_vendor, c_model, c_kind, c_ports,
                 c_svcs, first_seen, seen_count) = row
                # Fill in EMPTY fields from cache. Never overwrite
                # fresh signal.
                if not d.hostname and c_host:
                    d.hostname = c_host
                if not d.vendor and c_vendor:
                    d.vendor = c_vendor
                if not d.model and c_model:
                    d.model = c_model
                if d.kind == "unknown" and c_kind and c_kind != "unknown":
                    d.kind = c_kind
                if not d.open_ports and c_ports:
                    try:
                        d.open_ports = _json.loads(c_ports)
                    except (_json.JSONDecodeError, TypeError) as exc:
                        report_best_effort_failure(
                            log,
                            "device_cache_open_ports_decode",
                            exc,
                            level=logging.DEBUG,
                        )
                if not d.mdns_services and c_svcs:
                    try:
                        d.mdns_services = _json.loads(c_svcs)
                    except (_json.JSONDecodeError, TypeError) as exc:
                        report_best_effort_failure(
                            log,
                            "device_cache_services_decode",
                            exc,
                            level=logging.DEBUG,
                        )
                if "cache" not in d.sources:
                    d.sources.append("cache")
                # Write back: bump counter, update last_seen, refresh
                # any fields that improved this round.
                conn.execute(
                    "UPDATE discovered_devices SET "
                    "  ip=?, mac=?, hostname=?, vendor=?, model=?, "
                    "  kind=?, open_ports=?, mdns_services=?, "
                    "  last_seen_ms=?, seen_count=? "
                    "WHERE key=?",
                    (d.ip, d.mac, d.hostname, d.vendor, d.model,
                     d.kind, _json.dumps(d.open_ports),
                     _json.dumps(d.mdns_services),
                     now_ms, seen_count + 1, key),
                )
            else:
                # First time we've seen this device.
                conn.execute(
                    "INSERT INTO discovered_devices "
                    "(key, ip, mac, hostname, vendor, model, kind, "
                    " open_ports, mdns_services, first_seen_ms, "
                    " last_seen_ms, seen_count) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,1)",
                    (key, d.ip, d.mac, d.hostname, d.vendor,
                     d.model, d.kind,
                     _json.dumps(d.open_ports),
                     _json.dumps(d.mdns_services),
                     now_ms, now_ms),
                )
    except Exception as e:
        log.debug("device memory rehydrate failed: %s", e)
    finally:
        try:
            conn.close()
        except Exception as exc:
            report_best_effort_failure(
                log,
                "device_cache_rehydrate_close",
                exc,
                level=logging.DEBUG,
            )


def load_recent_cached_devices(max_age_ms: int = 24 * 3600 * 1000,
                               limit: int = 100,
                               ) -> list[DiscoveredDevice]:
    """Return cached devices last seen within `max_age_ms`. Used as
    a backstop when a fresh scan returns nothing (e.g., AP isolation
    or scan failure) — we can still show 'devices we've seen here
    before' so the UI never goes empty after the first scan."""
    conn = _open_device_memory()
    if conn is None:
        return []
    try:
        import json as _json
        cutoff = int(time.time() * 1000) - max_age_ms
        rows = conn.execute(
            "SELECT ip, mac, hostname, vendor, model, kind, "
            "       open_ports, mdns_services, last_seen_ms "
            "FROM discovered_devices "
            "WHERE last_seen_ms >= ? "
            "ORDER BY last_seen_ms DESC LIMIT ?",
            (cutoff, limit),
        ).fetchall()
        out: list[DiscoveredDevice] = []
        for r in rows:
            ip, mac, host, vendor, model, kind, ports, svcs, _last = r
            try:
                op = _json.loads(ports) if ports else []
            except Exception:
                op = []
            try:
                ms = _json.loads(svcs) if svcs else []
            except Exception:
                ms = []
            out.append(DiscoveredDevice(
                ip=ip or "", mac=mac or "", hostname=host or "",
                vendor=vendor or "", model=model or "",
                kind=kind or "unknown",
                open_ports=op, mdns_services=ms,
                sources=["cache"], confidence=0.4,
            ))
        return out
    except Exception as e:
        log.debug("device memory load failed: %s", e)
        return []
    finally:
        try:
            conn.close()
        except Exception as exc:
            report_best_effort_failure(
                log,
                "device_cache_load_close",
                exc,
                level=logging.DEBUG,
            )


async def enrich_via_tcp_probe(
    devices: list[DiscoveredDevice],
    *,
    only_unidentified: bool = True,
    per_port_timeout_s: float = 0.5,
) -> None:
    """Probe each device's well-known ports in parallel. Updates
    `open_ports`, then maps the port portfolio + any banner to a
    kind/vendor.

    `only_unidentified=True` (default) skips devices that already
    have a confirmed kind, vendor, AND model — those don't need
    further fingerprinting.
    """
    targets = [
        d for d in devices
        if not only_unidentified or d.kind in ("unknown", "")
        or not d.vendor or not d.hostname
    ]
    if not targets:
        return
    ports = list(_TCP_PORT_HINTS.keys())

    async def _probe_device(d: DiscoveredDevice) -> None:
        if not d.ip:
            return
        results = await asyncio.gather(
            *[_tcp_probe_port(d.ip, p, per_port_timeout_s) for p in ports],
            return_exceptions=True,
        )
        open_now = [
            p for p, ok in zip(ports, results)
            if ok is True
        ]
        if not open_now:
            return
        for p in open_now:
            if p not in d.open_ports:
                d.open_ports.append(p)
        if "tcp_probe" not in d.sources:
            d.sources.append("tcp_probe")
        # Walk the port → (kind, vendor, label) hints; first strong
        # one wins (i.e., port with non-empty vendor).
        best_kind = ""
        best_vendor = ""
        best_label = ""
        for p in open_now:
            kind, vendor, label = _TCP_PORT_HINTS.get(p, ("", "", ""))
            if vendor and not best_vendor:
                best_vendor = vendor
            if kind and not best_kind:
                best_kind = kind
            if label and not best_label:
                best_label = label
        # If we have a high-signal port (Sonos 1400, Chromecast 8009,
        # Roku 8060, Plex 32400, Synology 5000, Hue 80 → handled via
        # banner below), grab its banner for extra confirmation.
        banner_ports = [p for p in open_now if p in (80, 8060, 8009, 1400, 32400, 5000, 8080, 22)]
        for bp in banner_ports[:3]:  # cap at 3 banner grabs per host
            banner = await _tcp_grab_banner(d.ip, bp)
            if not banner:
                continue
            for pat, k, v, label in _BANNER_SIGNATURES:
                if pat.search(banner):
                    if k and not best_kind:
                        best_kind = k
                    if v and not best_vendor:
                        best_vendor = v
                    if label and not best_label:
                        best_label = label
                    break
        # Apply.
        if best_kind and d.kind in ("unknown", ""):
            d.kind = best_kind
        if best_vendor and not d.vendor:
            d.vendor = best_vendor
        if best_label and not d.model:
            d.model = best_label

    await asyncio.gather(*[_probe_device(d) for d in targets], return_exceptions=True)


# ── Reverse DNS backstop ───────────────────────────────────────────


async def enrich_via_reverse_dns(devices: list[DiscoveredDevice]) -> None:
    """For devices with no hostname, try `socket.gethostbyaddr(ip)`.
    Best-effort: short timeout, errors swallowed. Some routers
    return PTR records like `192-168-1-50.lan` which we discard."""
    loop = asyncio.get_running_loop()
    targets = [d for d in devices if d.ip and not d.hostname]
    if not targets:
        return

    def _rev(ip: str) -> str:
        try:
            # A LAN with no reverse-DNS server makes this wait out the full
            # resolver retry schedule per address. A missing friendly name is
            # cosmetic; the wait is not.
            host = resolve_bounded(
                socket.gethostbyaddr,
                ip,
                default=("", [], []),
                label="LAN discovery reverse lookup",
            )[0]
            # Discard reverse-IP-style names that aren't useful.
            if not host or host == ip:
                return ""
            ipstub = ip.replace(".", "-")
            if ipstub in host:
                return ""
            return host
        except (socket.herror, socket.gaierror, OSError):
            return ""

    async def _one(d: DiscoveredDevice) -> None:
        try:
            host = await asyncio.wait_for(
                loop.run_in_executor(None, _rev, d.ip), timeout=0.7,
            )
            if host:
                d.hostname = host.split(".")[0]
        except asyncio.TimeoutError:
            return

    await asyncio.gather(*[_one(d) for d in targets], return_exceptions=True)


def _infer_kind(dev: DiscoveredDevice) -> str:
    """Look at the merged signals and guess the device kind.
    Returns one of: phone, tablet, mobile, laptop, desktop, tv, speaker,
    printer, router, watch, console, iot, unknown.

    Inference order (strongest signal first):
      1. Hostname patterns (PS5-*, Roku-*, HomePod-*, ...)
      2. mDNS service portfolio + model strings
      3. TCP port hints (set during enrichment, also a fallback here)
      4. Vendor heuristics
    """
    # 1. Hostname pattern is the most specific signal we have.
    host = (dev.hostname or "").lower()
    if host:
        for pat, kind, _vendor, _label in _HOSTNAME_PATTERNS:
            if pat.search(host):
                return kind

    svcs = set(dev.mdns_services)
    vendor = (dev.vendor or "").lower()
    model = (dev.model or "").lower()
    combined = f"{host} {model}".strip()

    # 2. mDNS portfolio signatures (with disambiguation).
    if "_apple-mobdev2" in svcs:
        return "phone"
    if "_companion-link" in svcs or "_airdrop" in svcs:
        if "iphone" in model:    return "phone"
        if "ipad" in model:      return "tablet"
        if "macbook" in model:   return "laptop"
        if any(x in model for x in ("imac", "macmini", "macpro", "macstudio")):
            return "desktop"
        if "watch" in model:     return "watch"
        if "ps5" in combined or "ps4" in combined or "playstation" in combined:
            return "console"
        return "mobile"
    if "_airplay" in svcs and "_raop" in svcs:
        # AirPlay receiver. Could be Apple TV / HomePod / Sonos /
        # smart-speaker / PS5 / smart-TV. Discriminate by host/model.
        if any(x in combined for x in ("apple tv", "appletv")):  return "tv"
        if "homepod" in combined:                                return "speaker"
        if "sonos" in combined:                                  return "speaker"
        if "ps5" in combined or "playstation" in combined:       return "console"
        if any(x in combined for x in ("tv", "bravia", "lg-", "samsung", "webos")):
            return "tv"
        return "speaker"
    if "_googlecast" in svcs:    return "tv"
    if "_spotify-connect" in svcs: return "speaker"
    if "_ipp" in svcs or "_ipps" in svcs or "_printer" in svcs:
        return "printer"
    if "_homekit" in svcs:       return "iot"
    if "_ssh" in svcs:           return "desktop"

    # 3. Open TCP ports — high-signal port portfolios.
    op = set(dev.open_ports)
    if 8009 in op:           return "tv"        # Chromecast
    if 8060 in op:           return "tv"        # Roku
    if 1400 in op:           return "speaker"   # Sonos
    if 32400 in op:          return "desktop"   # Plex
    if 7000 in op:           return "speaker"   # AirPlay 2
    if 62078 in op:          return "phone"     # iOS lockdown
    if 5555 in op:           return "phone"     # Android debug bridge
    if 631 in op or 9100 in op: return "printer"
    if 3389 in op:           return "desktop"   # Windows RDP
    if 5000 in op or 5001 in op or 548 in op:
        return "desktop"

    # 4. Vendor heuristics.
    if "raspberry" in vendor:     return "iot"
    if "roku" in vendor:          return "tv"
    if "sonos" in vendor:         return "speaker"
    if "tp-link" in vendor or "router" in vendor or "netgear" in vendor:
        return "router"
    if "tesla" in vendor:         return "iot"
    if "ring" in vendor or "wyze" in vendor:
        return "iot"
    if is_locally_administered_mac(dev.mac) and not op:
        # iOS/Android private Wi-Fi addresses intentionally erase OUI
        # vendor identity. If the host is otherwise quiet and only
        # visible through ARP, surface it as a mobile candidate instead
        # of burying it under "unknown". This is a confidence-limited
        # hint, not a claim that we defeated phone privacy.
        return "mobile"
    return "unknown"


def _is_pairable_kind(kind: str) -> bool:
    """One Link pairs to user-controlled compute. TVs, speakers,
    printers, IoT — visible but not the primary pair target."""
    return kind in ("phone", "tablet", "mobile", "laptop", "desktop", "watch")


def merge_devices(*lists: list[DiscoveredDevice]) -> list[DiscoveredDevice]:
    """Fuse results from multiple scanners. Keys by (IP, MAC); if a
    device has IP but no MAC, the IP alone keys it; an ARP entry
    later supplies the MAC and the records merge. Confidence
    accumulates: each independent source adds 0.15, capped at 1.0."""
    by_key: dict[str, DiscoveredDevice] = {}
    for batch in lists:
        for dev in batch:
            if not dev.ip and not dev.mac:
                continue
            # Prefer IP as primary key (every device has one on the
            # LAN); fall back to MAC if mDNS returned a hostname
            # but no resolvable IP yet.
            key = dev.ip or dev.mac
            existing = by_key.get(key)
            if existing is None:
                by_key[key] = DiscoveredDevice(**asdict(dev))
                continue
            # Merge fields. Don't overwrite a known-good value with
            # an empty string.
            for f in ("ip", "mac", "hostname", "vendor", "model"):
                if not getattr(existing, f) and getattr(dev, f):
                    setattr(existing, f, getattr(dev, f))
            existing.mdns_services = sorted(
                set(existing.mdns_services) | set(dev.mdns_services)
            )
            existing.open_ports = sorted(
                set(existing.open_ports) | set(dev.open_ports)
            )
            for src in dev.sources:
                if src not in existing.sources:
                    existing.sources.append(src)
            existing.confidence = min(
                1.0,
                existing.confidence + 0.15 * len(set(dev.sources) - set(existing.sources[:-1])),
            )
            existing.is_one_link_peer = existing.is_one_link_peer or dev.is_one_link_peer
    # Post-merge: backfill vendor + kind on every device.
    for dev in by_key.values():
        if dev.mac and not dev.vendor:
            dev.vendor = vendor_for_mac(dev.mac)
        if dev.kind == "unknown":
            dev.kind = _infer_kind(dev)
        # Recalculate confidence from source count + signal richness.
        n_sources = len(dev.sources)
        signal_richness = 0
        if dev.vendor: signal_richness += 1
        if dev.hostname: signal_richness += 1
        if dev.mdns_services: signal_richness += 1
        if dev.kind != "unknown": signal_richness += 1
        dev.confidence = round(
            min(1.0, 0.25 * n_sources + 0.10 * signal_richness),
            2,
        )
    return list(by_key.values())


# ── Top-level scan ─────────────────────────────────────────────────


async def full_scan(
    timeout_s: float = 6.0,
    *,
    one_link_peers: Optional[list[dict]] = None,
) -> list[DiscoveredDevice]:
    """Run every scanner in parallel and return merged results.

    ``one_link_peers`` is an optional list of already-known One Link
    peers (from the existing mDNS discovery for our specific
    service). We use them to flag devices as `is_one_link_peer=True`
    by IP match.
    """
    loop = asyncio.get_running_loop()
    mdns_task = asyncio.create_task(scan_mdns_browse_all(timeout_s=timeout_s))
    arp_task = loop.run_in_executor(None, scan_arp_table)
    ssdp_task = loop.run_in_executor(None, scan_ssdp)
    netbios_task = loop.run_in_executor(None, scan_netbios)
    results = await asyncio.gather(
        mdns_task, arp_task, ssdp_task, netbios_task,
        return_exceptions=True,
    )
    batches: list[list[DiscoveredDevice]] = []
    for r in results:
        if isinstance(r, BaseException):
            log.debug("scanner failed: %s", r)
            continue
        batches.append(r)
    merged = merge_devices(*batches)

    # Enrichment passes.
    # Round 1: independent enrichments that need no prior signal.
    await asyncio.gather(
        enrich_via_ssdp_xml(merged),
        enrich_via_tcp_probe(merged),
        enrich_via_reverse_dns(merged),
        return_exceptions=True,
    )
    # Round 2: vendor-specific probes that depend on `open_ports`
    # being populated (Roku 8060, Sonos 1400, HTTP-root 80/8080).
    # Runs after Round 1 so port discovery has completed.
    await enrich_via_vendor_probes(merged)

    # Round 3: rehydrate from persistent cache so a re-scan that
    # missed some signal still benefits from prior knowledge. Also
    # records the fresh signal back to the cache for next time.
    try:
        rehydrate_from_cache(merged)
    except Exception as e:
        log.debug("rehydrate_from_cache skipped: %s", e)

    # Re-walk inference now that enrichment may have added hostname /
    # vendor / open_ports / model.
    gateway_ip = _default_gateway()
    _UUID_RE = _re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-", _re.I)
    for d in merged:
        # If the device IP is the default gateway, it's the router
        # regardless of what other heuristics decided.
        if gateway_ip and d.ip == gateway_ip:
            d.kind = "router"
            if not d.hostname:
                d.hostname = "Router"
            continue
        # If hostname looks like a UUID and we got a useful model
        # name (e.g., "BRAVIA 4K AE2" from SSDP XML), prefer the
        # model as the display name.
        if d.hostname and _UUID_RE.match(d.hostname) and d.model:
            d.hostname = d.model
        # Apply hostname-pattern table (vendor + kind fill-ins).
        apply_hostname_pattern(d)
        if d.kind == "unknown":
            d.kind = _infer_kind(d)

    # Mark already-paired peers + filter out self.
    self_ips = set(_local_ips())
    one_link_ips = set()
    one_link_macs = set()
    if one_link_peers:
        for p in one_link_peers:
            if p.get("address"):
                one_link_ips.add(p["address"])
            if p.get("mac"):
                one_link_macs.add(p["mac"].lower())
    for dev in merged:
        if dev.ip in self_ips:
            dev.is_one_link_peer = True  # ourselves; we'll filter
        if dev.ip in one_link_ips or dev.mac.lower() in one_link_macs:
            dev.is_one_link_peer = True
    # Exclude self.
    merged = [d for d in merged if d.ip not in self_ips]
    # Sort: pairable kinds first, then by hostname/IP for stability.
    merged.sort(key=lambda d: (
        0 if d.is_one_link_peer else 1,
        0 if _is_pairable_kind(d.kind) else 1,
        -d.confidence,
        d.hostname or d.ip,
    ))
    return merged


def _local_ips() -> list[str]:
    """Return this machine's own LAN IP addresses (so we filter
    ourselves out of the discovery results)."""
    ips: set[str] = set()
    try:
        # Bounded: same own-name resolution that blocked a macOS daemon for
        # 64s. Failing to filter ourselves out of discovery results is a
        # cosmetic defect; stalling the caller is not.
        for fam, _t, _p, _c, sockaddr in resolve_bounded(
            socket.getaddrinfo,
            socket.gethostname(),
            None,
            default=[],
            label="LAN discovery self-address enumeration",
        ):
            if fam == socket.AF_INET:
                ips.add(str(sockaddr[0]))
    except OSError as exc:
        # If this lookup fails, loopback is still filtered below. Log the
        # degraded self-filter so a local interface showing up as a duplicate
        # device is diagnosable instead of looking like a remote peer.
        report_best_effort_failure(
            log, "local_ip_enumeration", exc, level=logging.DEBUG
        )
    # Loopback is always self.
    ips.add("127.0.0.1")
    return list(ips)


# ── Network health hints (Phase 4) ─────────────────────────────────


@dataclass
class NetworkHealth:
    """One-shot diagnostic about the current network. Surfaced to the
    user when discovery returns 0 results despite the daemon being
    on a network."""
    ap_isolation_suspected: bool = False
    captive_portal_suspected: bool = False
    ipv6_only_suspected: bool = False
    has_default_gateway: bool = True
    gateway_ip: str = ""
    reasons: list[str] = field(default_factory=list)


def assess_network_health(devices: list[DiscoveredDevice]) -> NetworkHealth:
    """Heuristic look at the scan results. Tells the user why a
    discovery turned up empty."""
    h = NetworkHealth()
    h.gateway_ip = _default_gateway() or ""
    h.has_default_gateway = bool(h.gateway_ip)
    if not h.has_default_gateway:
        h.reasons.append(
            "This device has no default gateway. You may not be "
            "connected to any network."
        )
        return h
    # AP isolation: gateway responds to ARP (we have a gateway IP)
    # but discovery returned ZERO non-self devices.
    non_self = [d for d in devices if d.ip != h.gateway_ip]
    if not non_self:
        h.ap_isolation_suspected = True
        h.reasons.append(
            "Your Wi-Fi may be blocking devices from seeing each "
            "other (a setting called 'AP isolation' or 'client "
            "isolation' on the router). One Link still works once "
            "devices are paired; pairing on this network won't."
        )
    return h


def _default_gateway() -> str:
    """Best-effort default-gateway lookup. Used only to assess
    network health; never to send packets to."""
    if os.name == "nt":
        try:
            argv = resolve_argv(
                ["route.exe", "print", "0.0.0.0"],
                system_tool=True,
            )
            res = subprocess.run(
                argv,
                capture_output=True, text=True, timeout=2.0,
                creationflags=hidden_creationflags(),
                cwd=str(Path(argv[0]).parent),
                env=trusted_process_env(),
                check=False,
                shell=False,
            )
            for line in res.stdout.splitlines():
                # Default-route lines look like:
                # 0.0.0.0  0.0.0.0  192.168.1.1  192.168.1.42  ...
                m = re.search(
                    r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+"
                    r"(\d+\.\d+\.\d+\.\d+)",
                    line,
                )
                if m:
                    return m.group(1)
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            report_best_effort_failure(
                log, "windows_default_gateway", exc, level=logging.DEBUG
            )
    else:
        try:
            argv = resolve_argv(
                ["ip", "route", "show", "default"],
                system_tool=True,
            )
            res = subprocess.run(
                argv,
                capture_output=True, text=True, timeout=2.0,
                cwd=str(Path(argv[0]).parent),
                env=trusted_process_env(),
                check=False,
                shell=False,
            )
            m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", res.stdout)
            if m:
                return m.group(1)
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            report_best_effort_failure(
                log, "posix_default_gateway", exc, level=logging.DEBUG
            )
    return ""
