"""Live browser-engine proofs for the browser-peer transport surface.

These tests deliberately use the shipped ``/peer`` document rather than
extracting/evaluating snippets from ``peer.html``.  The page is loaded from the
daemon's real TLS listener with its real CSP, while rendezvous runs as a second
TLS origin.  The manual WebRTC test uses two isolated browser contexts so each
side owns a distinct OPFS identity, just like two physical browsers.

The whole module remains behind the suite-wide
``ONE_LINK_RUN_BROWSER_E2E=1`` gate in ``tests/e2e/conftest.py``.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import json
import os
import queue
import re
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

import pytest

# Live WebRTC handshakes (DTLS + SCTP between two browser contexts) are
# measured in single-digit seconds on dev hardware and can legitimately take
# far longer on a shared 2-vCPU CI runner already hosting two Chromium
# processes and two daemons. A 20s ceiling failed the release E2E gate on
# exactly that contention; the assertion is unchanged -- a handshake that
# never completes still fails, just after an honest budget for the machine
# class it runs on.
_LIVE_RTC_TIMEOUT_MS = 60_000 if os.environ.get("CI") == "true" else 20_000
from aiohttp import web
from playwright.sync_api import (
    Browser,
    BrowserContext,
    BrowserType,
    Page,
    Route,
    TimeoutError as PlaywrightTimeoutError,
)

from one_link.peer_https import build_ssl_context
from one_link.rendezvous_server import RendezvousApp, ServerConfig
from tests.e2e.browser_readiness import launch_settled_many


_PEER_CSP_PARTS = (
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline'",
    "'wasm-unsafe-eval'",
    "worker-src 'self'",
    "connect-src 'self' wss: https:",
    "frame-ancestors 'none'",
)
_IDENTITY_PASSPHRASE = "correct horse battery staple 2026"
_REGISTER_ACK_KEYS = {
    "expires_at_ms",
    "observed_host",
    "observed_port",
    "server_time_ms",
    "type",
    "v",
}
_LOOKUP_ACK_KEYS = {
    "advertised_endpoints",
    "capabilities",
    "expires_at_ms",
    "nat_type",
    "observed_endpoint",
    "pubkey_b64",
    "server_time_ms",
    "type",
    "v",
}
_SIGNAL_KEYS = {
    "body",
    "sender_pubkey_b64",
    "signature",
    "timestamp_ms",
    "type",
    "v",
}
_SCRIPTED_RDZ_ORIGIN = "https://rendezvous-boundary.invalid"


@dataclass(frozen=True)
class LiveHttpsRendezvous:
    """A real RendezvousApp listening on a dedicated TLS origin."""

    origin: str
    observed_requests: list[dict[str, str]]


@pytest.fixture(autouse=True)
def _no_public_browser_ice(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the local two-browser proof independent of public STUN health."""

    monkeypatch.setenv("ONE_LINK_STUN_SERVERS", "")


@pytest.fixture
def live_https_rendezvous(tmp_path: Path) -> Iterator[LiveHttpsRendezvous]:
    """Run RendezvousApp on TLS in a private event-loop thread.

    Chromium ignores only this test certificate's trust error.  CSP and CORS
    enforcement stay enabled; in particular, the browser must complete the
    real JSON preflight before it can read ``RegisterAck``.
    """

    startup: queue.Queue[tuple[str, Any]] = queue.Queue(maxsize=1)
    observed_requests: list[dict[str, str]] = []
    loop_holder: dict[str, asyncio.AbstractEventLoop] = {}

    def _thread_main() -> None:
        loop = asyncio.new_event_loop()
        loop_holder["loop"] = loop
        asyncio.set_event_loop(loop)
        runner: web.AppRunner | None = None
        try:
            rendezvous = RendezvousApp(
                ServerConfig(host="127.0.0.1", port=0, enable_relay=False),
            )
            app = rendezvous.make_app()

            @web.middleware
            async def _capture_request(request: web.Request, handler):
                observed_requests.append(
                    {
                        "method": request.method,
                        "path": request.path,
                        "origin": request.headers.get("Origin", ""),
                        "requested_method": request.headers.get(
                            "Access-Control-Request-Method",
                            "",
                        ),
                        "requested_headers": request.headers.get(
                            "Access-Control-Request-Headers",
                            "",
                        ),
                    },
                )
                return await handler(request)

            # Capture outside the production middleware chain; the handlers,
            # rate limits, schemas, signature verification, and CORS response
            # still come from RendezvousApp itself.
            app.middlewares.insert(0, _capture_request)
            runner = web.AppRunner(app, access_log=None)
            loop.run_until_complete(runner.setup())
            tls = build_ssl_context(tmp_path / "rendezvous-tls")
            if tls is None:
                raise RuntimeError("test TLS context was not created")
            site = web.TCPSite(
                runner,
                host="127.0.0.1",
                port=0,
                ssl_context=tls,
            )
            loop.run_until_complete(site.start())
            server = getattr(site, "_server", None)
            sockets = list(getattr(server, "sockets", ()) or ())
            if not sockets:
                raise RuntimeError("TLS rendezvous listener has no bound socket")
            port = int(sockets[0].getsockname()[1])
            startup.put(("ready", f"https://127.0.0.1:{port}"))
            loop.run_forever()
        except BaseException as exc:  # propagate startup failures to pytest
            with contextlib.suppress(queue.Full):
                startup.put_nowait(("error", exc))
        finally:
            if runner is not None:
                with contextlib.suppress(BaseException):
                    loop.run_until_complete(runner.cleanup())
                # Proactor SSL transports finish their close_notify work on a
                # later loop turn.  Closing the loop immediately after
                # AppRunner.cleanup leaves a real socket for Python's GC and
                # turns -W error into an unraisable ResourceWarning.
                with contextlib.suppress(BaseException):
                    loop.run_until_complete(asyncio.sleep(0.25))
            with contextlib.suppress(BaseException):
                loop.run_until_complete(loop.shutdown_asyncgens())
            loop.close()

    thread = threading.Thread(
        target=_thread_main,
        name="one-link-e2e-rendezvous-tls",
        daemon=True,
    )
    thread.start()
    try:
        kind, value = startup.get(timeout=20.0)
    except queue.Empty as exc:
        raise RuntimeError("TLS rendezvous fixture did not start within 20s") from exc
    if kind != "ready":
        thread.join(timeout=5.0)
        raise RuntimeError("TLS rendezvous fixture failed to start") from value

    origin = str(value)
    try:
        yield LiveHttpsRendezvous(
            origin=origin,
            observed_requests=observed_requests,
        )
    finally:
        loop = loop_holder.get("loop")
        if isinstance(loop, asyncio.AbstractEventLoop) and not loop.is_closed():
            loop.call_soon_threadsafe(loop.stop)
        thread.join(timeout=15.0)
        if thread.is_alive():
            raise RuntimeError("TLS rendezvous fixture did not shut down")


def _wait_for_daemon_https(live_daemon: Any, timeout_s: float = 20.0) -> str:
    """Return the daemon's actual TLS origin from its startup evidence."""

    deadline = time.monotonic() + timeout_s
    pattern = re.compile(r"UI server HTTPS up.*?https://[^:]+:(\d+)/")
    last_log = ""
    while time.monotonic() < deadline:
        with contextlib.suppress(OSError):
            last_log = live_daemon.log.read_text(
                encoding="utf-8",
                errors="replace",
            )
            matches = pattern.findall(last_log)
            if matches:
                return f"https://127.0.0.1:{int(matches[-1])}"
        if live_daemon.proc.poll() is not None:
            raise RuntimeError(
                "daemon exited before its HTTPS listener became ready\n" + last_log[-4000:],
            )
        time.sleep(0.05)
    raise RuntimeError(
        f"daemon HTTPS listener did not become ready within {timeout_s:.0f}s\n{last_log[-4000:]}",
    )


def _new_browser_context(browser: Browser) -> BrowserContext:
    return browser.new_context(
        ignore_https_errors=True,
        color_scheme="dark",
        viewport={"width": 1280, "height": 900},
    )


def _open_real_peer(page: Page, peer_origin: str) -> str:
    response = page.goto(
        f"{peer_origin}/peer",
        wait_until="domcontentloaded",
        timeout=30_000,
    )
    assert response is not None
    assert response.status == 200
    csp = response.headers.get("content-security-policy", "")
    for required in _PEER_CSP_PARTS:
        assert required in csp
    assert page.evaluate("() => window.isSecureContext") is True
    page.wait_for_function(
        """() => Boolean(
            window.__oneLinkPeer?.state?.rec?.private_key_jwk ||
            window.__oneLinkPeer?.state?.pending_rec?.private_key_jwk ||
            window.__oneLinkPeer?.state?.envelope ||
            window.__oneLinkPeer?.state?.boot_error_msg
        )""",
        timeout=_LIVE_RTC_TIMEOUT_MS,
    )
    phase = page.evaluate(
        """() => ({
            ready: Boolean(window.__oneLinkPeer.state.rec),
            setup: Boolean(window.__oneLinkPeer.state.pending_rec),
            locked: Boolean(window.__oneLinkPeer.state.envelope),
            error: window.__oneLinkPeer.state.boot_error_msg || null,
        })"""
    )
    assert phase["error"] is None, phase["error"]
    if phase["setup"]:
        page.locator("#identity-setup-passphrase").fill(_IDENTITY_PASSPHRASE)
        page.locator("#identity-setup-confirm").fill(_IDENTITY_PASSPHRASE)
        page.locator("#btn-identity-setup").click()
    elif phase["locked"] and not phase["ready"]:
        page.locator("#unlock-passphrase").fill(_IDENTITY_PASSPHRASE)
        page.locator("#btn-unlock").click()
    page.wait_for_function(
        "() => Boolean(window.__oneLinkPeer?.state?.rec?.private_key_jwk)",
        timeout=150_000,
    )
    return csp


def _show_manual_surfaces(page: Page) -> None:
    page.locator("#btn-show-advanced").click()
    page.wait_for_selector("#webrtc-card", state="visible", timeout=10_000)


def _register_ack(*, lifetime_ms: int = 60_000) -> dict[str, Any]:
    server_time_ms = 1_000_000
    return {
        "expires_at_ms": server_time_ms + lifetime_ms,
        "observed_host": "127.0.0.1",
        "observed_port": 41_111,
        "server_time_ms": server_time_ms,
        "type": "register_ack",
        "v": "OL-RDZ-1",
    }


def _install_scripted_rendezvous(page: Page, state: dict[str, Any]) -> None:
    """Route one fake HTTPS origin without weakening browser CSP or CORS."""

    state.setdefault("mode", "valid")
    state.setdefault("post_count", 0)
    state.setdefault("seen_modes", [])

    def _route(route: Route) -> None:
        request = route.request
        cors_headers = {
            "Access-Control-Allow-Headers": "Content-Type",
            "Access-Control-Allow-Methods": "POST",
            "Access-Control-Allow-Origin": "*",
        }
        if request.method == "OPTIONS":
            route.fulfill(status=204, headers=cors_headers, body="")
            return
        if request.method != "POST" or request.url != (f"{_SCRIPTED_RDZ_ORIGIN}/api/v1/register"):
            route.fulfill(status=404, headers=cors_headers, body="not found")
            return

        state["post_count"] += 1
        sequence = state.get("sequence")
        mode = sequence.pop(0) if sequence else state["mode"]
        state["seen_modes"].append(mode)
        headers = {**cors_headers, "Content-Type": "application/json"}
        ack = _register_ack(lifetime_ms=int(state.get("lifetime_ms", 60_000)))

        if mode == "valid":
            route.fulfill(status=200, headers=headers, body=json.dumps(ack))
        elif mode == "schema-extra":
            ack["unexpected"] = True
            route.fulfill(status=200, headers=headers, body=json.dumps(ack))
        elif mode == "lifetime-zero":
            ack["expires_at_ms"] = ack["server_time_ms"]
            route.fulfill(status=200, headers=headers, body=json.dumps(ack))
        elif mode == "malformed":
            route.fulfill(status=200, headers=headers, body='{"broken":')
        elif mode == "oversized":
            body = json.dumps({"padding": "x" * (32 * 1024 + 1)})
            route.fulfill(status=200, headers=headers, body=body)
        elif mode == "transient":
            route.fulfill(
                status=503,
                headers={**cors_headers, "Content-Type": "text/plain"},
                body="temporary rendezvous outage",
            )
        else:  # a typo in the test script must fail loudly, not become a 200
            route.fulfill(status=500, headers=cors_headers, body=f"bad mode: {mode}")

    page.route(f"{_SCRIPTED_RDZ_ORIGIN}/**", _route)


def _register_error(page: Page) -> str:
    result = page.evaluate(
        """async (origin) => {
            try {
                await window.__oneLinkPeer.registerWith(origin, { ttl_s: 60 });
                return { ok: true, error: "" };
            } catch (error) {
                return {
                    ok: false,
                    error: error && error.message ? error.message : String(error),
                };
            }
        }""",
        _SCRIPTED_RDZ_ORIGIN,
    )
    assert result["ok"] is False
    return str(result["error"])


def _wait_for_locator_text(
    page: Page,
    selector: str,
    expected: str,
    *,
    timeout_s: float = 5.0,
) -> str:
    """Poll outside the page clock so fake-timer tests cannot deadlock."""

    deadline = time.monotonic() + timeout_s
    value = ""
    while time.monotonic() < deadline:
        value = page.locator(selector).inner_text(timeout=1_000)
        if expected in value:
            return value
        time.sleep(0.01)
    raise AssertionError(f"{selector} never contained {expected!r}; last text={value!r}")


def test_peer_register_and_lookup_cross_origin_under_real_csp(
    browser: Browser,
    live_daemon: Any,
    live_https_rendezvous: LiveHttpsRendezvous,
) -> None:
    """The shipped browser client can CORS-preflight, sign, and read ACKs."""

    peer_origin = _wait_for_daemon_https(live_daemon)
    assert peer_origin != live_https_rendezvous.origin
    context = _new_browser_context(browser)
    page = context.new_page()
    try:
        csp = _open_real_peer(page, peer_origin)
        assert "https:" in csp

        result = page.evaluate(
            """async ({ rendezvousOrigin }) => {
                const api = window.__oneLinkPeer;
                const rec = api.state.rec;
                const opts = {
                    ttl_s: 60,
                    advertised_endpoints: [],
                    nat_type: "unknown",
                    capabilities: [
                        "browser_peer", "manual_signal_v1", "webrtc_v1",
                    ],
                };
                const wire = await api._buildSignedRegister(rec, opts);
                const ack = await api.registerWith(rendezvousOrigin, opts);
                const lookup = await api.lookupAt(
                    rendezvousOrigin,
                    rec.public_key_b64u,
                );
                return {
                    ack,
                    lookup,
                    wire,
                    identity: {
                        fingerprint: rec.fingerprint,
                        pubkey: rec.public_key_b64u,
                    },
                    pageOrigin: location.origin,
                    secure: window.isSecureContext,
                };
            }""",
            {"rendezvousOrigin": live_https_rendezvous.origin},
        )

        assert result["secure"] is True
        assert result["pageOrigin"] == peer_origin
        wire = result["wire"]
        assert wire["v"] == "OL-RDZ-1"
        assert wire["type"] == "register"
        assert wire["pubkey_b64"] == result["identity"]["pubkey"]
        assert len(wire["signature"]) == 86
        assert wire["advertised_endpoints"] == []

        ack = result["ack"]
        assert set(ack) == _REGISTER_ACK_KEYS
        assert ack["v"] == "OL-RDZ-1"
        assert ack["type"] == "register_ack"
        assert ack["observed_host"] == "127.0.0.1"
        assert 1 <= ack["observed_port"] <= 65_535
        assert ack["server_time_ms"] < ack["expires_at_ms"]
        assert ack["expires_at_ms"] - ack["server_time_ms"] == 60_000

        lookup = result["lookup"]
        assert lookup is not None
        assert set(lookup) == _LOOKUP_ACK_KEYS
        assert lookup["v"] == "OL-RDZ-1"
        assert lookup["type"] == "lookup_ack"
        assert lookup["pubkey_b64"] == result["identity"]["pubkey"]
        assert lookup["capabilities"] == [
            "browser_peer",
            "manual_signal_v1",
            "webrtc_v1",
        ]
        assert lookup["advertised_endpoints"] == []
        assert lookup["observed_endpoint"]["host"] == "127.0.0.1"

        # Also exercise the actual advanced-surface control.  Success text and
        # the observed endpoint prove the parsed ACK reached UI code rather
        # than merely completing as an opaque no-cors response.
        page.locator("#btn-show-advanced").click()
        page.locator("#rdz-url").fill(live_https_rendezvous.origin)
        page.locator("#btn-rdz-register").click()
        page.wait_for_function(
            "() => document.querySelector('#rdz-status')?.textContent === "
            "'Signed presence published. Manual signaling is still required.'",
            timeout=_LIVE_RTC_TIMEOUT_MS,
        )
        assert page.locator("#rdz-ack-wrap").is_visible()
        assert ":" in page.locator("#rdz-ack-endpoint").inner_text()

        observed = list(live_https_rendezvous.observed_requests)
        register_preflights = [
            item
            for item in observed
            if item["method"] == "OPTIONS" and item["path"] == "/api/v1/register"
        ]
        assert register_preflights
        assert all(
            item["origin"] == peer_origin
            and item["requested_method"] == "POST"
            and item["requested_headers"].lower() == "content-type"
            for item in register_preflights
        )
        assert any(
            item["method"] == "POST"
            and item["path"] == "/api/v1/register"
            and item["origin"] == peer_origin
            for item in observed
        )
        assert any(
            item["method"] == "GET"
            and item["path"].startswith("/api/v1/lookup/")
            and item["origin"] == peer_origin
            for item in observed
        )
    finally:
        context.close()


def test_rendezvous_client_rejects_hostile_2xx_and_ui_recovers(
    browser: Browser,
    live_daemon: Any,
) -> None:
    """Strict response parsing fails closed without wedging the Register UI."""

    peer_origin = _wait_for_daemon_https(live_daemon)
    context = _new_browser_context(browser)
    page = context.new_page()
    scripted: dict[str, Any] = {}
    try:
        _install_scripted_rendezvous(page, scripted)
        _open_real_peer(page, peer_origin)

        scripted["mode"] = "schema-extra"
        assert _register_error(page) == ("register_ack fields do not match OL-RDZ-1")

        scripted["mode"] = "lifetime-zero"
        assert _register_error(page) == ("register_ack lifetime is outside the protocol bound")

        scripted["mode"] = "malformed"
        assert _register_error(page) == "rendezvous returned malformed JSON"

        scripted["mode"] = "oversized"
        assert _register_error(page) == "rendezvous response is too large"

        # Drive the same oversized response through the button handler.  Its
        # finally path must re-enable the button so a corrected retry works.
        page.locator("#btn-show-advanced").click()
        page.locator("#rdz-url").fill(_SCRIPTED_RDZ_ORIGIN)
        page.locator("#btn-rdz-register").click()
        _wait_for_locator_text(
            page,
            "#rdz-status",
            "Register failed: rendezvous response is too large",
        )
        assert page.locator("#btn-rdz-register").is_enabled()
        assert page.locator("#rdz-ack-wrap").is_hidden()

        scripted["mode"] = "valid"
        page.locator("#btn-rdz-register").click()
        assert _wait_for_locator_text(
            page,
            "#rdz-status",
            "Signed presence published. Manual signaling is still required.",
        )
        assert page.locator("#btn-rdz-register").is_enabled()
        assert page.locator("#rdz-ack-wrap").is_visible()
        assert page.locator("#rdz-ack-endpoint").inner_text() == "127.0.0.1:41111"
        assert scripted["seen_modes"] == [
            "schema-extra",
            "lifetime-zero",
            "malformed",
            "oversized",
            "oversized",
            "valid",
        ]
    finally:
        context.close()


def test_rendezvous_refresh_retries_once_and_survives_bfcache_events(
    browser: Browser,
    live_daemon: Any,
) -> None:
    """Refresh backoff and persisted navigation retain one live timer."""

    peer_origin = _wait_for_daemon_https(live_daemon)
    context = _new_browser_context(browser)
    page = context.new_page()
    scripted: dict[str, Any] = {
        "lifetime_ms": 60_000,
        "sequence": ["valid", "transient", "valid", "valid"],
    }
    try:
        page.clock.install()
        _install_scripted_rendezvous(page, scripted)
        _open_real_peer(page, peer_origin)
        # Pause before registration so the 30-second refresh delay has an
        # exact origin; no wall-clock milliseconds are lost between scheduling
        # and the one-before-boundary assertion below.
        page.clock.pause_at(float(page.evaluate("() => Date.now()")))
        page.locator("#btn-show-advanced").click()
        page.locator("#rdz-url").fill(_SCRIPTED_RDZ_ORIGIN)
        page.locator("#btn-rdz-register").click()
        _wait_for_locator_text(
            page,
            "#rdz-status",
            "Signed presence published. Manual signaling is still required.",
        )
        assert scripted["post_count"] == 1

        # A 60-second lease schedules refresh at T+30s (the shipped
        # 30-second margin).
        page.clock.run_for(29_999)
        assert scripted["post_count"] == 1
        page.clock.run_for(1)
        _wait_for_locator_text(
            page,
            "#rdz-status",
            "Presence refresh failed; retrying: temporary rendezvous outage",
        )
        assert scripted["post_count"] == 2

        # retryAttempt=1 is exactly four seconds.  Running to one millisecond
        # before the boundary proves there is not a duplicate timer.
        page.clock.run_for(3_999)
        assert scripted["post_count"] == 2
        page.clock.run_for(1)
        _wait_for_locator_text(page, "#rdz-status", "Signed presence refreshed")
        assert scripted["post_count"] == 3

        # A persisted pagehide pauses but does not destroy refresh state.
        persisted = page.evaluate(
            """() => {
                const event = new PageTransitionEvent(
                    "pagehide", { persisted: true },
                );
                window.dispatchEvent(event);
                return event.persisted;
            }""",
        )
        assert persisted is True
        page.clock.run_for(90_000)
        assert scripted["post_count"] == 3

        # Repeated pageshow notifications must replace the pending timer, not
        # multiply it.  The retained lease is overdue, so the one replacement
        # timer fires at the minimum one-second delay.
        for _ in range(2):
            persisted = page.evaluate(
                """() => {
                    const event = new PageTransitionEvent(
                        "pageshow", { persisted: true },
                    );
                    window.dispatchEvent(event);
                    return event.persisted;
                }""",
            )
            assert persisted is True
        previous_status = page.locator("#rdz-status").inner_text()
        page.clock.run_for(999)
        assert scripted["post_count"] == 3
        page.clock.run_for(1)
        # The prior successful refresh already left identical success text.
        # Pump Playwright events while requiring this exact new POST and its
        # newly committed success status (the fake clock is 91 seconds later).
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            status = page.locator("#rdz-status").inner_text(timeout=1_000)
            if scripted["post_count"] == 4 and status != previous_status and "Signed presence refreshed" in status:
                break
            time.sleep(0.01)
        else:
            pytest.fail(f"new refresh not observed: posts={scripted['post_count']}, status={status!r}")
        assert scripted["post_count"] == 4
        assert scripted["seen_modes"] == [
            "valid",
            "transient",
            "valid",
            "valid",
        ]
    finally:
        context.close()


_RTC_CAPTURE_INIT = """
(() => {
    const NativePeerConnection = window.RTCPeerConnection;
    const telemetry = {
        peerConnections: [],
        channels: [],
        messages: [],
        events: [],
        droppedEvents: 0,
    };
    window.__oneLinkRtcE2E = telemetry;
    if (!NativePeerConnection) return;

    const seen = new WeakSet();
    const captureChannel = (channel) => {
        if (seen.has(channel)) return channel;
        seen.add(channel);
        const channelIndex = telemetry.channels.length;
        telemetry.channels.push(channel);
        const observe = (event, data) => {
            if (telemetry.events.length >= 64) {
                telemetry.droppedEvents += 1;
                return;
            }
            // Retain only protocol/type allowlists and state, never the
            // frame body, key, nonce, message text, token, or SDP credentials.
            let frame = null;
            if (typeof data === "string" && data.length <= 4096) {
                try {
                    const parsed = JSON.parse(data);
                    if (parsed?.v === "OL-PAIR-1" &&
                        ["hello", "confirm"].includes(parsed.t)) {
                        frame = `pair:${parsed.t}`;
                    }
                } catch (_) { /* malformed frames have no protocol label */ }
            }
            const pairing = window.__oneLinkPeer?.state?.pairing;
            telemetry.events.push({
                index: telemetry.events.length,
                atMs: Math.round(performance.now()),
                channel: channelIndex,
                label: ["one-link-control-v1", "one-link-bulk-v1"].includes(channel.label)
                    ? channel.label : "other",
                event,
                readyState: channel.readyState,
                frame,
                textChars: typeof data === "string" ? data.length : null,
                pairingPresent: Boolean(pairing),
                activeChannel: pairing?.session?.control === channel,
                sentHello: Boolean(pairing?.sent_hello),
                hasRemoteHello: Boolean(pairing?.remote_hello),
                finished: Boolean(pairing?.finished),
            });
        };
        for (const event of ["open", "close", "error"]) {
            channel.addEventListener(event, () => observe(event));
        }
        channel.addEventListener("message", (event) => {
            observe("message", event.data);
            if (telemetry.messages.length < 64) {
                telemetry.messages.push({
                    label: channel.label,
                    data: typeof event.data === "string"
                        ? event.data
                        : `[binary:${event.data?.byteLength ?? -1}]`,
                });
            }
        });
        const send = channel.send.bind(channel);
        channel.send = (data) => {
            try {
                const result = send(data);
                observe("send", data);
                return result;
            } catch (error) {
                observe("send-error", data);
                throw error;
            }
        };
        return channel;
    };

    window.RTCPeerConnection = new Proxy(NativePeerConnection, {
        construct(target, args) {
            const pc = Reflect.construct(target, args, target);
            telemetry.peerConnections.push(pc);
            pc.addEventListener("datachannel", (event) => {
                captureChannel(event.channel);
            });
            const createDataChannel = pc.createDataChannel.bind(pc);
            pc.createDataChannel = (...args) => {
                return captureChannel(createDataChannel(...args));
            };
            return pc;
        },
    });
})();
"""


def _signal_details(page: Page, selector: str, expected_type: str) -> dict[str, Any]:
    return page.evaluate(
        """async ({ selector, expectedType }) => {
            const value = document.querySelector(selector).value;
            const signal = window.__oneLinkPeer.decodeSignal(value);
            await window.__oneLinkPeer.verifySignal(signal, expectedType);
            const sdp = String(signal.body?.sdp || "");
            return {
                signal,
                value,
                candidateLines: sdp.split(/\\r?\\n/).filter(
                    (line) => line.startsWith("a=candidate:"),
                ),
                telemetry: window.__oneLinkRtcE2E.peerConnections.map((pc) => ({
                    connectionState: pc.connectionState,
                    iceConnectionState: pc.iceConnectionState,
                    iceGatheringState: pc.iceGatheringState,
                    signalingState: pc.signalingState,
                })),
            };
        }""",
        {"selector": selector, "expectedType": expected_type},
    )


def _numeric_host_candidates(lines: list[str]) -> list[str]:
    numeric: list[str] = []
    for line in lines:
        parts = line.split()
        if len(parts) < 8 or parts[6:8] != ["typ", "host"]:
            continue
        try:
            ipaddress.ip_address(parts[4])
        except ValueError:
            continue
        numeric.append(line)
    return numeric


def _wait_for_control_open(page: Page) -> None:
    try:
        page.wait_for_function(
            """() => window.__oneLinkRtcE2E.channels.some(
                (channel) => channel.label === "one-link-control-v1" &&
                    channel.readyState === "open",
            )""",
            timeout=_LIVE_RTC_TIMEOUT_MS,
        )
    except PlaywrightTimeoutError as exc:
        pytest.fail(
            "control channel did not open: "
            + json.dumps(_transport_diagnostics(page), sort_keys=True)
            + f" ({exc})"
        )


def _transport_diagnostics(page: Page) -> dict[str, Any]:
    return page.evaluate(
        """async () => ({
            status: document.querySelector('#webrtc-status')?.textContent || '',
            localSignalLength:
                document.querySelector('#webrtc-local')?.value?.length || 0,
            peerConnections: await Promise.all(
              (window.__oneLinkRtcE2E?.peerConnections || []).map(async (pc) => ({
                    connectionState: pc.connectionState,
                    iceConnectionState: pc.iceConnectionState,
                    iceGatheringState: pc.iceGatheringState,
                    signalingState: pc.signalingState,
                    localDescriptionType: pc.localDescription?.type || null,
                    remoteDescriptionType: pc.remoteDescription?.type || null,
                    // getStats supplies candidate metadata without copying
                    // raw SDP candidate extensions or ICE credentials.
                    stats: Array.from((await pc.getStats()).values())
                      .filter((entry) => [
                        'candidate-pair', 'local-candidate', 'remote-candidate',
                      ].includes(entry.type))
                      .map((entry) => ({
                        id: entry.id,
                        type: entry.type,
                        state: entry.state || null,
                        candidateType: entry.candidateType || null,
                        address: entry.address || null,
                        port: entry.port || null,
                        protocol: entry.protocol || null,
                        localCandidateId: entry.localCandidateId || null,
                        remoteCandidateId: entry.remoteCandidateId || null,
                        nominated: entry.nominated || false,
                      })),
                })),
            ),
            channels: (window.__oneLinkRtcE2E?.channels || []).map((channel) => ({
                label: ["one-link-control-v1", "one-link-bulk-v1"].includes(channel.label)
                    ? channel.label : "other",
                readyState: channel.readyState,
            })),
            // These listeners observe incoming events before the page's
            // handlers. "send" means the native send call returned normally;
            // it does not by itself prove remote receipt. Clocks are per page.
            events: window.__oneLinkRtcE2E?.events || [],
            droppedEvents: window.__oneLinkRtcE2E?.droppedEvents || 0,
            // Pairing state was missing here, which is why a remote_hello
            // stall on CI produced a bare "Timeout 10000ms exceeded" with
            // nothing to diagnose. An abort (wrong signer, self-pair, hello
            // timeout) leaves its reason ONLY in #pair-status, so capture it.
            pairing: (() => {
                const pairing = window.__oneLinkPeer?.state?.pairing;
                return {
                    present: Boolean(pairing),
                    sentHello: pairing?.sent_hello ?? null,
                    hasRemoteHello: Boolean(pairing?.remote_hello),
                    finished: pairing?.finished ?? null,
                    finalizing: pairing?.finalizing ?? null,
                    hasPinnedSigner: Boolean(
                        pairing?.session?.remote_signal_signer_pubkey_b64u,
                    ),
                    identityUnlocked: Boolean(
                        window.__oneLinkPeer?.state?.rec,
                    ),
                    statusText:
                        document.querySelector('#pair-status')?.textContent || '',
                };
            })(),
        })"""
    )


def _both_peer_transport_diagnostics(
    page_a: Page, page_b: Page,
) -> dict[str, Any]:
    snapshots: dict[str, Any] = {}
    for label, page in (("a", page_a), ("b", page_b)):
        try:
            snapshots[label] = _transport_diagnostics(page)
        except Exception as exc:
            # Preserve the other peer even if this page has already closed.
            # Exception text can contain a URL or payload; retain only its type.
            snapshots[label] = {"captureError": type(exc).__name__}
    return snapshots


def _send_control_probe(page: Page, payload: dict[str, str]) -> None:
    result = page.evaluate(
        """(payload) => {
            const control = window.__oneLinkRtcE2E.channels.find(
                (channel) => channel.label === "one-link-control-v1" &&
                    channel.readyState === "open",
            );
            if (!control) throw new Error("captured control channel is not open");
            window.__oneLinkPeer.sendControl({ control }, payload);
            return { label: control.label, state: control.readyState };
        }""",
        payload,
    )
    assert result == {"label": "one-link-control-v1", "state": "open"}


def _wait_for_probe(page: Page, probe_type: str) -> dict[str, Any]:
    page.wait_for_function(
        """(probeType) => window.__oneLinkRtcE2E.messages.some((entry) => {
            if (entry.label !== "one-link-control-v1") return false;
            try { return JSON.parse(entry.data).t === probeType; }
            catch (_) { return false; }
        })""",
        arg=probe_type,
        timeout=10_000,
    )
    return page.evaluate(
        """(probeType) => {
            const entry = window.__oneLinkRtcE2E.messages.find((candidate) => {
                if (candidate.label !== "one-link-control-v1") return false;
                try { return JSON.parse(candidate.data).t === probeType; }
                catch (_) { return false; }
            });
            return JSON.parse(entry.data);
        }""",
        probe_type,
    )


def test_two_isolated_peer_pages_complete_manual_webrtc_and_exchange_probe(
    browser_type: BrowserType,
    live_daemon: Any,
) -> None:
    """Two real peer pages exchange one-blob SDP and open the control DC."""

    peer_origin = _wait_for_daemon_https(live_daemon)
    # Each launch is a new Firefox process that would write its own startup
    # cache twice, holding every navigation and Playwright command while it
    # writes (RUN-01). The first goto below has a 30 s clock. Both browsers are
    # returned with that cache disabled and checked, or the test fails with a
    # named BrowserNotReady. No timeout here changes.
    browser_a, browser_b = launch_settled_many(browser_type, 2)
    context_a = _new_browser_context(browser_a)
    context_b = _new_browser_context(browser_b)
    context_a.add_init_script(_RTC_CAPTURE_INIT)
    context_b.add_init_script(_RTC_CAPTURE_INIT)
    page_a = context_a.new_page()
    page_b = context_b.new_page()
    try:
        _open_real_peer(page_a, peer_origin)
        _open_real_peer(page_b, peer_origin)
        _show_manual_surfaces(page_a)
        _show_manual_surfaces(page_b)

        # The suite-level environment explicitly disables every configured
        # public STUN server. The sole ICE helper is this daemon's local,
        # non-relaying responder, and its candidate addresses come from the
        # accepted HTTPS socket rather than browser/UA inference.
        ice_configs = [
            page.evaluate("() => window.__oneLinkPeer.loadPublicIceConfig()")
            for page in (page_a, page_b)
        ]
        for config in ice_configs:
            assert len(config["iceServers"]) == 1
            assert config["iceServers"][0]["urls"].startswith(
                "stun:127.0.0.1:"
            )
            assert config["localCandidateAddresses"][0] == "127.0.0.1"

        identities = {
            "a": page_a.evaluate(
                """() => ({
                    fingerprint: window.__oneLinkPeer.state.rec.fingerprint,
                    pubkey: window.__oneLinkPeer.state.rec.public_key_b64u,
                })""",
            ),
            "b": page_b.evaluate(
                """() => ({
                    fingerprint: window.__oneLinkPeer.state.rec.fingerprint,
                    pubkey: window.__oneLinkPeer.state.rec.public_key_b64u,
                })""",
            ),
        }
        assert identities["a"]["fingerprint"] != identities["b"]["fingerprint"]
        assert identities["a"]["pubkey"] != identities["b"]["pubkey"]

        page_a.locator("#btn-webrtc-offer").click()
        try:
            page_a.wait_for_function(
                "() => document.querySelector('#webrtc-local').value.length > 100",
                timeout=_LIVE_RTC_TIMEOUT_MS,
            )
        except PlaywrightTimeoutError as exc:
            pytest.fail(
                "offer signal was not produced: "
                + json.dumps(_transport_diagnostics(page_a), sort_keys=True)
                + f" ({exc})"
            )
        offer_status = page_a.locator("#webrtc-status").inner_text()
        offer = _signal_details(page_a, "#webrtc-local", "offer")
        assert offer_status.startswith("Complete offer ready.")
        assert set(offer["signal"]) == _SIGNAL_KEYS
        assert offer["signal"]["v"] == "OL-WRTC-1"
        assert offer["signal"]["type"] == "offer"
        assert set(offer["signal"]["body"]) == {"sdp", "type"}
        assert offer["signal"]["body"]["type"] == "offer"
        assert offer["signal"]["sender_pubkey_b64"] == identities["a"]["pubkey"]
        assert len(offer["signal"]["signature"]) == 86
        assert offer["candidateLines"], "complete offer must embed gathered ICE"
        assert _numeric_host_candidates(offer["candidateLines"]), (
            "signed offer must carry a routable numeric host candidate"
        )
        assert offer["telemetry"][0]["iceGatheringState"] == "complete"

        page_b.locator("#webrtc-remote").fill(offer["value"])
        page_b.locator("#btn-webrtc-accept").click()
        page_b.wait_for_function(
            "() => document.querySelector('#webrtc-local').value.length > 100",
            timeout=_LIVE_RTC_TIMEOUT_MS,
        )
        answer_status = page_b.locator("#webrtc-status").inner_text()
        answer = _signal_details(page_b, "#webrtc-local", "answer")
        assert answer_status.startswith("Complete answer ready.")
        assert set(answer["signal"]) == _SIGNAL_KEYS
        assert answer["signal"]["v"] == "OL-WRTC-1"
        assert answer["signal"]["type"] == "answer"
        assert set(answer["signal"]["body"]) == {"sdp", "type"}
        assert answer["signal"]["body"]["type"] == "answer"
        assert answer["signal"]["sender_pubkey_b64"] == identities["b"]["pubkey"]
        assert answer["candidateLines"], "complete answer must embed gathered ICE"
        assert _numeric_host_candidates(answer["candidateLines"]), (
            "signed answer must carry a routable numeric host candidate"
        )
        assert answer["telemetry"][0]["iceGatheringState"] == "complete"

        # No trickle step is performed.  The offer and answer textareas are the
        # sole signaling blobs, and completion freezes them before handoff.
        page_a.wait_for_timeout(250)
        page_b.wait_for_timeout(250)
        assert page_a.locator("#webrtc-local").input_value() == offer["value"]
        assert page_b.locator("#webrtc-local").input_value() == answer["value"]

        page_a.locator("#webrtc-remote").fill(answer["value"])
        page_a.locator("#btn-webrtc-accept").click()
        _wait_for_control_open(page_a)
        _wait_for_control_open(page_b)
        # Keep the existing timeout. If either peer stalls, retain both peers'
        # bounded event order and pairing state so the first failed wait does
        # not hide whether the other peer sent, received, or aborted a hello.
        for label, page in (("a", page_a), ("b", page_b)):
            try:
                page.wait_for_function(
                    "() => Boolean(window.__oneLinkPeer.state.pairing?.remote_hello)",
                    timeout=_LIVE_RTC_TIMEOUT_MS,
                )
            except PlaywrightTimeoutError as exc:
                pytest.fail(
                    f"peer {label} never received a pair hello: "
                    + json.dumps(_both_peer_transport_diagnostics(page_a, page_b), sort_keys=True)
                    + f" ({exc})"
                )

        # Run the diagnostics on the SUCCESS path too. Code that only executes
        # when a test fails is never exercised, so a JS error in it would
        # surface as an exception inside the failure reporter and bury the very
        # cause it exists to reveal. Asserting the healthy snapshot here keeps
        # the reporter honest and pins what a good pairing looks like.
        for label, page in (("a", page_a), ("b", page_b)):
            diagnostics = _transport_diagnostics(page)
            snapshot = diagnostics["pairing"]
            assert snapshot["present"] is True, label
            assert snapshot["sentHello"] is True, label
            assert snapshot["hasRemoteHello"] is True, label
            assert snapshot["hasPinnedSigner"] is True, label
            assert snapshot["identityUnlocked"] is True, label
            assert len(diagnostics["events"]) <= 64, label
            assert any(
                event["event"] == "send" and event["frame"] == "pair:hello"
                for event in diagnostics["events"]
            ), label
            assert any(
                event["event"] == "message" and event["frame"] == "pair:hello"
                for event in diagnostics["events"]
            ), label

        trust_bindings = {
            "a": page_a.evaluate(
                """() => ({
                    signalPubkey: window.__oneLinkPeer.state.pairing.session
                        .remote_signal_signer_pubkey_b64u,
                    signalFingerprint: window.__oneLinkPeer.state.pairing.session
                        .remote_signal_signer_fingerprint,
                    helloPubkey: window.__oneLinkPeer.state.pairing.remote_hello.pubkey,
                    helloFingerprint:
                        window.__oneLinkPeer.state.pairing.remote_hello.fingerprint,
                })""",
            ),
            "b": page_b.evaluate(
                """() => ({
                    signalPubkey: window.__oneLinkPeer.state.pairing.session
                        .remote_signal_signer_pubkey_b64u,
                    signalFingerprint: window.__oneLinkPeer.state.pairing.session
                        .remote_signal_signer_fingerprint,
                    helloPubkey: window.__oneLinkPeer.state.pairing.remote_hello.pubkey,
                    helloFingerprint:
                        window.__oneLinkPeer.state.pairing.remote_hello.fingerprint,
                })""",
            ),
        }
        assert trust_bindings["a"] == {
            "signalPubkey": identities["b"]["pubkey"],
            "signalFingerprint": identities["b"]["fingerprint"],
            "helloPubkey": identities["b"]["pubkey"],
            "helloFingerprint": identities["b"]["fingerprint"],
        }
        assert trust_bindings["b"] == {
            "signalPubkey": identities["a"]["pubkey"],
            "signalFingerprint": identities["a"]["fingerprint"],
            "helloPubkey": identities["a"]["pubkey"],
            "helloFingerprint": identities["a"]["fingerprint"],
        }

        final_states = {
            "a": page_a.evaluate(
                """() => window.__oneLinkRtcE2E.peerConnections.map((pc) => ({
                    connectionState: pc.connectionState,
                    iceConnectionState: pc.iceConnectionState,
                    iceGatheringState: pc.iceGatheringState,
                }))""",
            ),
            "b": page_b.evaluate(
                """() => window.__oneLinkRtcE2E.peerConnections.map((pc) => ({
                    connectionState: pc.connectionState,
                    iceConnectionState: pc.iceConnectionState,
                    iceGatheringState: pc.iceGatheringState,
                }))""",
            ),
        }
        for side in ("a", "b"):
            assert len(final_states[side]) == 1
            assert final_states[side][0]["connectionState"] == "connected"
            assert final_states[side][0]["iceConnectionState"] in {
                "connected",
                "completed",
            }
            assert final_states[side][0]["iceGatheringState"] == "complete"

        a_to_b = {
            "t": "e2e-control-probe-a-to-b",
            "nonce": "peer-live-transport-1",
        }
        _send_control_probe(page_a, a_to_b)
        assert _wait_for_probe(page_b, a_to_b["t"]) == a_to_b

        b_to_a = {
            "t": "e2e-control-probe-b-to-a",
            "nonce": "peer-live-transport-2",
        }
        _send_control_probe(page_b, b_to_a)
        assert _wait_for_probe(page_a, b_to_a["t"]) == b_to_a
    finally:
        context_a.close()
        context_b.close()
        browser_a.close()
        browser_b.close()
