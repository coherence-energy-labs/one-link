"""Live browser proofs for roster authorization and DataChannel identity.

This is deliberately more than a DOM/structure test: a real daemon runs with
the strict identity-possession gate enabled, the browser enrolls a real Ed25519
browser key, WebRTC reaches an open DataChannel, an owner request succeeds only
after the channel-bound signature acknowledgement, and roster revoke closes the
live channel immediately.
"""

from __future__ import annotations

import contextlib
import re
import time
from typing import Any

from playwright.sync_api import (
    Browser,
    BrowserContext,
    Page,
    TimeoutError as PlaywrightTimeoutError,
)

from tests.e2e.browser_readiness import wait_for_browser_ready


_IDENTITY_PASSPHRASE = "channel-bound browser authority 2026"


def _https_origin(live_daemon: Any, timeout_s: float = 20.0) -> str:
    deadline = time.monotonic() + timeout_s
    pattern = re.compile(r"UI server HTTPS up.*?https://[^:]+:(\d+)/")
    last_log = ""
    while time.monotonic() < deadline:
        with contextlib.suppress(OSError):
            last_log = live_daemon.log.read_text(
                encoding="utf-8", errors="replace",
            )
            matches = pattern.findall(last_log)
            if matches:
                return f"https://127.0.0.1:{int(matches[-1])}"
        if live_daemon.proc.poll() is not None:
            raise RuntimeError(
                "daemon exited before HTTPS became ready\n" + last_log[-4000:]
            )
        time.sleep(0.05)
    raise RuntimeError(
        f"daemon HTTPS did not become ready within {timeout_s:.0f}s\n"
        + last_log[-4000:]
    )


def _context(browser: Browser) -> BrowserContext:
    return browser.new_context(ignore_https_errors=True)


def _open_ready_peer(page: Page, origin: str) -> None:
    response = page.goto(
        f"{origin}/peer", wait_until="domcontentloaded", timeout=30_000,
    )
    assert response is not None and response.status == 200
    page.wait_for_function(
        """() => Boolean(
            window.__oneLinkPeer?.state?.rec?.private_key_jwk ||
            window.__oneLinkPeer?.state?.pending_rec?.private_key_jwk ||
            window.__oneLinkPeer?.state?.envelope ||
            window.__oneLinkPeer?.state?.boot_error_msg
        )""",
        timeout=30_000,
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
        timeout=180_000,
    )


def _fetch_json(page: Page, path: str, body: dict[str, Any]) -> dict[str, Any]:
    result = page.evaluate(
        """async ({path, body}) => {
            const response = await fetch(path, {
                method: 'POST',
                credentials: 'same-origin',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(body),
            });
            return {
                status: response.status,
                body: await response.json().catch(() => ({})),
            };
        }""",
        {"path": path, "body": body},
    )
    assert 200 <= result["status"] < 300, result
    return result["body"]


def test_required_mode_live_pair_owner_request_and_immediate_revoke(
    browser: Browser,
    live_daemon: Any,
) -> None:
    origin = _https_origin(live_daemon)
    context = _context(browser)
    try:
        # Set the guarded UI session cookie in this browser context.
        admin = context.new_page()
        response = admin.goto(
            live_daemon.auth_url,
            wait_until="domcontentloaded",
            timeout=30_000,
        )
        assert response is not None and response.status == 200

        peer = context.new_page()
        _open_ready_peer(peer, origin)
        # RUN-01: the pairing token TTL and the flow's 90 s deadline start
        # below. Before that, the browser must prove it is past its one-time
        # startup-cache write and that its parent process answers; otherwise
        # a browser/host stall would be reported as a pairing failure. The
        # pairing assertions and budgets that follow are unchanged.
        wait_for_browser_ready(peer, browser)
        identity = peer.evaluate(
            """() => ({
                pub: window.__oneLinkPeer.state.rec.public_key_b64u,
                fingerprint: window.__oneLinkPeer.state.rec.fingerprint,
            })"""
        )

        invite = _fetch_json(
            admin,
            "/api/setup/device-invite",
            {"label": "Browser identity-possession E2E"},
        )
        claim = _fetch_json(
            peer,
            "/api/setup/device-invite/claim",
            {
                "token": invite["token"],
                "device_pub_b64": identity["pub"],
                "device_kind": "browser-peer",
                "label": f"{browser.browser_type.name} authority",
            },
        )
        assert claim["pending"] is True
        confirmed = _fetch_json(
            admin,
            "/api/setup/device-invite/confirm",
            {"token": invite["token"], "sas": claim["trust_code"]},
        )
        assert confirmed["trusted"] is True

        status = peer.evaluate(
            """async (token) => {
                const response = await fetch(
                    `/api/setup/device-invite/status?token=${encodeURIComponent(token)}`,
                    {credentials: 'same-origin'},
                );
                return {status: response.status, body: await response.json()};
            }""",
            invite["token"],
        )
        assert status["status"] == 200
        handoff = status["body"]
        assert handoff["status"] == "confirmed"

        peer.evaluate(
            """(handoff) => {
                window.__olIdentityPairError = null;
                window.__olIdentityPairFlow =
                  window.__oneLinkPeer._runAutoPairFlow({
                    pair_token: handoff.pair_token,
                    daemon_fingerprint: handoff.daemon_fingerprint,
                    ws_url: handoff.ws_signaling_url,
                  });
                void window.__olIdentityPairFlow.catch((error) => {
                    window.__olIdentityPairError = String(error?.message || error);
                  });
            }""",
            handoff,
        )
        try:
            peer.wait_for_function(
                """() => Boolean(window.__olIdentityPairError) || Boolean(
                    window.__oneLinkPeer.state.daemon_identity_ready?.verified &&
                    window.__oneLinkPeer.state.daemon_dc?.readyState === 'open'
                )""",
                timeout=90_000,
            )
            pair_error = peer.evaluate("() => window.__olIdentityPairError")
            assert pair_error is None, (
                f"browser pairing rejected: {pair_error}; stages="
                + repr(peer.evaluate("() => window.__oneLinkPeer.state.autopair_diagnostics"))
            )
        except PlaywrightTimeoutError as exc:
            browser_state = peer.evaluate(
                """() => ({
                    pill: document.querySelector('#autopair-pill')?.textContent || '',
                    status: document.querySelector('#autopair-status')?.textContent || '',
                    dcState: window.__oneLinkPeer.state.daemon_dc?.readyState || null,
                    identityReady: window.__oneLinkPeer.state.daemon_identity_ready
                        ? {
                            settled: window.__oneLinkPeer.state.daemon_identity_ready.settled,
                            verified: window.__oneLinkPeer.state.daemon_identity_ready.verified,
                          }
                        : null,
                    pairingStages: window.__oneLinkPeer.state.autopair_diagnostics || null,
                })"""
            )
            log_tail = live_daemon.log.read_text(
                encoding="utf-8", errors="replace",
            )[-12_000:]
            raise AssertionError(
                f"browser pairing did not verify: {browser_state!r}\n"
                f"--- daemon log ---\n{log_tail}"
            ) from exc

        proof = peer.evaluate(
            """async () => {
                const api = window.__oneLinkPeer;
                const flowResult = await window.__olIdentityPairFlow;
                const acknowledgement = await api.state.daemon_identity_ready.promise;
                const challenge = api.state.daemon_identity_context.challenge;
                const roster = await api._daemonRequest('fetch_peers', {});
                return {
                    acknowledgement,
                    flowResult,
                    challenge,
                    rosterType: roster.t,
                    rosterIsArray: Array.isArray(roster.peers),
                    dcState: api.state.daemon_dc.readyState,
                };
            }"""
        )
        assert set(proof["challenge"]) == {
            "v", "t", "schema", "challenge_id", "nonce", "session_id",
            "peer_fingerprint", "daemon_fingerprint", "issued_ms", "expires_ms",
        }
        assert proof["challenge"]["peer_fingerprint"] == identity["fingerprint"]
        assert proof["challenge"]["schema"] == (
            "OL-BROWSER-IDENTITY-POSSESSION-1"
        )
        assert proof["acknowledgement"]["challenge_id"] == (
            proof["challenge"]["challenge_id"]
        )
        assert proof["acknowledgement"]["session_id"] == (
            proof["challenge"]["session_id"]
        )
        assert proof["flowResult"]["challenge_id"] == (
            proof["challenge"]["challenge_id"]
        )
        assert proof["rosterType"] == "peers"
        assert proof["rosterIsArray"] is True
        assert proof["dcState"] == "open"

        revoked = _fetch_json(
            admin,
            "/api/self-mesh/devices/revoke",
            {
                "root_pub_b64": confirmed["root_pub_b64"],
                "device_pub_b64": confirmed["device_pub_b64"],
            },
        )
        assert revoked["browser_authority_evicted"]["active_peers"] == 1
        peer.wait_for_function(
            "() => window.__oneLinkPeer.state.daemon_dc === null",
            timeout=10_000,
        )
        after_revoke = peer.evaluate(
            """async () => {
                try {
                    await window.__oneLinkPeer._daemonRequest('fetch_peers', {});
                    return {accepted: true, error: ''};
                } catch (error) {
                    return {accepted: false, error: String(error?.message || error)};
                }
            }"""
        )
        assert after_revoke["accepted"] is False
        assert after_revoke["error"] in {
            "no live daemon channel",
            "daemon data channel is not open",
        }
    finally:
        context.close()


def test_chromium_identity_challenge_parser_and_signature_fail_closed(
    browser: Browser,
    live_daemon: Any,
) -> None:
    origin = _https_origin(live_daemon)
    context = _context(browser)
    try:
        page = context.new_page()
        _open_ready_peer(page, origin)
        result = page.evaluate(
            """async () => {
                const api = window.__oneLinkPeer;
                class FakeDc extends EventTarget {
                    constructor() {
                        super();
                        this.readyState = 'open';
                        this.sent = [];
                        this.closed = false;
                    }
                    send(value) { this.sent.push(value); }
                    close() {
                        if (this.closed) return;
                        this.closed = true;
                        this.readyState = 'closed';
                        this.dispatchEvent(new Event('close'));
                    }
                }
                const daemonFingerprint =
                    'sha256:' + 'ab'.repeat(32);
                const dc = new FakeDc();
                const ready = api._registerDaemonDc(dc, daemonFingerprint);
                ready.catch(() => {});
                const now = Date.now();
                const challenge = {
                    v: 'OL-PEER-1',
                    t: 'identity_possession_challenge',
                    schema: 'OL-BROWSER-IDENTITY-POSSESSION-1',
                    challenge_id: api.bytesToB64Url(crypto.getRandomValues(new Uint8Array(16))),
                    nonce: api.bytesToB64Url(crypto.getRandomValues(new Uint8Array(32))),
                    session_id: api.bytesToB64Url(crypto.getRandomValues(new Uint8Array(16))),
                    peer_fingerprint: api.state.rec.fingerprint,
                    daemon_fingerprint: daemonFingerprint,
                    issued_ms: now,
                    expires_ms: now + 15000,
                };
                await api._handleDaemonIdentityChallenge(challenge, dc);
                const response = JSON.parse(dc.sent[0]);
                const signatureValid = await api._verifyEd25519(
                    api.b64UrlToBytes(api.state.rec.public_key_b64u),
                    api.b64UrlToBytes(response.signature),
                    api._identityPossessionSigningBytes(challenge),
                );
                api._handleDaemonIdentityVerified({
                    v: 'OL-PEER-1',
                    t: 'identity_possession_verified',
                    schema: 'OL-BROWSER-IDENTITY-POSSESSION-1',
                    challenge_id: challenge.challenge_id,
                    session_id: challenge.session_id,
                    verified_ms: Date.now(),
                }, dc);
                const verified = await ready;

                const replacedDc = new FakeDc();
                const replacedReady = api._registerDaemonDc(
                    replacedDc, daemonFingerprint,
                );
                const replacedOutcome = replacedReady.then(
                    () => 'unexpected-resolution',
                    (error) => String(error?.message || error),
                );
                let replacedPendingError = '';
                api.state.daemon_pending.set('replaced-rid', {
                    resolve: () => {},
                    reject: (error) => {
                        replacedPendingError = String(error?.message || error);
                    },
                    timer: setTimeout(() => {}, 60000),
                });
                const replacementDc = new FakeDc();
                const replacementReady = api._registerDaemonDc(
                    replacementDc, daemonFingerprint,
                );
                replacementReady.catch(() => {});
                const replacedIdentityError = await replacedOutcome;
                const replacementSurvived =
                    api.state.daemon_dc === replacementDc &&
                    replacementDc.readyState === 'open';
                let staleReplySettled = false;
                const staleReplyTimer = setTimeout(() => {}, 60000);
                api.state.daemon_pending.set('stale-rid', {
                    resolve: () => { staleReplySettled = true; },
                    reject: () => { staleReplySettled = true; },
                    timer: staleReplyTimer,
                });
                api._routeDaemonDcMessage(JSON.stringify({
                    v: 'OL-PEER-1', t: 'peers', rid: 'stale-rid', peers: [],
                }), replacedDc);
                const staleReplyIgnored =
                    api.state.daemon_pending.has('stale-rid') &&
                    !staleReplySettled;
                clearTimeout(staleReplyTimer);
                api.state.daemon_pending.delete('stale-rid');
                let unverifiedRequestError = '';
                try {
                    await api._daemonRequest('fetch_peers', {});
                } catch (error) {
                    unverifiedRequestError = String(error?.message || error);
                }

                const lateAckDc = new FakeDc();
                const lateAckReady = api._registerDaemonDc(
                    lateAckDc, daemonFingerprint,
                );
                lateAckReady.catch(() => {});
                const lateNow = Date.now();
                const lateChallenge = {
                    ...challenge,
                    challenge_id: api.bytesToB64Url(
                        crypto.getRandomValues(new Uint8Array(16)),
                    ),
                    session_id: api.bytesToB64Url(
                        crypto.getRandomValues(new Uint8Array(16)),
                    ),
                    issued_ms: lateNow,
                    expires_ms: lateNow + 15000,
                };
                await api._handleDaemonIdentityChallenge(
                    lateChallenge, lateAckDc,
                );
                api._handleDaemonIdentityVerified({
                    v: 'OL-PEER-1',
                    t: 'identity_possession_verified',
                    schema: 'OL-BROWSER-IDENTITY-POSSESSION-1',
                    challenge_id: lateChallenge.challenge_id,
                    session_id: lateChallenge.session_id,
                    verified_ms: lateChallenge.expires_ms,
                }, lateAckDc);

                const expiredDc = new FakeDc();
                const expiredReady = api._registerDaemonDc(
                    expiredDc, daemonFingerprint,
                );
                expiredReady.catch(() => {});
                const expired = {
                    ...challenge,
                    challenge_id: api.bytesToB64Url(
                        crypto.getRandomValues(new Uint8Array(16)),
                    ),
                    session_id: api.bytesToB64Url(
                        crypto.getRandomValues(new Uint8Array(16)),
                    ),
                    issued_ms: Date.now() - 15001,
                    expires_ms: Date.now() - 1,
                };
                await api._handleDaemonIdentityChallenge(expired, expiredDc);

                const schemaDc = new FakeDc();
                const schemaReady = api._registerDaemonDc(
                    schemaDc, daemonFingerprint,
                );
                schemaReady.catch(() => {});
                await api._handleDaemonIdentityChallenge(
                    {...challenge, ignored: 'parser-confusion'}, schemaDc,
                );

                const staleDc = new FakeDc();
                await api._handleDaemonIdentityChallenge(challenge, staleDc);
                return {
                    responseKeys: Object.keys(response).sort(),
                    signatureValid,
                    verified,
                    replacedIdentityError,
                    replacedPendingError,
                    replacementSurvived,
                    staleReplyIgnored,
                    unverifiedRequestError,
                    lateAckClosed: lateAckDc.closed,
                    expiredClosed: expiredDc.closed,
                    schemaClosed: schemaDc.closed,
                    staleClosed: staleDc.closed,
                };
            }"""
        )
        assert result["responseKeys"] == sorted(
            [
                "v", "t", "schema", "challenge_id", "session_id",
                "peer_fingerprint", "signature",
            ]
        )
        assert result["signatureValid"] is True
        assert result["verified"]["challenge_id"]
        assert result["replacedIdentityError"] == "daemon channel replaced"
        assert result["replacedPendingError"] == "daemon channel replaced"
        assert result["replacementSurvived"] is True
        assert result["staleReplyIgnored"] is True
        assert result["unverifiedRequestError"] == "daemon identity is not verified"
        assert result["lateAckClosed"] is True
        assert result["expiredClosed"] is True
        assert result["schemaClosed"] is True
        assert result["staleClosed"] is True
    finally:
        context.close()
