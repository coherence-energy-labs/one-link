"""Executable browser proofs for direct peer-to-peer chat durability.

These tests use Chromium's real IndexedDB, Web Locks, WebCrypto and page code.
They deliberately do not mock the persistence boundary that the outbox protects.
"""

from __future__ import annotations

import contextlib
import re
import time
from typing import Any

from playwright.sync_api import Browser, Page


def _daemon_https_origin(live_daemon: Any, timeout_s: float = 20.0) -> str:
    deadline = time.monotonic() + timeout_s
    pattern = re.compile(r"UI server HTTPS up.*?https://[^:]+:(\d+)/")
    last_log = ""
    while time.monotonic() < deadline:
        with contextlib.suppress(OSError):
            last_log = live_daemon.log.read_text(
                encoding="utf-8", errors="replace"
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


def _open_peer(page: Page, origin: str) -> None:
    response = page.goto(
        f"{origin}/peer", wait_until="domcontentloaded", timeout=30_000
    )
    assert response is not None and response.status == 200
    page.wait_for_function(
        "() => Boolean(window.__oneLinkPeer)", timeout=30_000
    )
    # Let the page's asynchronous identity boot choose its terminal setup /
    # ready / locked state before the test installs an isolated synthetic pair.
    # Firefox otherwise finishes boot between two evaluate calls and replaces
    # the test authority, which correctly makes _activeChatBinding fail closed.
    page.wait_for_function(
        """() => Boolean(
            window.__oneLinkPeer?.state?.rec?.private_key_jwk ||
            window.__oneLinkPeer?.state?.pending_rec?.private_key_jwk ||
            window.__oneLinkPeer?.state?.envelope ||
            window.__oneLinkPeer?.state?.boot_error_msg
        )""",
        timeout=30_000,
    )
    error = page.evaluate(
        "() => window.__oneLinkPeer.state.boot_error_msg || null"
    )
    assert error is None, error


_PAIR_SETUP = """
async () => {
    const api = window.__oneLinkPeer;
    const local = await api.generateIdentity();
    const remote = await api.generateIdentity();
    const sent = [];
    const pairing = {
        persisted: true,
        finished: true,
        local_confirm: true,
        remote_confirm: true,
        local_identity_fingerprint: local.fingerprint,
        local_identity_pubkey_b64u: local.public_key_b64u,
        remote_hello: {
            fingerprint: remote.fingerprint,
            pubkey: remote.public_key_b64u,
        },
        session: {
            control: {
                readyState: "open",
                send: (wire) => sent.push(wire),
            },
            remote_signal_signer_fingerprint: remote.fingerprint,
            remote_signal_signer_pubkey_b64u: remote.public_key_b64u,
        },
    };
    api._identityTestUseRecord(local);
    api.state.pairing = pairing;
    window.__chatOutboxProof = { local, remote, pairing, sent };
    return { local: local.fingerprint, remote: remote.fingerprint };
}
"""


def test_direct_chat_outbox_replays_once_per_bound_session_and_ack_clears(
    browser: Browser,
    live_daemon: Any,
) -> None:
    origin = _daemon_https_origin(live_daemon)
    context = browser.new_context(ignore_https_errors=True)
    try:
        page = context.new_page()
        _open_peer(page, origin)
        identities = page.evaluate(_PAIR_SETUP)
        proof = page.evaluate(
            """async () => {
                const api = window.__oneLinkPeer;
                const proof = window.__chatOutboxProof;
                const message = await api.sendChatMessage(
                    "durable direct message"
                );
                const afterAdmission = await api.listChatOutbox(
                    proof.local.fingerprint, proof.remote.fingerprint
                );
                const duplicateSameSession = await api.drainChatOutbox(
                    proof.pairing
                );

                const reconnectSent = [];
                const reconnect = {
                    ...proof.pairing,
                    chat_session_id: null,
                    session: {
                        ...proof.pairing.session,
                        control: {
                            readyState: "open",
                            send: (wire) => reconnectSent.push(wire),
                        },
                    },
                };
                api.state.pairing = reconnect;
                const firstReconnect = await api.drainChatOutbox(reconnect);
                const duplicateReconnect = await api.drainChatOutbox(reconnect);
                const exactReplay = reconnectSent[0] === proof.sent[0];

                await api.acknowledgeOutboundMessage(
                    proof.local.fingerprint,
                    proof.remote.fingerprint,
                    message.id,
                    Date.now(),
                );
                const afterAck = await api.listChatOutbox(
                    proof.local.fingerprint, proof.remote.fingerprint
                );
                const history = await api.loadMessages(
                    proof.remote.fingerprint, { limit: 20 }
                );
                return {
                    message,
                    initialWireCount: proof.sent.length,
                    admittedRows: afterAdmission.length,
                    admittedAttemptCount: afterAdmission[0]?.attempt_count,
                    duplicateSameSession,
                    firstReconnect,
                    duplicateReconnect,
                    reconnectWireCount: reconnectSent.length,
                    exactReplay,
                    afterAckRows: afterAck.length,
                    acked: Boolean(
                        history.find((row) => row.id === message.id)?.ack_ms
                    ),
                };
            }"""
        )
        assert identities["local"] != identities["remote"]
        assert proof["initialWireCount"] == 1
        assert proof["admittedRows"] == 1
        assert proof["admittedAttemptCount"] == 1
        assert proof["duplicateSameSession"]["sent_ids"] == []
        assert proof["firstReconnect"]["sent_ids"] == [proof["message"]["id"]]
        assert proof["duplicateReconnect"]["sent_ids"] == []
        assert proof["reconnectWireCount"] == 1
        assert proof["exactReplay"] is True
        assert proof["afterAckRows"] == 0
        assert proof["acked"] is True
    finally:
        context.close()


def test_direct_chat_outbox_rejects_wrong_owner_and_quarantines_poison(
    browser: Browser,
    live_daemon: Any,
) -> None:
    origin = _daemon_https_origin(live_daemon)
    context = browser.new_context(ignore_https_errors=True)
    try:
        page = context.new_page()
        _open_peer(page, origin)
        page.evaluate(_PAIR_SETUP)
        result = page.evaluate(
            """async () => {
                const api = window.__oneLinkPeer;
                const proof = window.__chatOutboxProof;
                const message = await api.sendChatMessage("owner-bound payload");

                const db = await new Promise((resolve, reject) => {
                    const request = indexedDB.open("one-link-peer-messages", 3);
                    request.onsuccess = () => resolve(request.result);
                    request.onerror = () => reject(request.error);
                });
                await new Promise((resolve, reject) => {
                    const tx = db.transaction("outbox.v1", "readwrite");
                    const store = tx.objectStore("outbox.v1");
                    for (let index = 0; index < 2000; index += 1) {
                        store.add({
                            key: `000-poison-${String(index).padStart(3, "0")}`,
                            id: `poison-${index}`,
                            body: "x".repeat(index + 1),
                            unexpected: true,
                        });
                    }
                    tx.oncomplete = resolve;
                    tx.onabort = () => reject(tx.error);
                    tx.onerror = () => reject(tx.error);
                });
                db.close();

                const intruder = await api.generateIdentity();
                const intruderSent = [];
                const wrongOwnerPairing = {
                    ...proof.pairing,
                    chat_session_id: null,
                    local_identity_fingerprint: intruder.fingerprint,
                    local_identity_pubkey_b64u: intruder.public_key_b64u,
                    session: {
                        ...proof.pairing.session,
                        control: {
                            readyState: "open",
                            send: (wire) => intruderSent.push(wire),
                        },
                    },
                };
                api._identityTestUseRecord(intruder);
                api.state.pairing = wrongOwnerPairing;
                const wrongOwnerDrain = await api.drainChatOutbox(
                    wrongOwnerPairing
                );

                const reconnectSent = [];
                const ownerReconnect = {
                    ...proof.pairing,
                    chat_session_id: null,
                    session: {
                        ...proof.pairing.session,
                        control: {
                            readyState: "open",
                            send: (wire) => reconnectSent.push(wire),
                        },
                    },
                };
                api._identityTestUseRecord(proof.local);
                api.state.pairing = ownerReconnect;
                const ownerDrain = await api.drainChatOutbox(ownerReconnect);
                const quarantine = await api.listChatOutboxQuarantine();
                const remaining = await api.listChatOutbox();

                const binding = api._activeChatBinding(ownerReconnect, true);
                const conflictRecord = {
                    id: message.id,
                    peer_fp: proof.remote.fingerprint,
                    direction: "out",
                    body: "different payload",
                    ts: message.ts,
                    received_ms: message.received_ms,
                };
                let conflict = "";
                try {
                    await api.persistOutboundMessage(
                        conflictRecord,
                        {
                            v: "OL-MSG-1",
                            t: "text",
                            id: message.id,
                            body: conflictRecord.body,
                            ts: message.ts,
                        },
                        binding,
                    );
                } catch (error) {
                    conflict = String(error && error.message || error);
                }

                await api.acknowledgeOutboundMessage(
                    proof.local.fingerprint,
                    proof.remote.fingerprint,
                    message.id,
                    Date.now(),
                );
                return {
                    messageId: message.id,
                    wrongOwnerSent: intruderSent.length,
                    wrongOwnerDrain,
                    ownerSent: reconnectSent.length,
                    ownerDrain,
                    quarantineCount: quarantine.length,
                    quarantineCopiedBodies: quarantine.some(
                        (row) => Object.hasOwn(row, "body")
                    ),
                    remainingKeys: remaining.map((row) => row.key),
                    conflict,
                    afterAck: (await api.listChatOutbox()).length,
                };
            }"""
        )
        assert result["wrongOwnerSent"] == 0
        assert result["wrongOwnerDrain"]["sent_ids"] == []
        assert result["ownerSent"] == 1
        assert result["ownerDrain"]["sent_ids"] == [result["messageId"]]
        assert result["quarantineCount"] == 256
        assert result["quarantineCopiedBodies"] is False
        assert len(result["remainingKeys"]) == 1
        assert "reused for different content" in result["conflict"]
        assert result["afterAck"] == 0
    finally:
        context.close()


def test_service_worker_drains_valid_row_behind_full_poison_snapshot(
    browser: Browser,
    live_daemon: Any,
) -> None:
    """A full 2,000-row poison prefix is removed in bulk, then row 2,001 runs."""

    delivered: list[str] = []
    context = browser.new_context(ignore_https_errors=True)

    def _fulfill_send(route) -> None:
        delivered.append(route.request.post_data or "")
        route.fulfill(
            status=200,
            content_type="application/json",
            body='{"ok":true}',
        )

    context.route("**/api/send", _fulfill_send)
    try:
        page = context.new_page()
        response = page.goto(
            live_daemon.auth_url, wait_until="domcontentloaded", timeout=30_000
        )
        assert response is not None and response.status == 200
        page.evaluate("() => navigator.serviceWorker.ready")
        if not page.evaluate("() => Boolean(navigator.serviceWorker.controller)"):
            page.reload(wait_until="domcontentloaded", timeout=30_000)
            page.wait_for_function(
                "() => Boolean(navigator.serviceWorker.controller)", timeout=20_000
            )

        seeded = page.evaluate(
            """async () => {
                const db = await new Promise((resolve, reject) => {
                    const request = indexedDB.open("one-link-outbox-v1", 3);
                    request.onupgradeneeded = () => {
                        const opened = request.result;
                        let queue;
                        if (!opened.objectStoreNames.contains("queue")) {
                            queue = opened.createObjectStore(
                                "queue", { keyPath: "id", autoIncrement: true }
                            );
                            queue.createIndex(
                                "dedupe_key", "dedupe_key", { unique: true }
                            );
                        }
                        if (!opened.objectStoreNames.contains("meta")) {
                            opened.createObjectStore("meta", { keyPath: "key" });
                        }
                        if (!opened.objectStoreNames.contains("quarantine")) {
                            opened.createObjectStore(
                                "quarantine",
                                { keyPath: "quarantine_id", autoIncrement: true }
                            );
                        }
                    };
                    request.onsuccess = () => resolve(request.result);
                    request.onerror = () => reject(request.error);
                });
                await new Promise((resolve, reject) => {
                    const tx = db.transaction(
                        ["queue", "quarantine"], "readwrite"
                    );
                    const queue = tx.objectStore("queue");
                    queue.clear();
                    tx.objectStore("quarantine").clear();
                    for (let index = 0; index < 2000; index += 1) {
                        queue.add({
                            url: "/not-an-executable-outbox-route",
                            method: "DELETE",
                            body: "x".repeat((index % 17) + 1),
                            dedupe_key: `poison:${index}`,
                        });
                    }
                    const payload = {
                        peer: "sha256:" + "a".repeat(64),
                        body: "valid row after poison prefix",
                        queue_on_failure: true,
                        client_msg_id: "valid_message_0001",
                    };
                    queue.add({
                        url: "/api/send",
                        method: "POST",
                        body: JSON.stringify(payload),
                        dedupe_key: "send:valid_message_0001",
                    });
                    tx.oncomplete = () => resolve(payload);
                    tx.onabort = () => reject(tx.error);
                    tx.onerror = () => reject(tx.error);
                });
                db.close();
                return 2001;
            }"""
        )
        assert seeded == 2001
        page.evaluate(
            """() => navigator.serviceWorker.controller.postMessage({
                type: "drain-now"
            })"""
        )
        deadline = time.monotonic() + 30.0
        proof = {"queue": 2001, "remaining": [], "quarantine": []}
        while time.monotonic() < deadline:
            proof = page.evaluate(
                """async () => {
                const db = await new Promise((resolve, reject) => {
                    const request = indexedDB.open("one-link-outbox-v1", 3);
                    request.onsuccess = () => resolve(request.result);
                    request.onerror = () => reject(request.error);
                });
                const result = await new Promise((resolve, reject) => {
                    const tx = db.transaction(
                        ["queue", "quarantine"], "readonly"
                    );
                    const queueRequest = tx.objectStore("queue").getAll();
                    const quarantineRequest = tx.objectStore(
                        "quarantine"
                    ).getAll();
                    tx.oncomplete = () => resolve({
                        queue: queueRequest.result.length,
                        remaining: queueRequest.result,
                        quarantine: quarantineRequest.result,
                    });
                    tx.onabort = () => reject(tx.error);
                    tx.onerror = () => reject(tx.error);
                });
                db.close();
                return result;
            }"""
            )
            # A routed Chromium worker fetch can be visible to Playwright a
            # few milliseconds before the worker commits the queue delete.
            # Do not mistake that in-flight success for the Firefox/WebKit
            # retained-row outcome; wait for Chromium's ACK-clear commit.
            quarantine_full = len(proof["quarantine"]) == 256
            if proof["queue"] == 0 and quarantine_full:
                break
            if proof["queue"] == 1 and quarantine_full and not delivered:
                break
            time.sleep(0.05)
        assert proof["queue"] in {0, 1}
        assert len(proof["quarantine"]) == 256
        assert all("body" not in row for row in proof["quarantine"])
        if proof["queue"] == 0:
            # Chromium exposes service-worker fetches to BrowserContext.route.
            assert len(delivered) == 1
            assert "valid row after poison prefix" in delivered[0]
        else:
            # Firefox/WebKit can bypass Playwright routing for worker fetches;
            # the real daemon rejects the synthetic peer. The sole retained row
            # must nevertheless be the valid row that sat at position 2,001.
            assert delivered == []
            assert len(proof["remaining"]) == 1
            assert proof["remaining"][0]["dedupe_key"] == (
                "send:valid_message_0001"
            )
    finally:
        context.close()
