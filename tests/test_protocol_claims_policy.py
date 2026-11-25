"""Configured protocol descriptions follow migration switches, not capability guesses."""
from __future__ import annotations

import pytest

from one_link.channel import configured_handshake_policy


@pytest.mark.parametrize("override", [None, "ONE_LINK_ALLOW_CLASSICAL_HANDSHAKE", "ONE_LINK_ALLOW_V1_HELLO"])
def test_default_policy_and_explicit_migration_are_distinguished(monkeypatch, override):
    monkeypatch.delenv("ONE_LINK_ALLOW_CLASSICAL_HANDSHAKE", raising=False)
    monkeypatch.delenv("ONE_LINK_ALLOW_V1_HELLO", raising=False)
    if override:
        monkeypatch.setenv(override, "1")
    policy = configured_handshake_policy()
    assert policy["default_version"] == 3
    assert policy["default_key_agreement"] == "X25519 + ML-KEM-768"
    assert policy["classical_receiver_override"] is (override is not None)
    assert policy["unbound_v1_migration_override"] is (override == "ONE_LINK_ALLOW_V1_HELLO")
    assert policy["automatic_downgrade"] is False
    assert policy["browser_webrtc_pq_qualified"] is False

