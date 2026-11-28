"""Discovery registry: add/find/remove/list. Network-free."""

from __future__ import annotations

import hashlib

from one_link.discovery import Peer, Registry


def _peer(short_id: str, host: str = "host", addr: str = "10.0.0.2", port: int = 1234) -> Peer:
    return Peer(
        short_id=short_id,
        hostname=host,
        address=addr,
        port=port,
        ed_pub_hex=hashlib.sha256(short_id.encode("utf-8")).hexdigest(),
    )


def test_upsert_and_find_by_short_id():
    r = Registry()
    p = _peer("abcdef12", "alice")
    r.upsert(p)
    assert r.find("abcdef12") is p


def test_upsert_rejects_malformed_public_key():
    r = Registry()
    r.upsert(Peer("ghost123", "ghost", "10.0.0.9", 1234, ""))
    r.upsert(Peer("ghost456", "ghost", "10.0.0.9", 1235, "not-hex"))

    assert r.list() == []
    assert r.find("ghost123") is None


def test_upsert_quarantines_same_host_alien_identity():
    r = Registry(
        self_ed_pub_hex="11" * 32,
        local_addresses={"192.168.1.142", "127.0.0.1"},
    )
    r.upsert(Peer("ghost123", "ghost", "192.168.1.142", 1234, "22" * 32))
    r.upsert(Peer("loopback", "ghost", "127.0.0.1", 1235, "33" * 32))
    r.upsert(Peer("remote12", "real", "192.168.1.26", 1236, "44" * 32))

    assert [p.short_id for p in r.list()] == ["remote12"]


def test_find_by_hostname_case_insensitive():
    r = Registry()
    p = _peer("abcdef12", "Alice-Mac")
    r.upsert(p)
    assert r.find("alice-mac") is p
    assert r.find("ALICE-MAC") is p


def test_find_by_short_id_prefix():
    r = Registry()
    p = _peer("abcdef12")
    r.upsert(p)
    assert r.find("abc") is p
    assert r.find("abcde") is p


def test_candidates_prefer_identity_matches_over_hostname():
    r = Registry()
    host_match = _peer("bbbbbbbb", "abc")
    prefix_match = _peer("abcdef12", "shared-host")
    r.upsert(host_match)
    r.upsert(prefix_match)

    assert r.candidates("abc")[0] is prefix_match


def test_candidates_return_all_hostname_matches_for_retry():
    r = Registry()
    old = _peer("aaaaaaaa", "Shared", "127.0.0.1", 1)
    new = _peer("bbbbbbbb", "Shared", "127.0.0.1", 2)
    r.upsert(old)
    r.upsert(new)

    assert r.candidates("shared") == [old, new]


def test_find_returns_none_for_unknown():
    r = Registry()
    r.upsert(_peer("abcdef12"))
    assert r.find("zzzzzzzz") is None
    assert r.find("nope") is None


def test_remove():
    r = Registry()
    r.upsert(_peer("abcdef12"))
    r.remove("abcdef12")
    assert r.find("abcdef12") is None


def test_remove_unknown_is_noop():
    r = Registry()
    r.upsert(_peer("aaaaaaaa", "alice"))

    r.remove("nope")

    # "No error" cannot catch the failure that matters: removing an unknown id
    # must not disturb the peers that ARE known. A remove that cleared the
    # registry would raise nothing and look identical.
    assert [p.hostname for p in r.list()] == ["alice"]


def test_list_sorted_by_hostname():
    r = Registry()
    r.upsert(_peer("aaaaaaaa", "charlie"))
    r.upsert(_peer("bbbbbbbb", "alice"))
    r.upsert(_peer("cccccccc", "bob"))
    out = r.list()
    assert [p.hostname for p in out] == ["alice", "bob", "charlie"]


def test_upsert_overwrites_same_id():
    r = Registry()
    r.upsert(_peer("abcdef12", "alice", "10.0.0.1", 1111))
    r.upsert(_peer("abcdef12", "alice2", "10.0.0.2", 2222))
    p = r.find("abcdef12")
    assert p is not None
    assert p.hostname == "alice2"
    assert p.address == "10.0.0.2"
    assert p.port == 2222


def test_upsert_replaces_same_public_key_alias():
    r = Registry()
    pub = "11" * 32
    r.upsert(Peer("aaaa1111", "WeareOne", "10.0.0.2", 1111, pub))
    r.upsert(Peer("bbbb2222", "WeareOne", "10.0.0.2", 2222, pub))

    out = r.list()
    assert len(out) == 1
    assert out[0].short_id == "bbbb2222"
    assert out[0].port == 2222


def test_on_change_callback():
    seen = []
    r = Registry(on_change=lambda: seen.append(1))
    r.upsert(_peer("a"))
    r.upsert(_peer("b"))
    r.remove("a")
    r.remove("nope")  # should NOT fire (nothing removed)
    assert len(seen) == 3


# ─── ONE_LINK_MDNS_SERVICE_TYPE private-scope override ─────────────


def test_service_type_defaults_when_env_unset(monkeypatch):
    from one_link import discovery as d

    monkeypatch.delenv("ONE_LINK_MDNS_SERVICE_TYPE", raising=False)
    assert d._resolve_service_type() == "_onelink._tcp.local."


def test_service_type_honours_valid_private_scope(monkeypatch):
    """An isolated cohort (test swarm / private household) can browse +
    advertise its own scope so it never cross-discovers ambient daemons."""
    from one_link import discovery as d

    monkeypatch.setenv("ONE_LINK_MDNS_SERVICE_TYPE", "_olt00042._tcp.local.")
    assert d._resolve_service_type() == "_olt00042._tcp.local."


def test_service_type_rejects_malformed_override(monkeypatch):
    """Out-of-spec values fall back to the default rather than breaking
    discovery entirely (RFC 6335 caps the protocol label at 15 chars)."""
    from one_link import discovery as d

    for bad in (
        "garbage",                       # no ._tcp.local.
        "nounderscore._tcp.local.",      # missing leading underscore
        "_waytoolongprotolabel._tcp.local.",  # >15 char label
        "_bad space._tcp.local.",        # non-alnum label
        "   ",                            # blank
    ):
        monkeypatch.setenv("ONE_LINK_MDNS_SERVICE_TYPE", bad)
        assert d._resolve_service_type() == "_onelink._tcp.local.", bad


def test_find_refuses_an_ambiguous_short_id_prefix():
    r = Registry()
    first = _peer("abc11111")
    second = _peer("abc22222")
    r.upsert(first)
    r.upsert(second)
    assert r.find("abc") is None
    assert r.find("abc1") is first
    assert r.find("abc22222") is second
    assert {p.short_id for p in r.candidates("abc")} == {"abc11111", "abc22222"}


def test_empty_needle_matches_nothing():
    r = Registry()
    r.upsert(_peer("abc11111"))
    assert r.candidates("") == []
    assert r.find("") is None
