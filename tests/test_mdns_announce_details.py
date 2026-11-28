"""What the LAN announcement says about a device follows the privacy preset."""

from __future__ import annotations

from one_link import sovereignty as sov


def test_only_just_works_describes_the_device() -> None:
    assert sov.JUST_WORKS.mdns_announce_details_enabled is True
    assert sov.QUIET.mdns_announce_details_enabled is False
    assert sov.OFF_GRID.mdns_announce_details_enabled is False


def test_setting_can_turn_details_off_but_never_on() -> None:
    resolve = sov.resolve_mdns_announce_details_enabled
    assert resolve(state_setting=None, preset_name="just_works") is True
    assert resolve(state_setting="false", preset_name="just_works") is False
    # A preset's "no" is a ceiling.
    assert resolve(state_setting="true", preset_name="quiet") is False
    assert resolve(state_setting="true", preset_name="off_grid") is False
    assert resolve(state_setting=None, preset_name="quiet") is False


def _discovery(details: bool):
    from one_link.discovery import Discovery

    return Discovery(
        short_id="abcd1234",
        hostname="Dana's laptop",
        port=7117,
        ed_pub_hex="11" * 32,
        rendezvous_urls=["https://rdz.example"],
        device_kind="macos-laptop",
        announce_details=details,
    )


def test_full_announcement_describes_the_device() -> None:
    assert _discovery(True)._txt_properties() == {
        "sid": "abcd1234",
        "host": "Dana's laptop",
        "pub": "11" * 32,
        "v": "0.0.1",
        "rdz": "https://rdz.example",
        "kind": "macos-laptop",
    }


def test_minimal_announcement_carries_only_what_a_dial_needs() -> None:
    assert _discovery(False)._txt_properties() == {
        "sid": "abcd1234",
        "host": "abcd1234",
        "pub": "11" * 32,
        "v": "0.0.1",
    }


def test_later_rendezvous_updates_do_not_leak_into_a_minimal_announcement() -> None:
    import asyncio

    minimal = _discovery(False)
    asyncio.run(minimal.update_rendezvous_urls(["https://new.example"]))
    assert "rdz" not in minimal._txt_properties()


def test_daemon_start_passes_the_policy_to_discovery() -> None:
    from pathlib import Path

    from one_link import daemon

    source = Path(daemon.__file__).read_text(encoding="utf-8")
    construct = source[source.index("self.discovery = Discovery(") :][:700]
    assert "announce_details=_sov.mdns_announce_details_for(self.state)" in construct


def test_policy_is_read_from_the_stored_setting_and_preset() -> None:
    class _State:
        def __init__(self, settings):
            self._settings = settings

        def get_setting(self, key):
            return self._settings.get(key)

    assert sov.mdns_announce_details_for(None) is True
    assert sov.mdns_announce_details_for(_State({})) is True
    assert sov.mdns_announce_details_for(_State({"mdns_announce_details": "false"})) is False
