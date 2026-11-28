"""docs/NETWORK_CONTACTS.md tells users what a default install contacts."""

from __future__ import annotations

from pathlib import Path

from one_link import sovereignty as sov
from one_link import update_check

REPO = Path(__file__).resolve().parents[1]
PAGE = (REPO / "docs" / "NETWORK_CONTACTS.md").read_text(encoding="utf-8")


def test_default_preset_is_the_one_described() -> None:
    assert sov.DEFAULT_PRESET_NAME == "just_works"
    assert "default privacy preset is **Just Works**" in PAGE


def test_every_default_stun_server_is_named() -> None:
    assert sov.JUST_WORKS.stun_servers == sov.COMMUNITY_STUN_SERVERS
    assert len(sov.COMMUNITY_STUN_SERVERS) == 3
    for url in sov.COMMUNITY_STUN_SERVERS:
        host_port = url.removeprefix("stun:")
        assert f"`{host_port}`" in PAGE, host_port
    assert "3 community servers" in PAGE


def test_update_check_is_disclosed_as_on_by_default() -> None:
    assert sov.JUST_WORKS.update_check_enabled is True
    assert sov.resolve_update_check_enabled(
        env_var=None, state_setting=None, preset_name=None
    ) is True
    assert "`api.github.com`" in PAGE
    assert f"{update_check.DEFAULT_OWNER}/{update_check.DEFAULT_REPO}" in PAGE
    assert "one-link-update-check/0.21" in PAGE
    source = Path(update_check.__file__).read_text(encoding="utf-8")
    assert '"User-Agent": "one-link-update-check/0.21"' in source


def test_strict_presets_match_the_table() -> None:
    for preset in (sov.QUIET, sov.OFF_GRID):
        assert preset.update_check_enabled is False
        assert preset.stun_servers == ()
        assert preset.rendezvous_enabled is False
        assert preset.turn_relay_enabled is False
    assert sov.QUIET.mdns_discovery_enabled is True
    assert sov.QUIET.mdns_announce_details_enabled is False
    assert sov.OFF_GRID.mdns_discovery_enabled is False
    assert sov.JUST_WORKS.mdns_announce_details_enabled is True


def test_the_daemon_comment_no_longer_claims_the_poll_is_opt_in() -> None:
    from one_link import daemon

    source = Path(daemon.__file__).read_text(encoding="utf-8")
    assert "opt-IN, not opt-out" not in source
    assert "ONLY external network call" not in source


def test_readme_points_to_the_disclosure() -> None:
    assert "docs/NETWORK_CONTACTS.md" in (REPO / "README.md").read_text(encoding="utf-8")
