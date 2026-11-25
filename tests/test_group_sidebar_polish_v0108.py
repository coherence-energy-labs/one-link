"""v0.10.8 — group sidebar polish.

Three fixes to the group chat surface:
  1. Snap-back bug: refreshPeers' auto-select-the-only-peer branch
     ignored selectedGroup, so a 5-second timer would silently
     restore the previous device chat after the user clicked a
     group. The condition now also checks !state.selectedGroup.
  2. Discoverable settings: every group row in the sidebar now has
     a gear icon, matching the per-device gear convention. The
     conversation header still shows "Group settings" as a
     fallback for keyboard-only users.
  3. Leave group is reachable: the existing modal already had a
     "Leave group" button + handler, but it was unreachable for
     users who didn't know to click into the group first AND
     spot the small text button. The gear unblocks it.
"""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def index_html() -> str:
    return Path("src/one_link/web/index.html").read_text(encoding="utf-8")


# ───────── 1. snap-back bug fix ─────────────────────────────────────

def test_auto_select_respects_selected_group(index_html: str):
    """The single-peer auto-select branch in renderPeers must check
    BOTH selectedPeer AND selectedGroup. Without the second guard,
    the 5s refreshPeers tick re-selects the lone peer and silently
    yanks the user out of any group they just clicked into."""
    idx = index_html.find("Auto-select if there's exactly one paired peer")
    assert idx > 0, "auto-select branch comment not found"
    snippet = index_html[idx:idx + 600]
    assert "!state.selectedPeer" in snippet
    assert "!state.selectedGroup" in snippet


def test_auto_select_branch_combines_both_guards(index_html: str):
    """Specifically: the && conjunction must connect the two guards
    on the same line so the auto-select doesn't fire when a group
    is active. A blank line between them or a separate if would
    hide the regression."""
    idx = index_html.find("if (peers.length === 1 && !state.selectedPeer")
    assert idx > 0, "guarded auto-select line not found"
    line_end = index_html.find("\n", idx)
    line = index_html[idx:line_end]
    assert "!state.selectedGroup" in line, (
        f"selectedGroup guard missing from auto-select line: {line!r}"
    )


# ───────── 2. gear icon on group rows ───────────────────────────────

def test_group_row_renders_gear_button(index_html: str):
    """Every group row must include a gear button so users can open
    group settings without first having to enter the group + scan
    the conversation header."""
    idx = index_html.find("function renderGroups()")
    assert idx > 0
    snippet = index_html[idx:idx + 2500]
    assert 'el("button", "gear-btn"' in snippet
    assert "openGroupSettings" in snippet


def test_group_gear_stops_propagation(index_html: str):
    """Clicking the gear must NOT also fire row.onclick (which would
    re-select the group as a side-effect). stopPropagation is the
    standard escape hatch."""
    idx = index_html.find("function renderGroups()")
    snippet = index_html[idx:idx + 2500]
    gear_idx = snippet.find('el("button", "gear-btn"')
    assert gear_idx > 0
    branch = snippet[gear_idx:gear_idx + 800]
    assert "stopPropagation()" in branch


def test_group_gear_selects_first_when_not_active(index_html: str):
    """openGroupSettings reads state.groupDetail. If the user clicks
    the gear on a NON-active group, the handler must select the
    group first so groupDetail is populated; otherwise the modal
    early-returns (silent no-op)."""
    idx = index_html.find("function renderGroups()")
    snippet = index_html[idx:idx + 2500]
    gear_idx = snippet.find('el("button", "gear-btn"')
    branch = snippet[gear_idx:gear_idx + 800]
    assert "state.selectedGroup !== g.group_id" in branch
    assert "await selectGroup(g.group_id)" in branch


# ───────── 3. leave-group surface still wired ───────────────────────

def test_leave_button_present_in_settings_modal(index_html: str):
    """Pin the existing Leave Group button so a future refactor
    doesn't quietly drop it. Leave is only reachable through this
    modal."""
    assert 'id="group-leave"' in index_html
    assert "Leave group" in index_html


def test_leave_group_handler_calls_endpoint(index_html: str):
    """The handler must POST to /api/groups/{gid}/leave. If this
    breaks, the button is decorative."""
    idx = index_html.find("async function leaveCurrentGroup()")
    assert idx > 0
    snippet = index_html[idx:idx + 800]
    assert "/leave" in snippet
    assert "api.post" in snippet


def test_leave_group_clears_local_state(index_html: str):
    """After leaving, the UI must drop into the empty state — both
    selectedGroup and groupDetail must clear, plus the convo-empty
    pane must show. Otherwise the user sees a phantom convo for a
    group they no longer belong to."""
    idx = index_html.find("async function leaveCurrentGroup()")
    snippet = index_html[idx:idx + 1000]
    assert "state.selectedGroup = null" in snippet
    assert "state.groupDetail = null" in snippet
    assert "messageStore.clearGroup()" in snippet
    assert '"#convo-empty"' in snippet


def test_leave_group_wired_to_button(index_html: str):
    """The handler must be attached to #group-leave's click listener
    or the button does nothing."""
    idx = index_html.find('"#group-leave"')
    assert idx > 0
    snippet = index_html[idx:idx + 200]
    assert "leaveCurrentGroup" in snippet


# ───────── 4. settings-modal completeness ───────────────────────────

@pytest.mark.parametrize("section", [
    "Members",
    "Add someone",
    "Invite link",
    "Leave group",
])
def test_settings_modal_has_section(index_html: str, section: str):
    """Pin the four core sections so the modal stays a one-stop shop
    for every group action."""
    backdrop_idx = index_html.find('id="group-settings-backdrop"')
    assert backdrop_idx > 0
    # The modal closes shortly after; capture a generous window.
    end = index_html.find("</div>\n  </div>", backdrop_idx + 1)
    if end < 0:
        end = backdrop_idx + 5000
    scope = index_html[backdrop_idx:end + 1000]
    assert section in scope, f"section {section!r} missing from group settings modal"


# ───────── 5. sole-member leave reducer carve-out ───────────────────

def test_sole_member_leave_unblocks_ghost_group():
    """End-to-end via the reducer: a sole-owner sole-member group
    must be leave-able. Pre-fix this was rejected and the user was
    stuck with a row in their sidebar with no way to clear it."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )
    from one_link.groups import (
        new_group_id, reduce_events,
        sign_create_group, sign_remove_member,
    )

    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key().public_bytes_raw()
    gid = new_group_id()
    events = [
        sign_create_group(private_key=sk, pubkey=pk, name="ghost",
                          group_id=gid),
        sign_remove_member(private_key=sk, pubkey=pk, group_id=gid,
                           member_pubkey=pk),
    ]
    state = reduce_events(events)
    assert state is not None
    assert not state.is_member(pk)
    assert len(state.members) == 0
