"""A blob-admission refusal must say enough to be solved.

On 2026-08-05 a live-daemon CI run refused a file send with
`admission_blob_in_use_by_another_delivery` and left nothing behind to explain
it: not which delivery held the blob, not how long it had held it, not whether
the holder was still real. It could not be reproduced -- 5/5 passes for that
test alone, 25/25 for the whole file locally, the other three CI matrix legs
green -- so there was no thread to pull.

The guard itself is correct and was deliberately NOT changed. Content already
being delivered under one identity must not be silently adopted by another, and
loosening that on a theory, with no reproduction, is how a real defect gets
introduced while chasing a phantom.

What was missing is evidence. `_incoming_files` entries are released through
the stuck-transfer reaper, which only parks entries whose transfer row appears
in its bounded scan; an entry the reaper never sees would refuse that blob
until the daemon restarts. `held_ms` and `holder_has_transfer_row` exist to
confirm or eliminate exactly that on the next occurrence.

These tests pin the evidence, because a diagnostic nobody verified is a comment
rather than a fix.

2026-11-25: the evidence was used. A live install logged the refusal 13 times
in 16 minutes, each with `holder_has_transfer_row=True` and
`holder_transfer_status=offered`, held for up to 855 seconds. The holder was
not an orphan the reaper missed: it was an offer held for the owner's answer,
and the refused offers were the same sender sending the same file again. That
case now gets the answer the first offer got (FILE_OFFER_HELD) and is tested in
tests/test_held_offer_makes_later_offers_wait.py and, between two real daemons,
tests/test_held_offers_two_daemon_e2e.py. The refusal itself, and everything
pinned below, is unchanged for content that really is in delivery under another
identity. Whether the 2026-08-05 CI refusal was the same thing is not known:
that run left no evidence line to read.
"""

from __future__ import annotations

import time

import pytest

from one_link.daemon import IncomingFile, _incoming_delivery_contract_matches


def _incoming(**over) -> IncomingFile:
    base = dict(
        name="report.pdf",
        size=1024,
        blob_hex="a" * 64,
        out_path=__import__("pathlib").Path("out.part"),
        handle=None,
        hasher=None,
        delivery_id="d" * 32,
        delivery_name="report.pdf",
        delivery_rel_path="",
        delivery_kind="file",
        peer_fp="b" * 64,
    )
    base.update(over)
    return IncomingFile(**base)


# ── the age stamp ─────────────────────────────────────────────────────


def test_every_incoming_file_stamps_when_it_claimed_the_blob() -> None:
    """Self-stamping, so no construction site can forget it.

    An age is the difference between "a delivery started two seconds ago"
    (normal contention) and "an orphan has held this since boot" (the bug).
    """
    before = int(time.time() * 1000)
    f = _incoming()
    after = int(time.time() * 1000)
    assert before <= f.started_ms <= after, (
        f"started_ms={f.started_ms} is outside [{before}, {after}]"
    )


def test_the_stamp_is_per_instance_not_shared() -> None:
    """A mutable default shared across instances would make every age equal.

    This is the classic dataclass trap; `default_factory` avoids it, and this
    is what proves the factory is actually being used.
    """
    first = _incoming()
    time.sleep(0.02)
    second = _incoming()
    assert second.started_ms >= first.started_ms
    assert first.started_ms != 0 and second.started_ms != 0


# ── the guard still guards ────────────────────────────────────────────


def test_a_matching_retry_is_still_admitted() -> None:
    """CONTROL. The diagnostic must not have changed who gets in.

    An authenticated retry of the SAME delivery must still match, or the
    logging change would have broken resume.
    """
    holder = _incoming()
    assert _incoming_delivery_contract_matches(
        holder,
        peer_fp=holder.peer_fp,
        delivery_id=holder.delivery_id,
        delivery_name=holder.delivery_name,
        delivery_rel_path=holder.delivery_rel_path,
        delivery_kind=holder.delivery_kind,
    ) is True


@pytest.mark.parametrize(
    "field,value,why",
    [
        ("peer_fp", "c" * 64, "a different peer"),
        ("delivery_id", "e" * 32, "a different delivery id"),
        ("delivery_name", "other.pdf", "a different public name"),
        ("delivery_rel_path", "sub/dir", "a different folder position"),
        ("delivery_kind", "folder", "a different delivery kind"),
    ],
)
def test_every_binding_still_refuses_a_mismatch(field, value, why) -> None:
    """The guard is unchanged: each binding independently refuses.

    Without this, "made the refusal diagnosable" could have quietly become
    "made the refusal rarer", which is the failure mode I was most concerned
    about while touching this path.
    """
    holder = _incoming()
    args = dict(
        peer_fp=holder.peer_fp,
        delivery_id=holder.delivery_id,
        delivery_name=holder.delivery_name,
        delivery_rel_path=holder.delivery_rel_path,
        delivery_kind=holder.delivery_kind,
    )
    args[field] = value
    assert _incoming_delivery_contract_matches(holder, **args) is False, (
        f"{why} was accepted onto an active delivery"
    )


# ── the refusal actually emits the evidence ───────────────────────────


def test_the_refusal_path_logs_the_holder_and_its_age(caplog) -> None:
    """The whole point: the next occurrence must be solvable from the log.

    Asserted against the daemon source rather than by driving a full offer
    exchange, because the value here is that the fields are PRESENT in the
    emitted record -- and a full live-daemon offer round trip is precisely the
    thing that could not be made to reproduce.
    """
    from pathlib import Path

    source = (
        Path(__file__).resolve().parents[1] / "src" / "one_link" / "daemon.py"
    ).read_text(encoding="utf-8")
    start = source.index("file offer REFUSED (%s)")
    block = source[start - 1200:start + 900]

    for token in (
        "held_ms",
        "holder_delivery",
        "holder_peer",
        "holder_finalizing",
        "holder_has_transfer_row",
        "holder_transfer_status",
    ):
        assert token in block, f"the refusal log no longer reports {token}"

    # It must be a WARNING: an INFO line is invisible in the default CI capture,
    # which is how the original occurrence left nothing behind.
    assert "log.warning(" in block, "the refusal must be logged at WARNING"

    # And it must not leak a full fingerprint into logs that get pasted around.
    assert "peer_fp[:8]" in block, "the peer fingerprint must be truncated"


def test_the_diagnostic_cannot_itself_break_the_refusal() -> None:
    """The evidence gathering must never raise on the refusal path.

    Reading the holder's transfer row touches the database while the daemon is
    already rejecting something. If that read threw, a refusal would become a
    crash -- strictly worse than the missing diagnostic it replaced.
    """
    from pathlib import Path

    source = (
        Path(__file__).resolve().parents[1] / "src" / "one_link" / "daemon.py"
    ).read_text(encoding="utf-8")
    start = source.index("file offer REFUSED (%s)")
    block = source[start - 1200:start]
    assert "contextlib.suppress(Exception)" in block, (
        "the holder transfer-row lookup is not protected"
    )
    assert "getattr(existing_owner," in block, (
        "holder fields must be read defensively; a missing attribute must not "
        "turn a refusal into an AttributeError"
    )
