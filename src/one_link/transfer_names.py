"""Turning a file name a peer chose into one that is safe to store and show."""

from __future__ import annotations

from pathlib import Path, PurePosixPath

PLACEHOLDER = "unnamed.bin"

# Code points removed from every received file name: the Unicode bidi
# controls (marks, embeddings, overrides, isolates) and the C1 controls.
_SPOOFING_CODEPOINTS = dict.fromkeys(
    (
        0x061C,
        0x200E,
        0x200F,
        *range(0x202A, 0x202F),
        *range(0x2066, 0x206A),
        *range(0x0080, 0x00A0),
    )
)


def safe_transfer_name(value: object, *, reserved: frozenset[str], max_bytes: int) -> str:
    """Reduce a peer-supplied name to one safe path leaf on every platform.

    ``reserved`` is the set of Windows device names (upper case) and
    ``max_bytes`` the longest UTF-8 encoding allowed.
    """
    # Take the basename against BOTH separators regardless of host.
    # ``Path(...).name`` only understands the local one, so on POSIX a
    # peer-supplied "C:\\Windows\\System32\\evil.dll" survived whole and
    # was stored with its backslashes intact. That is harmless where it
    # lands -- backslash is an ordinary character on POSIX -- but this is
    # a FILE TRANSFER product: that artifact travels, and the same name on
    # a Windows machine is a traversal path. A received name must never
    # carry another platform's separators.
    raw = str(value or "").replace("\\", "/")
    name = PurePosixPath(raw).name
    if not name or name in (".", ".."):
        return PLACEHOLDER
    # v0.20.7 (security audit H16):
    #   - Reject NUL + control chars (0x00-0x1f, 0x7f).
    #   - Reject trailing dots and spaces (Windows silently strips
    #     them, so "report.pdf." collides with "report.pdf").
    #   - Reject Windows reserved device names (CON, NUL, COM1-9,
    #     LPT1-9, AUX, PRN). Match by stem so "CON.txt" is also
    #     rejected -- Windows treats the device-name stem as the
    #     reserved meaning even with an extension.
    # 2026-05-21 audit T3-R: also strip the ``:`` separator. On
    # NTFS, ``report.pdf:hidden.exe`` is a valid filename where
    # ``:hidden.exe`` is an Alternate Data Stream -- invisible to
    # Explorer but executable. A paired peer could ship an
    # executable hidden as a document attachment.
    clean = name.replace("\x00", "").replace(":", "_").rstrip(". ")
    clean = "".join(c for c in clean if not (ord(c) <= 0x1F or ord(c) == 0x7F))
    # Bidirectional-override characters reorder how a name is drawn
    # without changing its bytes: "photo<U+202E>gnp.exe" is displayed as
    # "photoexe.png" and still runs as an .exe. They have no place in a
    # file name a stranger chose, so they are removed, along with the C1
    # control range the check above does not cover.
    clean = clean.translate(_SPOOFING_CODEPOINTS).rstrip(". ")
    if not clean:
        return PLACEHOLDER
    if Path(clean).stem.upper() in reserved:
        clean = "_" + clean
    encoded = clean.encode("utf-8", errors="ignore")
    if len(encoded) <= max_bytes:
        return clean
    # Preserve the extension when clipping by total byte length so
    # a long-prefix attacker can't collide on the trimmed name.
    suffix = Path(clean).suffix.encode("utf-8", errors="ignore")
    if 0 < len(suffix) < max_bytes // 2:
        stem_bytes = encoded[: max_bytes - len(suffix)]
        clipped = stem_bytes.decode("utf-8", errors="ignore").rstrip() + suffix.decode(
            "utf-8", errors="ignore"
        )
    else:
        clipped = encoded[:max_bytes].decode("utf-8", errors="ignore").strip()
    return clipped or PLACEHOLDER
