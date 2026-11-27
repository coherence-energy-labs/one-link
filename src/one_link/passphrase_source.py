"""Where the operator's passphrase comes from.

``ONE_LINK_PASSPHRASE`` in the environment was the only way to supply the
passphrase that seals the identity key and the lockbox. An environment
variable ends up in unit files, shell history, ``docker inspect`` output and
the environment of every child process, which is a poor home for a
long-lived secret.

``ONE_LINK_PASSPHRASE_FILE`` names a file that holds the passphrase instead.
That is how systemd credentials (``LoadCredential=``), Docker secrets and
Kubernetes secret volumes deliver a secret: a file only this service can
read, mounted at start. The file is read once, here, and its content is
placed in this process's own ``ONE_LINK_PASSPHRASE`` so every existing reader
of that variable keeps working without knowing where the value came from.
"""

from __future__ import annotations

import logging
import os
import stat
from collections.abc import MutableMapping
from pathlib import Path

log = logging.getLogger(__name__)

ENV_VAR = "ONE_LINK_PASSPHRASE"
FILE_ENV_VAR = "ONE_LINK_PASSPHRASE_FILE"
MAX_PASSPHRASE_FILE_BYTES = 4096


class PassphraseSourceError(RuntimeError):
    """The configured passphrase file cannot be used."""


def adopt_passphrase_file(environ: MutableMapping[str, str] | None = None) -> bool:
    """Load the passphrase named by ``ONE_LINK_PASSPHRASE_FILE``.

    Returns ``True`` when a passphrase was loaded from the file, ``False``
    when no file is configured. Calling it again is harmless. Raises
    :class:`PassphraseSourceError` when a file is configured but cannot be
    used, because starting without the passphrase the operator asked for
    would silently leave the key material unprotected.
    """
    env = os.environ if environ is None else environ
    configured = env.get(FILE_ENV_VAR, "")
    if not configured:
        return False
    path = Path(configured)
    try:
        info = path.stat()
        if not stat.S_ISREG(info.st_mode):
            raise PassphraseSourceError(f"{FILE_ENV_VAR} must name a regular file: {path}")
        if info.st_size > MAX_PASSPHRASE_FILE_BYTES:
            raise PassphraseSourceError(
                f"{FILE_ENV_VAR} is larger than {MAX_PASSPHRASE_FILE_BYTES} bytes: {path}"
            )
        raw = path.read_bytes()
    except OSError as exc:
        raise PassphraseSourceError(f"{FILE_ENV_VAR} cannot be read: {exc}") from exc
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PassphraseSourceError(f"{FILE_ENV_VAR} is not valid UTF-8: {path}") from exc
    # Editors and `echo` append one line ending; it is not part of the secret.
    if text.endswith("\r\n"):
        text = text[:-2]
    elif text.endswith("\n"):
        text = text[:-1]
    if not text:
        raise PassphraseSourceError(f"{FILE_ENV_VAR} names an empty file: {path}")
    if "\x00" in text:
        raise PassphraseSourceError(f"{FILE_ENV_VAR} contains a NUL byte: {path}")
    existing = env.get(ENV_VAR, "")
    if existing and existing != text:
        raise PassphraseSourceError(
            f"both {ENV_VAR} and {FILE_ENV_VAR} are set and they disagree; set only one"
        )
    if os.name == "posix" and info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise PassphraseSourceError(
            f"{FILE_ENV_VAR} is writable by other users, so its content cannot "
            f"be trusted: {path}"
        )
    if os.name == "posix" and info.st_mode & stat.S_IROTH:
        log.warning(
            "%s is readable by every user on this machine (%s); restrict it "
            "to the service account unless the mount is already private",
            FILE_ENV_VAR,
            path,
        )
    env[ENV_VAR] = text
    return True
