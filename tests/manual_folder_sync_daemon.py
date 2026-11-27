"""Real test daemon with scheduled folder pushes disabled.

Only tests.harness opts into this module. The normal product CLI and all other
live tests keep the periodic scheduler; this process still uses the real CLI,
watchers, protocol handlers, storage, and authenticated receipt validation.
"""

from one_link import cli
from one_link.daemon import Daemon


async def _manual_folder_sync_only(_daemon: Daemon) -> None:
    """Leave delivery to the explicit sync request under test."""


def main() -> None:
    Daemon._folder_sync_loop = _manual_folder_sync_only
    cli.main()


if __name__ == "__main__":
    main()
