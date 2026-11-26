# Rolling new code onto a running source install

This is for a machine that runs One Link from a git checkout: the daemon is started from the checkout's `.venv`, `one_link` is installed editable from `src/`, and the desktop shortcut runs `pythonw -m one_link.cli app` in that folder. A packaged install updates through the updater and does not use this procedure.

It was written from one roll, on Windows, on 2026-11-26, and records what that roll needed, including four things that were not obvious beforehand. Total downtime was 71 seconds.

## What you are replacing

A source install is four things that must agree. Changing the checkout changes only the first.

| Part | Where it lives | Changes when |
| --- | --- | --- |
| Python source | `src/one_link/` (editable install) | you move the checkout |
| Native extension | `one_link_native` in `.venv/Lib/site-packages` | you install a build of `native/` |
| Native window | `native/ol_shell/target/release/ol_shell[.exe]` | you build `native/ol_shell` |
| Running processes | supervisor, daemon, the window | you restart them |

Never move the checkout under a running daemon. Modules it has not imported yet would load from the new revision into the old process.

## Before you stop anything

1. **The checkout is clean and the target is a fast-forward.** `git status --short` prints nothing, and `git merge-base --is-ancestor HEAD <target>` succeeds.
2. **Build the native extension somewhere else.** In another checkout of the target revision: `maturin build --release --locked` from `native/`. Installing a finished wheel takes a second; building in place would add minutes of downtime. Runtime dependencies in `uv.lock` rarely change; if they did, plan for that too. Do not run `uv sync` in the live folder: it removes the native extension, which is not in the lock.
3. **Know who is attached.** List the processes whose command line names this checkout. A `one_link.cli tail` listener belongs to someone; tell them.
4. **Record the state you will compare against.** The daemon's reported source fingerprint (`/api/me`) and the list of saved sign-ins (`/api/auth/sessions`), read with the owner token.
5. **Check nothing is in flight.** A stop interrupts a transfer in progress; it resumes after the restart.

## The roll

1. **Stop.** `python -m one_link.cli daemon-stop` from the checkout, using its `.venv`. The daemon exits 0 and its supervisor exits with it.

   A daemon older than `4e73895` cannot finish stopping while a `tail` listener or a quiet peer session is attached (see "Four things" below). If it has not exited after ten seconds, end the attached `tail` process. The daemon then exits at once, cleanly.
2. **Back up what a first start could change.** Copy `state.db` (and `-wal`, `-shm` if present) from the data folder, and the installed `one_link_native` package with its `.dist-info`, to a folder outside the data folder.
3. **Move the checkout.** Leave a branch at the old revision, then `git merge --ff-only <target>`.
4. **Install the native extension.** `uv pip install --python .venv/Scripts/python.exe --no-deps --reinstall <wheel>`, then `python scripts/verify_native_runtime.py`.
5. **Start without a window.** `pythonw -m one_link.cli app --no-browser`, started with the normal desktop environment and the checkout as working directory. Starting it from a development shell hands that shell's environment to the daemon for its whole life.
6. **Check it.** `/api/debug/health` answers 200. `/api/me` reports the fingerprint of the files now in the checkout (compute it there: `one_link.build_identity.runtime_build_identity()`). The saved sign-ins have the same record-key prefixes as before the stop. The log has no "prior shutdown was unclean" integrity check.
7. **Rebuild the native window in this checkout**, with every One Link window closed: `python scripts/build_native_shell.py --output-dir <any folder> --required`. It prints `UI pin verified`.
8. **Open One Link from its shortcut.** A window that was open across the roll reloads itself if its sign-in is still valid. One whose sign-in was already dead cannot; close it.

## If the new daemon does not come up

Nothing irreversible has happened. Move the checkout back to the branch left in step 3, restore the native package from the backup, and start as in step 5. Restore `state.db` only if the new code changed it and the old code cannot read it; the schema version is in the `schema_version` table.

## Four things this roll found

**A daemon asked to stop kept running while anything stayed connected.** Since Python 3.12 a closed asyncio server waits for every connection it accepted. Measured: stopped in 1.8 seconds with nothing connected; still running 45 seconds after acknowledging the stop with one `tail` client or one quiet peer session. Fixed in `4e73895`. A daemon older than that needs the workaround in step 1.

**The native window refuses the page it was not built for.** `native/ol_shell/build.rs` compiles the SHA-256 of `src/one_link/web/index.html` into the window, and the window will not render a page with a different hash. After a roll that changes the page, the old window binary refuses it and the launcher falls back to a browser window with a tamper warning. That is the mechanism working. Rebuild the window (step 7).

**The pin is over the file's bytes in this checkout.** On Windows a checkout has CRLF line endings; a page written by `scripts/build_owner_ui.py`, or a checkout on another platform, has LF. Same commit, different hash. A window built in a different folder of the same revision was pinned to a hash this checkout did not have. Build the window in the checkout it will run from.

**The same is true of the source fingerprint.** It is computed over file bytes, so the value computed in one checkout does not predict the value in another. Compare the daemon's report with a fingerprint computed in the live checkout, together with a clean `git status` there.

## What this does not cover

- macOS and Linux. The steps are the same in outline; the process inspection, the way a detached process is started and the window build differ, and none of that was exercised.
- An install that runs on the system Python with no `.venv`, or a checkout that follows `master`. One such install is known and neither part was exercised. For a checkout that follows `master`, the change has to reach `master` first; moving it to an unmerged branch is a different, larger step than the one described here.
- A machine with no Rust toolchain. Steps 2 and 7 need one. Without the window build One Link still opens, in a browser window.
- An install whose data key is protected by a passphrase. A daemon from `61ab3e1` on refuses to start without `ONE_LINK_PASSPHRASE`; that is intended.
