# Browser authoring sources

`owner/` and `peer/` contain canonical markup, feature modules, and isolated
service factories. They are build inputs outside the installed Python package.
The complete offline artifacts remain `src/one_link/web/index.html` and
`src/one_link/web/peer.html`.

```sh
python scripts/build_owner_ui.py
python scripts/build_owner_ui.py --check
```

The historical command name is retained for CI compatibility; both commands
process **both pages** by default. Use `--page owner` or `--page peer` when
working on one page. Commit regenerated HTML with the canonical change. No
runtime imports, package installation, network requests, or source-path
redirection are involved in assembly.

See [owner architecture](owner/README.md) and [peer architecture](peer/README.md)
for ownership and service interfaces. The generator validates source inventory
and lifecycle membership; executable tests parse every module and run the
isolated services. Existing browser/source tests continue to read the actual
shipped HTML.
