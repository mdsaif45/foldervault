# Versioning & release policy

FolderVault follows [Semantic Versioning 2.0.0](https://semver.org): every
release is `MAJOR.MINOR.PATCH`. The number reflects **what changed for people
using it**, not how much work went in — a one-line security fix is a perfectly
good reason to cut a new PATCH.

## What bumps which number

| Bump | When | Example |
|---|---|---|
| **PATCH** (`0.2.0` → `0.2.1`) | Backwards-compatible bug or security fixes. No new features, no format changes. | The v0.2.1 traversal / KDF fixes. |
| **MINOR** (`0.2.1` → `0.3.0`) | New, backwards-compatible functionality. Existing `.fvlt` files still open. | The v0.2.0 "Delete with FolderVault" feature. |
| **MAJOR** (`0.x` → `1.0.0`, `1.x` → `2.0.0`) | A breaking change: the `.fvlt` container format changes incompatibly, or a CLI flag / behavior is removed. | A future format v2 that old builds can't read. |

### The `0.x` phase (where we are)

While the version starts with `0.`, the project is still taking shape and any
release may change things freely. Reaching **`1.0.0`** is a deliberate promise:
the container format is frozen and the tool is considered production-trustworthy.
We are intentionally not there yet (the build is unsigned and unaudited).

## Release cadence

- **Released when ready**, not on a calendar. A solo open-source project — a
  release happens when a change is worth shipping.
- **Security fixes ship immediately as a PATCH release**, regardless of what
  else is in flight. This is the one rule we treat as non-negotiable.

## How a release is cut

1. Land the changes on `main` (via issue → branch → PR — see
   [CONTRIBUTING.md](../CONTRIBUTING.md)).
2. Update `CHANGELOG.md` (move items out of *Unreleased* into the new version).
3. Bump `version` in the workspace `Cargo.toml`.
4. Build artifacts: `pwsh installer/build-release.ps1`.
5. Tag `vX.Y.Z` and push the tag.
6. `gh release create vX.Y.Z dist/* --notes-file docs/RELEASE-NOTES-vX.Y.Z.md`.

## Who decides

There is no external authority — SemVer is a convention, not a rule anyone
enforces. The project owner decides each version. We follow SemVer anyway
because it is what package managers and downstream users rely on to upgrade
safely, and it makes the project's releases predictable and trustworthy.
