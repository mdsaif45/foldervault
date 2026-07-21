# Changelog

All notable changes to FolderVault are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
See [docs/VERSIONING.md](docs/VERSIONING.md) for how versions are decided.

## [Unreleased]

## [0.2.1] - 2026-07-21

### Security
- Reject `.fvlt` manifest paths containing `:` (which could escape the
  extraction folder via a drive-prefix quirk, or write a hidden NTFS alternate
  data stream) and Windows reserved device names (`CON`, `COM1`, …).
- Bounds-check Argon2 KDF parameters read from a container header before use, so
  a maliciously edited container can't request an enormous memory cost (OOM).

### Fixed
- First-run master recovery key is now enrolled only after the user confirms the
  code was saved; dismissing the setup dialog no longer leaves an unrecoverable
  key sealed into future containers.
- Closing the dialog (X / Esc) while a lock/unlock/delete is in progress is
  ignored, so an in-flight filesystem operation can't be interrupted mid-write.

## [0.2.0] - 2026-07-20

### Added
- **Delete with FolderVault**: a right-click verb on locked `.fvlt` files (and
  `fvlt delete`) that asks for the password or recovery code before recycling
  the container. Shares unlock's 3-attempt / 24-hour lockout. Honest scope: a
  convenience gate on FolderVault's delete path, not a hard block — Windows' own
  Delete still works.

### Changed
- Dialog UI refined to the intended design: rounded lock badge, crisp show/hide
  eye toggle in the password field, cleaner buttons and typography, aligned
  field borders.

### Fixed
- Dialogs are always-on-top; keyboard input reliably reaches the password
  fields; the confirm-password field border no longer looks unfinished.

## [0.1.0] - 2026-07-20

### Added
- First release. Right-click **Lock with FolderVault** on any folder;
  double-click a locked `.fvlt` to unlock.
- AES-256-GCM content encryption + Argon2id password hashing; a locked folder
  becomes a single encrypted file (filenames included).
- X25519 master recovery code, shown once on first run; only its public half is
  stored on disk.
- 3 wrong attempts → 24-hour lockout (recovery code still works).
- Crash-safe lock/unlock (journalled staging → rename → delete).
- Windows 11 top-level context menu via a sparse MSIX + `IExplorerCommand`.
- DPAPI-protected per-install key. Four release artifacts: installer, portable,
  self-contained (+MSIX), CLI.

[Unreleased]: https://github.com/mdsaif45/foldervault/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/mdsaif45/foldervault/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/mdsaif45/foldervault/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/mdsaif45/foldervault/releases/tag/v0.1.0
