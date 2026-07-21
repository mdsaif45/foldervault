# FolderVault v0.2.1

Security and robustness fixes from an internal review. No feature changes —
recommended for everyone on v0.2.0.

## Fixes

- **Path-traversal / ADS hardening (security)**: a crafted `.fvlt` could, on
  unlock, write outside the staging folder or into a hidden NTFS alternate data
  stream via a manifest entry containing `:` (e.g. `a/b:c`), and could name
  Windows reserved devices (`CON`, `COM1`, …). These are now rejected. Only
  affects containers from an untrusted source; your own locks were never at
  risk.
- **KDF denial-of-service (security)**: opening a maliciously edited container
  whose header requested an enormous Argon2 memory cost could exhaust memory.
  Parameters are now bounds-checked before use — a bad container is rejected
  in milliseconds.
- **Recovery-code enrollment fix (data-loss)**: the first-run master recovery
  key is now saved only after you confirm you've written the code down. Closing
  the setup dialog without saving no longer leaves an unrecoverable key
  enrolled.
- **Safe cancel during operations**: closing the dialog (X / Esc) while a
  lock/unlock/delete is in progress is now ignored, so an in-flight operation
  can't be interrupted mid-write.

## Downloads

| File | Use |
|---|---|
| `FolderVault-0.2.1-installer.exe` | Recommended. Per-user install, no admin, uninstaller included. |
| `FolderVault-0.2.1-portable.zip` | Run from anywhere; self-heals if moved. |
| `FolderVault-0.2.1-selfcontained.zip` | Portable + MSIX for the Windows 11 top-level menu. |
| `fvlt-0.2.1-cli.zip` | Command-line tool for scripting. |

## Notes

Unchanged from v0.2.0: unsigned build (SmartScreen warns on first run — "More
info → Run anyway"); keep your recovery code (a forgotten password + lost code
is unrecoverable by design). Requires Windows 10 (1809+) or Windows 11, 64-bit.
