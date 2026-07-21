# FolderVault v0.2.0

Adds password-gated deletion and a round of UI polish on top of v0.1.0.

## New in this release

- **Delete with FolderVault**: right-click a locked `.fvlt` → *Delete with
  FolderVault* (or `fvlt delete`) asks for the password (or recovery code)
  before sending it to the Recycle Bin. Shares unlock's 3-attempt / 24-hour
  lockout so it can't be used as a password-guessing oracle.
  - Honest scope: this is a **convenience gate on FolderVault's delete path**,
    not a hard block — Windows' own Delete still works. (We investigated an
    ACL-based hard block; it doesn't work reliably in user folders like
    Documents, so it isn't shipped. See the threat model.)
- **UI polish**: refined dialog to match the design — rounded lock badge, a
  crisp show/hide **eye toggle** in the password field, cleaner buttons and
  typography (Segoe UI Variable), aligned field borders.
- **Fixes**: dialog is now always-on-top; keyboard input reliably reaches the
  password fields; the confirm-password border no longer looks unfinished.

## Carried over from v0.1.0

- Right-click **Lock with FolderVault**; double-click a `.fvlt` to unlock.
- **AES-256-GCM** + **Argon2id**; a locked folder is one encrypted file
  (filenames included).
- **X25519 master recovery code** (shown once; only its public half stored).
- **3 wrong attempts → 24-hour lockout**; **crash-safe** lock/unlock.
- **DPAPI**-protected per-install key. ~360 KB exe, zero background processes.

## Downloads

| File | Use |
|---|---|
| `FolderVault-0.2.0-installer.exe` | Recommended. Per-user install, no admin, uninstaller included. |
| `FolderVault-0.2.0-portable.zip` | Run from anywhere; self-heals if moved. |
| `FolderVault-0.2.0-selfcontained.zip` | Portable + MSIX for the Windows 11 top-level menu. |
| `fvlt-0.2.0-cli.zip` | Command-line tool for scripting. |

## Notes

- **Unsigned build**: Windows SmartScreen will warn on first run. Click
  "More info → Run anyway". A signed build will come once the project has users.
- **Windows 11 menu**: without the MSIX (selfcontained package), the entry
  appears under "Show more options". With it, it's at the top level.
- **Keep your recovery code.** A forgotten password + lost recovery code means
  the data is unrecoverable by design — there is no backdoor.

## Requirements

Windows 10 (1809+) or Windows 11, 64-bit.
