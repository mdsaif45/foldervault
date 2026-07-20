# FolderVault v0.1.0

First release. Lock any Windows folder behind a password, straight from the
right-click menu.

## Features

- **Right-click → Lock with FolderVault** on any folder; **double-click** a
  locked `.fvlt` file to unlock. Clean dark dialog, folder+padlock icon.
- **Real encryption**: AES-256-GCM content + Argon2id password hashing. A locked
  folder is a single encrypted file — filenames included.
- **Master recovery code** (X25519): shown once on first run, unlocks anything
  even after you forget a password. Only its public half is stored on disk.
- **3 wrong attempts → 24-hour lockout** (the recovery code still works).
- **Crash-safe**: an interrupted lock/unlock never loses data (journalled
  staging → rename → delete).
- **Tiny + quiet**: ~350 KB exe, ~190 MB/s encryption, zero background processes.
- **DPAPI**-protected per-install key.

## Downloads

| File | Use |
|---|---|
| `FolderVault-0.1.0-installer.exe` | Recommended. Per-user install, no admin, uninstaller included. |
| `FolderVault-0.1.0-portable.zip` | Run from anywhere; self-heals if moved. |
| `FolderVault-0.1.0-selfcontained.zip` | Portable + MSIX for the Windows 11 top-level menu. |
| `fvlt-0.1.0-cli.zip` | Command-line tool for scripting. |

## Notes

- **Unsigned build**: Windows SmartScreen will warn on first run (an app that
  encrypts files looks like ransomware to heuristics). Click "More info → Run
  anyway". A signed build will come once the project has users.
- **Windows 11 menu**: without the MSIX (selfcontained package), the entry
  appears under "Show more options". With it, it's at the top level.
- **Keep your recovery code.** A forgotten password + lost recovery code means
  the data is unrecoverable by design — there is no backdoor.

## Requirements

Windows 10 (1809+) or Windows 11, 64-bit.
