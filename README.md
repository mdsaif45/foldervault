# FolderVault

A native Windows folder locker with first-class Explorer integration.
Right-click any folder → **Lock with FolderVault** → enter a password → the folder
becomes a single encrypted file with a folder-with-padlock icon. Double-click it →
a clean, slick unlock popup. Wrong password 3 times → locked out for 24 hours
(master recovery code can always unlock).

Rust + raw Win32. No .NET, no Electron, no webview. `FolderVault.exe` is ~350 KB
and nothing stays resident — the process only exists while a dialog is open.

## Status

All four phases complete; `v0.1.0` is release-ready.

| Metric | Result |
|---|---|
| `FolderVault.exe` | ~350 KB |
| `fvlt.exe` (CLI) | ~310 KB |
| `vault_shellext.dll` (Win11 menu) | ~110 KB |
| Encryption throughput | ~190 MB/s (AES-NI) |
| Tests | 30 (crypto, format, lockout, journal, recovery, DPAPI) |
| Resident processes | 0 |

## How it works (one paragraph)

Locking moves the folder's contents into a single encrypted container file
(`Photos` → `Photos.fvlt`) and deletes the original folder. The container holds a
random 256-bit data key wrapped twice: once by your password (via Argon2id) and
once by an X25519 master recovery key generated on first run. Unlocking streams
the contents back out and deletes the container. Because the locked artifact is a
regular file with our registered extension, Explorer gives us the lock icon and
double-click-to-unlock for free. The write is crash-safe (staging file → fsync →
rename → only then delete the other copy, journalled), so a crash never loses
data. See [docs/SPEC.md](docs/SPEC.md) for the container format and
[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) for what it does and doesn't protect.

## Security

- **AES-256-GCM** content + manifest encryption (filenames never visible in the
  locked file); per-chunk nonce with container-UUID+sequence AAD blocks
  reordering/splicing.
- **Argon2id** password hashing (64 MiB, t=3) — the real barrier against offline
  brute force.
- **X25519** master recovery: only the *public* half is stored on disk (it can
  seal but never open); the recovery code is shown once and never saved.
- **DPAPI** protects the per-install key file at rest (user-scoped).
- **3 attempts → 24 h lockout**, tamper-evident (header HMAC + registry mirror);
  the recovery code bypasses the lockout.

## Install

Grab a release artifact (see [docs/RELEASING.md](docs/RELEASING.md) for how they
differ) and run it once — every artifact self-registers the right-click menu and
`.fvlt` association on first run:

- **installer.exe** — per-user, no admin, with an uninstaller. Recommended.
- **portable.zip** — run from anywhere; self-heals if you move the folder.
- **selfcontained.zip** — portable + a sparse MSIX that puts the entry at the
  **top** of the Windows 11 right-click menu (not under "Show more options").
- **cli.zip** — `fvlt.exe` for scripting.

## Repository layout

```
foldervault/
├── crates/
│   ├── vault-core/      # container format, crypto, lockout, journal, DPAPI (pure lib)
│   ├── vault-app/       # GUI exe: dialogs + HKCU shell registration
│   ├── vault-cli/       # fvlt: scriptable front-end + test harness
│   └── vault-shellext/  # IExplorerCommand COM DLL for the Win11 top-level menu
├── installer/           # build-release.ps1, Inno Setup script, MSIX manifest, icon gen
├── assets/              # app.ico (padlock) + locked-folder.ico
└── docs/                # PLAN, SPEC, THREAT-MODEL, RELEASING, VERSIONING
```

## Project docs

- [CHANGELOG.md](CHANGELOG.md) — what changed in each release.
- [docs/VERSIONING.md](docs/VERSIONING.md) — SemVer policy; how versions are
  decided; security fixes ship immediately as a patch.
- [CONTRIBUTING.md](CONTRIBUTING.md) — issue → branch → PR workflow.
- [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) — what it does and doesn't protect.

## Building from source

Prerequisites: Rust stable (`x86_64-pc-windows-msvc`) and the MSVC C++ toolset.

```powershell
winget install Rustlang.Rustup
# MSVC C++ toolset (adds to an existing VS, or standalone Build Tools):
pwsh installer\setup-toolchain.ps1
```

```powershell
cargo build --release          # binaries in target/release/
cargo test  --workspace        # 30 tests
pwsh installer\build-release.ps1   # all four release artifacts -> dist/
```

The release profile is tuned for size (`opt-level="z"`, fat LTO, `panic=abort`,
stripped) with the AES/Argon2/SHA crates pinned to `opt-level=3` so the crypto
hot path stays fast.
