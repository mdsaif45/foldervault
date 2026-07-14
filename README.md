# FolderVault

A native Windows folder locker with first-class Explorer integration.
Right-click any folder → **Lock with FolderVault** → enter a password → the folder
becomes a single encrypted file with a folder-with-padlock icon. Double-click it →
a clean, slick unlock popup. Wrong password 3 times → locked out for 24 hours
(master recovery key can always unlock).

## Design goals

| Goal                | How we get there                                              |
|---------------------|---------------------------------------------------------------|
| Tiny binary         | Rust + raw Win32 (no .NET, no Electron, no webview). Target < 2 MB. |
| Low CPU / memory    | Streaming chunked encryption (~8 MB working set regardless of folder size), AES-NI hardware acceleration. |
| Real security       | AES-256-GCM content encryption, Argon2id password hashing. Not ACL tricks — actual cryptography. |
| Perfect Explorer UX | Locked folder is a `.fvlt` container file with a custom folder+padlock icon; double-click opens the unlock dialog natively via file association. |
| Slick UI            | Borderless dark rounded window (DWM Mica/acrylic), custom-drawn, instant startup. |

## How it works (one paragraph)

Locking moves the folder's contents into a single encrypted container file
(`Photos` → `Photos.fvlt`) and deletes the original folder. The container holds a
random 256-bit data key wrapped twice: once by your password (via Argon2id) and
once by a master recovery key generated on first run. Unlocking streams the
contents back out and deletes the container. Because the locked artifact is a
regular file with our registered extension, Explorer gives us the lock icon and
double-click-to-unlock for free — no shell hooks needed for the core flow.

## Repository layout

```
foldervault/
├── crates/
│   ├── vault-core/    # container format, crypto, lockout logic (pure lib, no UI)
│   ├── vault-app/     # GUI exe: lock/unlock dialogs, file association handler
│   └── vault-cli/     # thin CLI for scripting + testing the core
├── installer/         # registry scripts for context menu + file association
├── assets/            # icons (folder+padlock .ico)
└── docs/
    ├── PLAN.md        # phased implementation plan  ← start here
    ├── SPEC.md        # container format + crypto spec
    └── THREAT-MODEL.md
```

## Prerequisites (not yet installed on this machine)

```powershell
winget install Rustlang.Rustup
rustup default stable-x86_64-pc-windows-msvc
# MSVC Build Tools if not present:
winget install Microsoft.VisualStudio.2022.BuildTools --override "--wait --add Microsoft.VisualStudio.Workload.VCTools"
```

## Build

```powershell
cargo build --release        # binaries land in target/release/
```

The release profile is tuned for size (`opt-level="z"`, LTO, `panic=abort`, stripped).
