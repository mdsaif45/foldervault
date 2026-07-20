# FolderVault — Implementation Plan

## Product requirements (from the brief)

1. Right-click a folder in Explorer → **Lock** option with a popup offering
   password/encryption options.
2. After entering the password, the folder is locked and shows a
   **folder-with-padlock icon**.
3. Double-clicking a locked folder opens a **clean, slick password popup**.
4. **3 failed attempts → 24-hour lockout**; only the master password can bypass it.
5. Correct password → folder restored.
6. Super lightweight: small binary, low memory/CPU, good UI.

## Core architectural decision

**A locked folder is not a folder — it's an encrypted container file.**

`D:\Photos` → lock → `D:\Photos.fvlt` (original folder gone).

Why this wins over "keep the folder, overlay an icon, hook double-click":

- **Icon**: a registered file extension gets any icon we want (folder + padlock).
  Icon *overlays* on real folders require a COM overlay handler, compete for the
  system's 15 global overlay slots (Dropbox/OneDrive hog them), and need
  Explorer restarts. Ours needs one registry key.
- **Double-click**: file associations give us "double-click → our unlock dialog"
  natively. Intercepting double-click on a real folder is impossible without
  fragile shell hooks.
- **Security**: contents are actually encrypted in one artifact. ACL/hide tricks
  (what most "folder lockers" do) are defeated by a Linux live USB or `attrib`.
- **Footprint**: no resident process, no Explorer-injected DLL for the MVP.
  Nothing runs until the user clicks.

Trade-off to document honestly: locking a folder requires rewriting its bytes
(encryption), so lock/unlock time is I/O-bound — ~1 GB/s on an SSD with AES-NI,
i.e. a 5 GB folder takes a few seconds with a progress bar. This is the price of
real encryption; anything instant is not encrypting.

## Tech stack

| Layer        | Choice                                    | Rationale |
|--------------|-------------------------------------------|-----------|
| Language     | Rust (stable, MSVC target)                | No runtime dependency, memory-safe crypto code, ~1–2 MB stripped binary. |
| Win32 API    | `windows` crate (windows-rs)              | Official Microsoft bindings, zero-cost. |
| Crypto       | RustCrypto: `aes-gcm`, `argon2`, `hmac`, `sha2`, `zeroize` | Audited pure-Rust + AES-NI intrinsics; no OpenSSL DLLs to ship. |
| UI           | Raw Win32 window, custom-drawn (Direct2D or GDI double-buffer), DWM rounded corners + Mica backdrop | "Clean slick popup" at zero framework cost. No WinUI (huge), no egui (~3 MB + GPU context), no Tauri (webview RAM). |
| Packaging    | Phase 1: `.reg`/installer registry writes. Phase 2: sparse MSIX for the Windows 11 top-level context menu. | |

Release profile (workspace `Cargo.toml`): `opt-level = "z"`, `lto = "fat"`,
`codegen-units = 1`, `panic = "abort"`, `strip = "symbols"`.

## Components

```
vault-core (lib)          vault-app (exe, GUI)           vault-cli (exe)
├── format.rs             ├── main.rs (arg routing:      └── scripting/testing
│   container read/write  │    lock <dir> | open <file>      front-end over
├── crypto.rs             │    | setup)                      vault-core
│   Argon2id KDF,         ├── ui/window.rs (borderless,
│   AES-256-GCM chunks,   │    Mica, rounded, dark)
│   key wrapping          ├── ui/lock_dialog.rs
├── lockout.rs            ├── ui/unlock_dialog.rs
│   attempts, 24 h timer, │    (attempts left, lockout
│   HMAC tamper evidence  │    countdown, shake on fail)
├── recovery.rs           ├── ui/progress.rs
│   master key gen/wrap   └── shell/assoc.rs (register
└── walk.rs                    .fvlt + context-menu verb)
    parallel folder
    streaming
```

vault-core has **zero** UI/Win32 dependencies → fully unit-testable on any OS.

## Explorer integration detail

**Phase 1 (registry only, no COM):**

- Context menu on folders — `HKCU\Software\Classes\Directory\shell\FolderVault.Lock`
  → `command` = `"...\vault-app.exe" lock "%1"`. Also on `Directory\Background`
  disabled (not needed). HKCU only → **no admin required**.
- File association — `HKCU\Software\Classes\.fvlt` → ProgID `FolderVault.Container`
  with `DefaultIcon` = folder+padlock `.ico` and `shell\open\command` =
  `"...\vault-app.exe" open "%1"`.
- On Windows 11 the verb appears under "Show more options" (and the classic menu
  directly on Win10). Fixing top-level Win11 placement is Phase 4.

**Phase 4 (Windows 11 modern menu) — done:** `vault-shellext` cdylib is an
in-proc `IExplorerCommand` COM server (110 KB) registered by a sparse MSIX
package (`installer/msix/AppxManifest.xml`). The command does nothing but
`ShellExecuteW("FolderVault.exe", "lock \"<folder>\"")` — all logic stays in
the exe. Sparse = the package registers the shell verb but the files live at
an ExternalLocation, so any build layout can register it. CLSID
`7F9C2E14-4B3A-4E2D-9C7A-A1B2C3D4E5F6`.

## Lockout design (3 attempts / 24 h)

- Attempt counter + `locked_until` timestamp live in the container header,
  authenticated by an HMAC keyed from a per-install secret in
  `%LOCALAPPDATA%\FolderVault\install.key` (DPAPI-protected), and mirrored in
  `HKCU\Software\FolderVault\state\<container-uuid>`.
- Two mirrors + HMAC make casual tampering (copy file, edit bytes, reset clock)
  detectable: on mismatch, treat as locked out.
- Honest limitation (see THREAT-MODEL.md): a determined attacker who copies the
  container to another machine escapes the counter — the *real* brute-force
  barrier is Argon2id (64 MiB, t=3), which makes offline guessing ~100 ms/try.
- Master password: on first run, generate a 256-bit recovery key, show it once
  as 8 groups of 4 Crockford-base32 chars (and offer to save a recovery file).
  Every container's data key is also wrapped by this key → master unlock always
  works, bypassing lockout.

## UI spec (vault-app)

Single borderless window, ~380×auto px, dark theme, 8 px DWM rounded corners,
Mica/acrylic backdrop with fallback solid `#1e1e24`, drop shadow. Segoe UI
Variable. No titlebar — padlock glyph + folder name + close ✕.

- **Lock dialog** (from context menu): folder name + size, password + confirm
  with strength meter, options row (secure-delete originals ▢, remember name ▢),
  primary button `Lock`. Enter = confirm.
- **Unlock dialog** (from double-click): folder name, single password box
  (focused on open), `● ● ○` attempt dots, on failure: window shake animation +
  "2 attempts remaining". On lockout: countdown `Locked — try again in 23:59:12`
  + "Use master password" link. Enter = unlock.
- **Progress**: thin indeterminate→determinate bar in the same window,
  MB/s + ETA, cancel-safe (see crash-safety below).

## Crash safety (must-have, in Phase 2)

Lock: write `Photos.fvlt.tmp` → fsync → rename to `Photos.fvlt` → verify header
→ only then delete originals (optionally secure-wipe). Unlock: extract to
`Photos.__restoring` → rename to `Photos` → delete container. A journal file in
`%LOCALAPPDATA%` records in-flight operations so a crash mid-way is resumable,
never lossy. **At no point can both copies be gone.**

## Phases

- **Phase 0 — scaffold (done)**: workspace, docs, size-tuned profiles, stubs.
- **Phase 1 — core (done)**: container format, Argon2id + AES-256-GCM
  streaming (1 MiB chunks), key wrapping, lockout module, 16 tests.
  *Measured: 200 MB locks in ~1 s incl. KDF; fvlt.exe 240 KB.*
- **Phase 2 — crash safety + recovery (done)**: X25519 master recovery key
  (public half stored, private half = one-time recovery code, bypasses
  lockout), crash-recovery journal (staging-first replay rule), secure-delete
  option, atomic rename dance. 27 tests total.
- **Phase 3 — GUI + Explorer (done)**: borderless dark Win32 window (DWM
  rounded corners + Mica + immersive dark title), owner-drawn buttons, three
  dialogs (lock / unlock / setup), password worker on a background thread with
  live progress, shake-on-fail, attempt dots, lockout countdown timer,
  "use recovery code" toggle. `.fvlt` association + folder-padlock icon
  (resource id 2), HKCU "Lock with FolderVault" verb + app icon, first-run
  setup that registers shell entries and shows the recovery code. Icons
  generated procedurally (GDI+) into multi-size ICOs. Per-monitor DPI v2 via
  manifest. FolderVault.exe = 352 KB. Verified live in Explorer (icon + type
  "FVLT File") and via CLI/GUI container cross-compatibility.
  *Note: full keystroke-level GUI automation isn't possible in this headless
  session (no interactive desktop focus); lock/unlock correctness is covered
  by the 27 vault-core tests + CLI smoke tests that exercise identical code.*
- **Phase 4 — polish + distribution**: Win11 top-level menu (sparse MSIX +
  IExplorerCommand), tiny installer (Inno Setup or MSIX), DPAPI-protect
  install.key, code signing, auto-update check (optional, off by default).

## Performance budget

| Metric                     | Target                          |
|----------------------------|---------------------------------|
| vault-app.exe size         | < 2 MB (stretch: < 1 MB)        |
| Cold start to dialog       | < 100 ms                        |
| Idle RAM (dialog open)     | < 15 MB                         |
| Encryption throughput      | ≥ 500 MB/s on AES-NI SSD        |
| Working set while locking  | < 50 MB regardless of folder size |
| Background processes       | **0** (nothing resident)        |

## Risks / open questions

1. **Antivirus heuristics**: an unsigned exe that encrypts files en masse looks
   like ransomware. Mitigations: code signing (Phase 4), only ever touching the
   user-selected folder, no network. Expect SmartScreen friction until signed.
2. **Files in use / locks**: skip-and-report vs abort — abort by default
   (folder must lock fully or not at all).
3. **Very long paths / OneDrive placeholder files**: handle `\\?\` prefix;
   detect reparse/cloud placeholders and hydrate or warn.
4. **Forgotten master password**: unrecoverable by design — must be crystal
   clear in first-run UX.
