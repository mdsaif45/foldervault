# UI framework experiments (archive)

> **This is an archive branch, not part of FolderVault.** It is an orphan branch
> (`experiments/ui-framework-demos`) with its own history, kept so the
> exploration isn't lost. The shipping app lives on `main` and uses **none** of
> this — it draws its dialogs directly with raw Win32/GDI (see
> `crates/vault-app/src/ui.rs` on `main`).

## Why this exists

FolderVault's UI is hand-drawn on raw Win32 (0.36 MB binary, pixel-native, but
every rectangle is manual). The question was: would a Rust UI *framework* make
the UI easier to build, and at what cost? These two throwaway demos rebuild
FolderVault's unlock dialog in **egui** and **Slint** so the trade-off is
concrete.

## The same dialog, three ways

```
                    binary   deps   build   UI code            look control
  raw Win32 (main)  0.36 MB   ~5    ~10s    ~1200 lines Rust   total, manual
  egui              4.3  MB   231   62s     ~90 lines Rust     good, code-driven
  Slint            14.0  MB   777  130s     ~40 lines .slint   good, declarative
```

Measured on this machine (release build), 2026-07. See `screenshots/`.

## What each is

- **egui** — *immediate mode*: the whole UI is one Rust function that re-runs
  every frame (`if ui.button().clicked() {…}`). Dead simple, all-Rust, but a
  custom (game-engine-ish) look and constant redraw. Source: `egui-demo/`.
- **Slint** — *retained + declarative*: you describe the UI in a `.slint` file
  (its own small language) with a live VS Code preview + online designer; Rust
  just launches it. Closest to actually "designing" a UI. Heavier binary + a
  language to learn. Source: `slint-demo/` (UI in `slint-demo/ui/unlock.slint`).

## Verdict (for FolderVault specifically)

Keep raw Win32 on `main` — it is *why* the app is 0.36 MB and native. A
framework would multiply the binary 12–40× for a 3-dialog app. A framework
(Slint, for its designer workflow) would only pay off if the product grew to
many screens.

## Running a demo

```powershell
cd egui-demo   && cargo run --release
cd slint-demo  && cargo run --release
```
(Each pulls its own dependencies; nothing here shares FolderVault's crates.)
