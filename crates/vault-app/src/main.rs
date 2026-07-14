//! FolderVault GUI (windows subsystem — no console flash).
//!
//! Invocations (all sub-100 ms cold start, nothing stays resident):
//!   FolderVault.exe lock  "<folder>"   ← Explorer context-menu verb
//!   FolderVault.exe open  "<file>"     ← .fvlt double-click association
//!   FolderVault.exe setup              ← first run / re-register shell entries
//!
//! UI: single borderless dark window, DWM rounded corners + Mica backdrop,
//! custom-drawn (see docs/PLAN.md §UI spec).

#![windows_subsystem = "windows"]

mod shell;
mod ui;

fn main() {
    // TODO(phase-3): route args → ui::lock_dialog / ui::unlock_dialog / shell::setup.
}
