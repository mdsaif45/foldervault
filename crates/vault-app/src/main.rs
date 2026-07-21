//! FolderVault GUI (windows subsystem — no console flash).
//!
//!   FolderVault.exe lock  "<folder>"   <- Explorer context-menu verb
//!   FolderVault.exe open  "<file>"     <- .fvlt double-click association
//!   FolderVault.exe setup              <- register shell entries + master key
//!
//! Nothing stays resident: the process exists only while a dialog is open.

#![windows_subsystem = "windows"]

mod shell;
mod ui;

use std::path::PathBuf;

use windows::core::PCWSTR;
use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK};

use vault_core::journal::Journal;

fn msgbox(text: &str) {
    let t = shell::wide(text);
    let c = shell::wide("FolderVault");
    unsafe {
        MessageBoxW(None, PCWSTR(t.as_ptr()), PCWSTR(c.as_ptr()), MB_OK | MB_ICONERROR);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let dir = shell::data_dir();
    let hmac_key = match shell::install_key(&dir) {
        Ok(k) => k,
        Err(e) => {
            msgbox(&format!("Cannot access FolderVault data directory:\n{e}"));
            return;
        }
    };
    // heal any interrupted operation before doing anything new
    if let Ok(j) = Journal::open(&dir.join("journal")) {
        let _ = j.recover(&hmac_key);
    }

    let exe = std::env::current_exe().unwrap_or_default();
    match (args.first().map(|s| s.as_str()), args.get(1)) {
        (Some("lock"), Some(path)) => {
            // self-heal registration if the (portable) exe was moved
            shell::register_if_needed(&exe);
            // first run: no master key yet -> set it up before the first lock
            let master_pub = match shell::load_master_pub(&dir) {
                Some(p) => Some(p),
                None => run_setup(&dir, &exe, hmac_key),
            };
            ui::run_dialog(ui::Mode::Lock { src: PathBuf::from(path) }, hmac_key, master_pub);
        }
        (Some("open"), Some(path)) => {
            shell::register_if_needed(&exe);
            ui::run_dialog(ui::Mode::Unlock { container: PathBuf::from(path) }, hmac_key, None);
        }
        (Some("delete"), Some(path)) => {
            shell::register_if_needed(&exe);
            ui::run_dialog(ui::Mode::Delete { container: PathBuf::from(path) }, hmac_key, None);
        }
        (Some("unregister"), _) => {
            // used by the installer's uninstaller
            shell::unregister();
        }
        _ => {
            // bare launch or explicit `setup`
            run_setup(&dir, &exe, hmac_key);
        }
    }
}

/// Register the shell entries and, if no master key is enrolled yet, generate
/// one and show the recovery code. Returns the enrolled master public key, or
/// `None` if none is enrolled.
///
/// Critical: the master public key is persisted ONLY after the user confirms
/// they saved the one-time code ("I saved it" -> `run_dialog` returns true).
/// If they dismiss the dialog (X / Esc), nothing is enrolled — otherwise a
/// user who never saw/saved the code would have an unrecoverable master key
/// sealed into every future container. Dismissing just means "no recovery key
/// yet"; a later run re-offers setup with a fresh code.
fn run_setup(dir: &std::path::Path, exe: &std::path::Path, hmac_key: [u8; 32]) -> Option<[u8; 32]> {
    if let Err(e) = shell::register(exe) {
        msgbox(&format!("Could not register Explorer integration:\n{e}"));
    }
    if let Some(existing) = shell::load_master_pub(dir) {
        return Some(existing);
    }
    let pair = vault_core::recovery::generate();
    let confirmed = ui::run_dialog(ui::Mode::Setup { code: pair.code }, hmac_key, None);
    if !confirmed {
        // user dismissed without saving the code -> do NOT enroll
        return None;
    }
    if let Err(e) = shell::save_master_pub(dir, &pair.public) {
        msgbox(&format!("Could not save the master key:\n{e}"));
        return None;
    }
    Some(pair.public)
}
