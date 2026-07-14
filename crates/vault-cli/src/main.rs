//! fvlt — scripting/test front-end over vault-core (no UI, no registry).
//!
//!   fvlt lock    <folder> [--password-stdin]
//!   fvlt unlock  <file>   [--password-stdin]
//!   fvlt inspect <file>
//!   fvlt verify  <file>
//!
//! Passwords: --password-stdin reads one line from stdin (for scripts/tests);
//! otherwise an interactive prompt is shown (echoed — the GUI app is the
//! proper interactive surface, this tool is for automation).
//!
//! Exit codes: 0 ok, 2 usage, 3 wrong password, 4 locked out, 5 tampered, 1 other.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use vault_core::format::{inspect, lock_folder, unlock_container, verify_structure, LockOptions};
use vault_core::VaultError;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = run(&args);
    std::process::exit(code);
}

fn run(args: &[String]) -> i32 {
    let (cmd, rest) = match args.split_first() {
        Some(x) => x,
        None => return usage(),
    };
    let path = match rest.first() {
        Some(p) => PathBuf::from(p),
        None => return usage(),
    };
    let stdin_pw = rest.iter().any(|a| a == "--password-stdin");

    let hmac_key = match install_key() {
        Ok(k) => k,
        Err(e) => return fail(&format!("cannot access install key: {e}")),
    };

    match cmd.as_str() {
        "lock" => {
            let pw = match read_password(stdin_pw, true) {
                Ok(p) => p,
                Err(e) => return fail(&e),
            };
            let mut last = 0u64;
            match lock_folder(&path, pw.as_bytes(), &hmac_key, &LockOptions::default(),
                &mut |done, total| print_progress(&mut last, done, total))
            {
                Ok(dest) => {
                    eprintln!("\nlocked -> {}", dest.display());
                    0
                }
                Err(e) => err_code(&e),
            }
        }
        "unlock" => {
            let pw = match read_password(stdin_pw, false) {
                Ok(p) => p,
                Err(e) => return fail(&e),
            };
            let mut last = 0u64;
            match unlock_container(&path, pw.as_bytes(), &hmac_key, now_unix(),
                &mut |done, total| print_progress(&mut last, done, total))
            {
                Ok(dest) => {
                    eprintln!("\nunlocked -> {}", dest.display());
                    0
                }
                Err(e) => err_code(&e),
            }
        }
        "inspect" => match inspect(&path, &hmac_key) {
            Ok(h) => {
                println!("container:    {}", path.display());
                println!("uuid:         {}", hex(&h.uuid));
                println!("kdf:          argon2id m={} KiB t={} lanes={}",
                    h.kdf.m_cost_kib, h.kdf.t_cost, h.kdf.lanes);
                println!("entries:      {}", h.entry_count);
                println!("payload:      {} bytes", h.payload_len);
                println!("failed tries: {}", h.lockout.fail_count);
                println!("locked until: {}", if h.lockout.locked_until == 0 {
                    "-".to_string() } else { h.lockout.locked_until.to_string() });
                println!("hmac:         {}", if h.hmac_ok { "ok (this install)" }
                    else { "FOREIGN or tampered" });
                0
            }
            Err(e) => err_code(&e),
        },
        "verify" => match verify_structure(&path, &hmac_key) {
            Ok(frames) => {
                println!("structure ok ({frames} data frames)");
                0
            }
            Err(e) => err_code(&e),
        },
        _ => usage(),
    }
}

fn usage() -> i32 {
    eprintln!("usage: fvlt <lock|unlock|inspect|verify> <path> [--password-stdin]");
    2
}

fn fail(msg: &str) -> i32 {
    eprintln!("error: {msg}");
    1
}

fn err_code(e: &VaultError) -> i32 {
    eprintln!("error: {e}");
    match e {
        VaultError::WrongPassword { .. } => 3,
        VaultError::LockedOut { .. } => 4,
        VaultError::Tampered | VaultError::BadMagic | VaultError::BadVersion(_) => 5,
        _ => 1,
    }
}

fn read_password(from_stdin: bool, confirm: bool) -> Result<String, String> {
    let read_line = |prompt: &str| -> Result<String, String> {
        if !from_stdin {
            eprint!("{prompt}");
            let _ = std::io::stderr().flush();
        }
        let mut line = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut line)
            .map_err(|e| e.to_string())?;
        let line = line.trim_end_matches(['\r', '\n']).to_string();
        if line.is_empty() {
            return Err("empty password".into());
        }
        Ok(line)
    };
    let pw = read_line("password: ")?;
    if confirm && !from_stdin {
        let again = read_line("confirm:  ")?;
        if pw != again {
            return Err("passwords do not match".into());
        }
    }
    Ok(pw)
}

fn print_progress(last: &mut u64, done: u64, total: u64) {
    if total == 0 {
        return;
    }
    let pct = done * 100 / total;
    if pct != *last {
        *last = pct;
        eprint!("\r{pct:3}%");
        let _ = std::io::stderr().flush();
    }
}

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Per-install HMAC key at %LOCALAPPDATA%\FolderVault\install.key.
/// (The GUI app will DPAPI-protect this in phase 3; the CLI keeps it plain.)
fn install_key() -> std::io::Result<[u8; 32]> {
    let base = std::env::var_os("FVLT_KEY_DIR")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("LOCALAPPDATA").map(|d| Path::new(&d).join("FolderVault")))
        .unwrap_or_else(|| PathBuf::from(".foldervault"));
    let path = base.join("install.key");
    match std::fs::read(&path) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut k = [0u8; 32];
            k.copy_from_slice(&bytes);
            Ok(k)
        }
        _ => {
            std::fs::create_dir_all(&base)?;
            let mut k = [0u8; 32];
            vault_core::crypto::random_bytes(&mut k);
            std::fs::write(&path, k)?;
            Ok(k)
        }
    }
}
