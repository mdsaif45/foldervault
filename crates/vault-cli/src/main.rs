//! fvlt — scripting/test front-end over vault-core (no UI, no registry).
//!
//!   fvlt lock        <folder> [--password-stdin] [--secure-delete]
//!   fvlt unlock      <file>   [--password-stdin | --master-stdin]
//!   fvlt inspect     <file>
//!   fvlt verify      <file>
//!   fvlt master-init          # generate recovery code (prints once) [--force]
//!   fvlt recover              # replay crash-recovery journal
//!
//! Passwords: --password-stdin/--master-stdin read one line from stdin (for
//! scripts/tests); otherwise an interactive prompt is shown (echoed — the GUI
//! app is the proper interactive surface, this tool is for automation).
//!
//! Exit codes: 0 ok, 2 usage, 3 wrong password, 4 locked out, 5 tampered, 1 other.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use vault_core::format::{
    inspect, lock_folder, unlock_container, verify_structure, Credential, LockOptions,
};
use vault_core::journal::Journal;
use vault_core::recovery;
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
    let flag = |name: &str| rest.iter().any(|a| a == name);

    let dir = data_dir();
    let hmac_key = match install_key(&dir) {
        Ok(k) => k,
        Err(e) => return fail(&format!("cannot access install key: {e}")),
    };
    let journal = Journal::open(&dir.join("journal")).ok();

    // heal any interrupted operation before doing anything new
    if let Some(j) = &journal {
        if let Ok(actions) = j.recover(&hmac_key) {
            for a in &actions {
                eprintln!("recovered: {a:?}");
            }
        }
    }

    match cmd.as_str() {
        "master-init" => {
            let pub_path = dir.join("master.pub");
            if pub_path.exists() && !flag("--force") {
                return fail("a master key already exists (use --force to replace it; \
                             containers sealed to the old key keep working only with the OLD code)");
            }
            let pair = recovery::generate();
            if let Err(e) = std::fs::write(&pub_path, pair.public) {
                return fail(&format!("cannot save master public key: {e}"));
            }
            println!("Master recovery code (shown ONCE — write it down or store it in a password manager):");
            println!();
            println!("    {}", pair.code);
            println!();
            println!("Anyone with this code can unlock your folders. FolderVault stores only");
            println!("the public half; losing the code cannot be undone.");
            0
        }
        "recover" => 0, // recovery already ran above
        "lock" => {
            let path = match rest.iter().find(|a| !a.starts_with("--")) {
                Some(p) => PathBuf::from(p),
                None => return usage(),
            };
            let pw = match read_secret("password: ", flag("--password-stdin"), true) {
                Ok(p) => p,
                Err(e) => return fail(&e),
            };
            let mut opts = LockOptions {
                secure_delete: flag("--secure-delete"),
                ..Default::default()
            };
            let pub_path = dir.join("master.pub");
            if let Ok(bytes) = std::fs::read(&pub_path) {
                if bytes.len() == 32 {
                    opts.master_pub = Some(bytes.try_into().unwrap());
                }
            }
            if opts.master_pub.is_none() {
                eprintln!("note: no master key enrolled (run `fvlt master-init`) — \
                           this container will be password-only");
            }
            let mut last = 0u64;
            match lock_folder(&path, pw.as_bytes(), &hmac_key, &opts, journal.as_ref(),
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
            let path = match rest.iter().find(|a| !a.starts_with("--")) {
                Some(p) => PathBuf::from(p),
                None => return usage(),
            };
            let use_master = flag("--master-stdin");
            let secret = match read_secret(
                if use_master { "recovery code: " } else { "password: " },
                flag("--password-stdin") || use_master,
                false,
            ) {
                Ok(p) => p,
                Err(e) => return fail(&e),
            };
            let cred = if use_master {
                Credential::MasterCode(&secret)
            } else {
                Credential::Password(secret.as_bytes())
            };
            let mut last = 0u64;
            match unlock_container(&path, cred, &hmac_key, now_unix(), journal.as_ref(),
                &mut |done, total| print_progress(&mut last, done, total))
            {
                Ok(dest) => {
                    eprintln!("\nunlocked -> {}", dest.display());
                    0
                }
                Err(e) => err_code(&e),
            }
        }
        "inspect" => {
            let path = match rest.first() {
                Some(p) => PathBuf::from(p),
                None => return usage(),
            };
            match inspect(&path, &hmac_key) {
                Ok(h) => {
                    println!("container:    {}", path.display());
                    println!("uuid:         {}", hex(&h.uuid));
                    println!("kdf:          argon2id m={} KiB t={} lanes={}",
                        h.kdf.m_cost_kib, h.kdf.t_cost, h.kdf.lanes);
                    println!("entries:      {}", h.entry_count);
                    println!("payload:      {} bytes", h.payload_len);
                    println!("master key:   {}", if recovery::is_enrolled(&h.wrapped_dk_mk) {
                        "enrolled" } else { "not enrolled" });
                    println!("failed tries: {}", h.lockout.fail_count);
                    println!("locked until: {}", if h.lockout.locked_until == 0 {
                        "-".to_string() } else { h.lockout.locked_until.to_string() });
                    println!("hmac:         {}", if h.hmac_ok { "ok (this install)" }
                        else { "FOREIGN or tampered" });
                    0
                }
                Err(e) => err_code(&e),
            }
        }
        "verify" => {
            let path = match rest.first() {
                Some(p) => PathBuf::from(p),
                None => return usage(),
            };
            match verify_structure(&path, &hmac_key) {
                Ok(frames) => {
                    println!("structure ok ({frames} data frames)");
                    0
                }
                Err(e) => err_code(&e),
            }
        }
        _ => usage(),
    }
}

fn usage() -> i32 {
    eprintln!("usage: fvlt lock <folder> [--password-stdin] [--secure-delete]");
    eprintln!("       fvlt unlock <file> [--password-stdin | --master-stdin]");
    eprintln!("       fvlt inspect|verify <file>");
    eprintln!("       fvlt master-init [--force] | recover");
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

fn read_secret(prompt: &str, from_stdin: bool, confirm: bool) -> Result<String, String> {
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
            return Err("empty input".into());
        }
        Ok(line)
    };
    let pw = read_line(prompt)?;
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

fn data_dir() -> PathBuf {
    std::env::var_os("FVLT_KEY_DIR")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("LOCALAPPDATA").map(|d| Path::new(&d).join("FolderVault")))
        .unwrap_or_else(|| PathBuf::from(".foldervault"))
}

/// Per-install HMAC key at %LOCALAPPDATA%\FolderVault\install.key.
/// (The GUI app will DPAPI-protect this in phase 3; the CLI keeps it plain.)
fn install_key(base: &Path) -> std::io::Result<[u8; 32]> {
    let path = base.join("install.key");
    match std::fs::read(&path) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut k = [0u8; 32];
            k.copy_from_slice(&bytes);
            Ok(k)
        }
        _ => {
            std::fs::create_dir_all(base)?;
            let mut k = [0u8; 32];
            vault_core::crypto::random_bytes(&mut k);
            std::fs::write(&path, k)?;
            Ok(k)
        }
    }
}
