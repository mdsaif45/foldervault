//! Container header read/write and the lock/unlock operations (SPEC.md).

use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::crypto::{
    derive_kek, unwrap_key, wrap_key, ChunkCipher, KdfParams, SecretKey, MANIFEST_SEQ, NONCE_LEN,
    TAG_LEN, WRAPPED_KEY_LEN,
};
use crate::journal::{Journal, OpKind, Record};
use crate::lockout::{LockoutState, MAX_ATTEMPTS};
use crate::recovery::{is_enrolled, open_dk, seal_dk, MASTER_WRAP_LEN};
use crate::walk::{self, Entry};
use crate::{Result, VaultError, CHUNK_SIZE, MAGIC, VERSION};

type HmacSha256 = Hmac<Sha256>;

pub const HEADER_LEN: usize = 268;
const HMAC_OFFSET: usize = HEADER_LEN - 32;
/// Upper bound for the encrypted manifest frame (~1M entries).
const MAX_MANIFEST_LEN: usize = 256 * 1024 * 1024;

pub struct Header {
    pub uuid: [u8; 16],
    pub salt: [u8; 16],
    pub kdf: KdfParams,
    pub wrapped_dk_pw: [u8; WRAPPED_KEY_LEN],
    /// X25519-sealed data key for master recovery; all-zero = not enrolled.
    pub wrapped_dk_mk: [u8; MASTER_WRAP_LEN],
    pub lockout: LockoutState,
    pub entry_count: u64,
    /// Total plaintext bytes (for progress reporting).
    pub payload_len: u64,
    /// Whether the header HMAC verified against this install's key. False on
    /// a container created by another install (or a tampered one) — the
    /// lockout fields are then untrusted and get clamped by the caller.
    pub hmac_ok: bool,
}

impl Header {
    pub fn to_bytes(&self, hmac_key: &[u8; 32]) -> [u8; HEADER_LEN] {
        let mut b = [0u8; HEADER_LEN];
        b[0..4].copy_from_slice(&MAGIC);
        b[4..8].copy_from_slice(&VERSION.to_le_bytes());
        b[8..24].copy_from_slice(&self.uuid);
        b[24..40].copy_from_slice(&self.salt);
        b[40..44].copy_from_slice(&self.kdf.m_cost_kib.to_le_bytes());
        b[44..48].copy_from_slice(&self.kdf.t_cost.to_le_bytes());
        b[48..52].copy_from_slice(&self.kdf.lanes.to_le_bytes());
        b[52..112].copy_from_slice(&self.wrapped_dk_pw);
        b[112..204].copy_from_slice(&self.wrapped_dk_mk);
        b[204..208].copy_from_slice(&self.lockout.fail_count.to_le_bytes());
        // b[208..212] reserved, zero
        b[212..220].copy_from_slice(&self.lockout.locked_until.to_le_bytes());
        b[220..228].copy_from_slice(&self.entry_count.to_le_bytes());
        b[228..236].copy_from_slice(&self.payload_len.to_le_bytes());
        let mut mac = HmacSha256::new_from_slice(hmac_key).expect("hmac key");
        mac.update(&b[..HMAC_OFFSET]);
        b[HMAC_OFFSET..].copy_from_slice(&mac.finalize().into_bytes());
        b
    }

    pub fn from_bytes(b: &[u8; HEADER_LEN], hmac_key: &[u8; 32]) -> Result<Header> {
        if b[0..4] != MAGIC {
            return Err(VaultError::BadMagic);
        }
        let version = u32::from_le_bytes(b[4..8].try_into().unwrap());
        if version != VERSION {
            return Err(VaultError::BadVersion(version));
        }
        let mut mac = HmacSha256::new_from_slice(hmac_key).expect("hmac key");
        mac.update(&b[..HMAC_OFFSET]);
        let hmac_ok = mac.verify_slice(&b[HMAC_OFFSET..]).is_ok();
        Ok(Header {
            uuid: b[8..24].try_into().unwrap(),
            salt: b[24..40].try_into().unwrap(),
            kdf: KdfParams {
                m_cost_kib: u32::from_le_bytes(b[40..44].try_into().unwrap()),
                t_cost: u32::from_le_bytes(b[44..48].try_into().unwrap()),
                lanes: u32::from_le_bytes(b[48..52].try_into().unwrap()),
            },
            wrapped_dk_pw: b[52..112].try_into().unwrap(),
            wrapped_dk_mk: b[112..204].try_into().unwrap(),
            lockout: LockoutState {
                fail_count: u32::from_le_bytes(b[204..208].try_into().unwrap()),
                locked_until: u64::from_le_bytes(b[212..220].try_into().unwrap()),
            },
            entry_count: u64::from_le_bytes(b[220..228].try_into().unwrap()),
            payload_len: u64::from_le_bytes(b[228..236].try_into().unwrap()),
            hmac_ok,
        })
    }
}

fn rewrite_header(f: &mut File, header: &Header, hmac_key: &[u8; 32]) -> Result<()> {
    f.seek(SeekFrom::Start(0))?;
    f.write_all(&header.to_bytes(hmac_key))?;
    f.sync_all()?;
    Ok(())
}

/// Join a manifest-relative path onto `root`, rejecting anything that could
/// escape it (`..`, absolute paths, drive prefixes). Defense against a
/// crafted container performing path traversal on unlock.
pub(crate) fn safe_join(root: &Path, rel: &str) -> Result<PathBuf> {
    if rel.is_empty() {
        return Err(VaultError::Tampered);
    }
    let mut out = root.to_path_buf();
    for comp in Path::new(rel).components() {
        match comp {
            Component::Normal(c) => out.push(c),
            _ => return Err(VaultError::Tampered),
        }
    }
    Ok(out)
}

fn read_frame(r: &mut impl Read, max_len: usize) -> Result<([u8; NONCE_LEN], Vec<u8>)> {
    let mut nonce = [0u8; NONCE_LEN];
    r.read_exact(&mut nonce)?;
    let mut len_bytes = [0u8; 4];
    r.read_exact(&mut len_bytes)?;
    let len = u32::from_le_bytes(len_bytes) as usize;
    if len < TAG_LEN || len > max_len {
        return Err(VaultError::Tampered);
    }
    let mut blob = vec![0u8; len];
    r.read_exact(&mut blob)?;
    Ok((nonce, blob))
}

#[derive(Default)]
pub struct LockOptions {
    pub kdf: Option<KdfParams>,
    /// Master public key: when set, the data key is also sealed to it so the
    /// recovery code can unlock this container.
    pub master_pub: Option<[u8; 32]>,
    /// Best-effort overwrite of source file contents before deletion.
    /// (SSD wear-leveling limits what this can promise — see THREAT-MODEL.md.)
    pub secure_delete: bool,
    /// Send the original folder to the Recycle Bin (recoverable) instead of a
    /// permanent delete. Ignored when `secure_delete` is set (a wipe is,
    /// by intent, unrecoverable).
    pub recycle_original: bool,
    /// Mark the resulting `.fvlt` read-only so Explorer asks before deleting
    /// it — friction against accidental deletion, not a hard block.
    pub readonly_container: bool,
}

/// How the caller is trying to open a container.
pub enum Credential<'a> {
    Password(&'a [u8]),
    /// Master recovery code (`XXXX-XXXX-...`). Bypasses the lockout — the
    /// code has 256 bits of entropy, brute force is not a concern.
    MasterCode(&'a str),
}

/// Encrypt `src` folder into a sibling `<name>.fvlt` container, then delete
/// the original folder. Write is atomic: tmp file -> fsync -> rename; the
/// source is only removed after the container is fully on disk.
pub fn lock_folder(
    src: &Path,
    password: &[u8],
    hmac_key: &[u8; 32],
    opts: &LockOptions,
    journal: Option<&Journal>,
    progress: &mut dyn FnMut(u64, u64),
) -> Result<PathBuf> {
    let name = src
        .file_name()
        .ok_or_else(|| VaultError::Other("folder has no name".into()))?
        .to_string_lossy()
        .into_owned();
    let parent = src
        .parent()
        .ok_or_else(|| VaultError::Other("folder has no parent".into()))?;
    let dest = parent.join(format!("{name}.fvlt"));
    if dest.exists() {
        return Err(VaultError::Exists(dest));
    }
    let tmp = parent.join(format!("{name}.fvlt.tmp"));
    if tmp.exists() {
        fs::remove_file(&tmp)?; // stale leftover from an interrupted attempt
    }

    let scan = walk::scan(src)?;
    let uuid = match write_container(
        src, &tmp, &scan.entries, scan.total_bytes, password, hmac_key, opts, progress,
    ) {
        Ok(uuid) => uuid,
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            return Err(e);
        }
    };

    let record = journal
        .map(|j| {
            let rec = Record {
                op: OpKind::Lock,
                folder: src.to_string_lossy().into_owned(),
                container: dest.to_string_lossy().into_owned(),
                staging: tmp.to_string_lossy().into_owned(),
            };
            j.begin(&uuid, &rec).map(|p| (j, p))
        })
        .transpose()?;

    fs::rename(&tmp, &dest)?;
    if opts.secure_delete {
        // a wipe is meant to be unrecoverable, so never recycle in this mode
        wipe_tree(src, &scan.entries);
        fs::remove_dir_all(src)?;
    } else if opts.recycle_original {
        crate::trash::recycle(src)?;
    } else {
        fs::remove_dir_all(src)?;
    }
    if opts.readonly_container {
        let _ = crate::trash::set_readonly(&dest, true);
    }
    if let Some((j, p)) = record {
        j.complete(&p);
    }
    Ok(dest)
}

/// Best-effort: overwrite file contents with zeros + fsync before deletion.
fn wipe_tree(src: &Path, entries: &[Entry]) {
    let zeros = vec![0u8; CHUNK_SIZE];
    for e in entries.iter().filter(|e| !e.is_dir && e.size > 0) {
        let Ok(path) = safe_join(src, &e.rel_path) else { continue };
        // clear read-only so the overwrite (and later delete) can proceed
        if let Ok(meta) = fs::metadata(&path) {
            let mut perms = meta.permissions();
            if perms.readonly() {
                perms.set_readonly(false);
                let _ = fs::set_permissions(&path, perms);
            }
        }
        let Ok(mut f) = OpenOptions::new().write(true).open(&path) else { continue };
        let mut remaining = e.size;
        while remaining > 0 {
            let n = remaining.min(CHUNK_SIZE as u64) as usize;
            if f.write_all(&zeros[..n]).is_err() {
                break;
            }
            remaining -= n as u64;
        }
        let _ = f.sync_all();
    }
}

#[allow(clippy::too_many_arguments)]
fn write_container(
    src: &Path,
    tmp: &Path,
    entries: &[Entry],
    total_bytes: u64,
    password: &[u8],
    hmac_key: &[u8; 32],
    opts: &LockOptions,
    progress: &mut dyn FnMut(u64, u64),
) -> Result<[u8; 16]> {
    use aes_gcm::aead::OsRng;
    use rand_core::RngCore;

    let kdf = opts.kdf.unwrap_or_default();
    let mut uuid = [0u8; 16];
    OsRng.fill_bytes(&mut uuid);
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    let dk = SecretKey::random();
    let kek = derive_kek(password, &salt, &kdf)?;
    let header = Header {
        uuid,
        salt,
        kdf,
        wrapped_dk_pw: wrap_key(&kek, &dk),
        wrapped_dk_mk: opts
            .master_pub
            .map(|p| seal_dk(&p, &dk))
            .unwrap_or([0u8; MASTER_WRAP_LEN]),
        lockout: LockoutState::default(),
        entry_count: entries.len() as u64,
        payload_len: total_bytes,
        hmac_ok: true,
    };

    let file = File::create(tmp)?;
    let mut w = BufWriter::with_capacity(CHUNK_SIZE, file);
    w.write_all(&header.to_bytes(hmac_key))?;

    let cipher = ChunkCipher::new(&dk, uuid);
    let manifest =
        bincode::serialize(entries).map_err(|e| VaultError::Other(format!("manifest: {e}")))?;
    if manifest.len() > MAX_MANIFEST_LEN - TAG_LEN {
        return Err(VaultError::Other("folder has too many entries".into()));
    }
    w.write_all(&cipher.seal(MANIFEST_SEQ, &manifest))?;

    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut seq = 0u64;
    let mut done = 0u64;
    for e in entries.iter().filter(|e| !e.is_dir) {
        let mut f = File::open(safe_join(src, &e.rel_path)?)?;
        let mut remaining = e.size;
        while remaining > 0 {
            let n = remaining.min(CHUNK_SIZE as u64) as usize;
            f.read_exact(&mut buf[..n]).map_err(|_| {
                VaultError::Other(format!("{} changed while locking", e.rel_path))
            })?;
            w.write_all(&cipher.seal(seq, &buf[..n]))?;
            seq += 1;
            remaining -= n as u64;
            done += n as u64;
            progress(done, total_bytes);
        }
    }
    w.flush()?;
    w.get_ref().sync_all()?;
    Ok(uuid)
}

/// Shared prologue for unlock/delete: open the container, verify the
/// credential against the header, and mutate the lockout state accordingly.
///
/// On success returns the opened handle (seeked past the header is the
/// caller's job), the parsed header, the recovered data key, and whether the
/// file was read-only on entry (so the caller can re-arm the guard on a later
/// error). A wrong password rewrites the incremented lockout counter and
/// re-arms read-only before returning the error; the master code bypasses the
/// lockout. Read-only is cleared on entry so the header can be rewritten.
fn open_and_authorize(
    container: &Path,
    credential: Credential<'_>,
    hmac_key: &[u8; 32],
    now_unix: u64,
) -> Result<(File, Header, SecretKey, bool)> {
    let was_readonly = std::fs::metadata(container).map(|m| m.permissions().readonly()).unwrap_or(false);
    if was_readonly {
        let _ = crate::trash::set_readonly(container, false);
    }
    let rearm = |c: &Path| {
        if was_readonly {
            let _ = crate::trash::set_readonly(c, true);
        }
    };
    let mut f = OpenOptions::new().read(true).write(true).open(container)?;
    let mut hb = [0u8; HEADER_LEN];
    f.read_exact(&mut hb)?;
    let mut header = Header::from_bytes(&hb, hmac_key)?;

    // Foreign/tampered lockout fields can't be trusted: allow exactly one
    // attempt before a fresh lockout arms (Argon2 remains the real barrier).
    if !header.hmac_ok && header.lockout.fail_count < MAX_ATTEMPTS - 1 {
        header.lockout.fail_count = MAX_ATTEMPTS - 1;
    }

    let dk = match credential {
        Credential::Password(password) => {
            if let Err(e) = header.lockout.check(now_unix) {
                rearm(container);
                return Err(e);
            }
            let kek = derive_kek(password, &header.salt, &header.kdf)?;
            match unwrap_key(&kek, &header.wrapped_dk_pw) {
                Some(dk) => dk,
                None => {
                    let err = header.lockout.record_failure(now_unix);
                    rewrite_header(&mut f, &header, hmac_key)?;
                    rearm(container);
                    return Err(err);
                }
            }
        }
        Credential::MasterCode(code) => {
            if !is_enrolled(&header.wrapped_dk_mk) {
                rearm(container);
                return Err(VaultError::Other(
                    "no master key is enrolled in this container".into(),
                ));
            }
            match open_dk(code, &header.wrapped_dk_mk) {
                Some(dk) => dk,
                None => {
                    rearm(container);
                    return Err(VaultError::Other("invalid recovery code".into()));
                }
            }
        }
    };
    if header.lockout != LockoutState::default() || !header.hmac_ok {
        header.lockout.reset();
        rewrite_header(&mut f, &header, hmac_key)?;
    }
    Ok((f, header, dk, was_readonly))
}

/// Verify the password/recovery code and, on success, recycle the container
/// (recoverable from the Recycle Bin). Shares the exact lockout behavior of
/// unlock — 3 wrong attempts arm the 24 h lockout — so the delete prompt can't
/// be used as an unlimited password oracle. Does NOT extract anything.
///
/// This is a *password convenience* on top of the file's own deletability, not
/// an enforcement mechanism: the built-in Windows Delete still works (see
/// docs/THREAT-MODEL.md).
pub fn verify_and_delete(
    container: &Path,
    credential: Credential<'_>,
    hmac_key: &[u8; 32],
    now_unix: u64,
) -> Result<()> {
    let (f, _header, _dk, _was_readonly) =
        open_and_authorize(container, credential, hmac_key, now_unix)?;
    drop(f); // close before deleting
    // credential verified: clear the read-only guard and recycle.
    let _ = crate::trash::set_readonly(container, false);
    crate::trash::recycle(container)?;
    Ok(())
}

/// Decrypt a container back into its folder, then delete the container.
/// A wrong password mutates the lockout state in the container header before
/// returning; the master code path bypasses the lockout entirely. Extraction
/// goes to `<name>.__restoring` and is renamed into place only when complete
/// — a failure never leaves a half-restored folder.
pub fn unlock_container(
    container: &Path,
    credential: Credential<'_>,
    hmac_key: &[u8; 32],
    now_unix: u64,
    journal: Option<&Journal>,
    progress: &mut dyn FnMut(u64, u64),
) -> Result<PathBuf> {
    let (mut f, header, dk, was_readonly) =
        open_and_authorize(container, credential, hmac_key, now_unix)?;
    let rearm = |c: &Path| {
        if was_readonly {
            let _ = crate::trash::set_readonly(c, true);
        }
    };

    // from here on, any error leaves the container in place; re-arm its
    // read-only guard on the way out.
    macro_rules! bail {
        ($e:expr) => {{
            rearm(container);
            return Err($e);
        }};
    }

    if let Err(e) = f.seek(SeekFrom::Start(HEADER_LEN as u64)) {
        bail!(e.into());
    }
    let mut r = BufReader::with_capacity(CHUNK_SIZE, f);
    let cipher = ChunkCipher::new(&dk, header.uuid);
    let (nonce, blob) = match read_frame(&mut r, MAX_MANIFEST_LEN) {
        Ok(v) => v,
        Err(e) => bail!(e),
    };
    let manifest = match cipher.open(MANIFEST_SEQ, &nonce, &blob) {
        Ok(m) => m,
        Err(e) => bail!(e),
    };
    let entries: Vec<Entry> = match bincode::deserialize(&manifest) {
        Ok(v) => v,
        Err(_) => bail!(VaultError::Tampered),
    };
    if entries.len() as u64 != header.entry_count {
        bail!(VaultError::Tampered);
    }

    let stem = container
        .file_stem()
        .ok_or_else(|| VaultError::Other("container has no name".into()))?
        .to_string_lossy()
        .into_owned();
    let parent = container
        .parent()
        .ok_or_else(|| VaultError::Other("container has no parent".into()))?;
    let dest = parent.join(&stem);
    if dest.exists() {
        bail!(VaultError::Exists(dest));
    }
    let tmpdir = parent.join(format!("{stem}.__restoring"));
    if tmpdir.exists() {
        fs::remove_dir_all(&tmpdir)?;
    }
    fs::create_dir(&tmpdir)?;

    let result = extract_entries(&mut r, &cipher, &entries, &tmpdir, header.payload_len, progress);
    if let Err(e) = result {
        let _ = fs::remove_dir_all(&tmpdir);
        bail!(e);
    }
    drop(r); // close the container before deleting it

    let record = journal
        .map(|j| {
            let rec = Record {
                op: OpKind::Unlock,
                folder: dest.to_string_lossy().into_owned(),
                container: container.to_string_lossy().into_owned(),
                staging: tmpdir.to_string_lossy().into_owned(),
            };
            j.begin(&header.uuid, &rec).map(|p| (j, p))
        })
        .transpose()?;

    fs::rename(&tmpdir, &dest)?;
    // the container may be read-only (delete guard); clear it, then recycle
    // it so an accidental unlock is undoable.
    let _ = crate::trash::set_readonly(container, false);
    crate::trash::recycle(container)?;
    if let Some((j, p)) = record {
        j.complete(&p);
    }
    Ok(dest)
}

fn extract_entries(
    r: &mut impl Read,
    cipher: &ChunkCipher,
    entries: &[Entry],
    tmpdir: &Path,
    payload_len: u64,
    progress: &mut dyn FnMut(u64, u64),
) -> Result<()> {
    let mut seq = 0u64;
    let mut done = 0u64;
    for e in entries {
        let target = safe_join(tmpdir, &e.rel_path)?;
        if e.is_dir {
            fs::create_dir_all(&target)?;
            continue;
        }
        if let Some(p) = target.parent() {
            fs::create_dir_all(p)?;
        }
        let out = File::create(&target)?;
        let mut w = BufWriter::with_capacity(CHUNK_SIZE, out);
        let mut remaining = e.size;
        while remaining > 0 {
            let expected = remaining.min(CHUNK_SIZE as u64) as usize;
            let (nonce, blob) = read_frame(r, CHUNK_SIZE + TAG_LEN)?;
            let plain = cipher.open(seq, &nonce, &blob)?;
            seq += 1;
            if plain.len() != expected {
                return Err(VaultError::Tampered);
            }
            w.write_all(&plain)?;
            remaining -= expected as u64;
            done += expected as u64;
            progress(done, payload_len);
        }
        w.flush()?;
        let out = w.into_inner().map_err(|e| VaultError::Io(e.into_error()))?;
        if e.mtime > 0 {
            let _ = out.set_modified(UNIX_EPOCH + Duration::from_secs(e.mtime));
        }
        drop(out);
        if e.readonly {
            let mut perms = fs::metadata(&target)?.permissions();
            perms.set_readonly(true);
            fs::set_permissions(&target, perms)?;
        }
    }
    Ok(())
}

/// Read header info without credentials (for `fvlt inspect` and the UI).
pub fn inspect(container: &Path, hmac_key: &[u8; 32]) -> Result<Header> {
    let mut f = File::open(container)?;
    let mut hb = [0u8; HEADER_LEN];
    f.read_exact(&mut hb)?;
    Header::from_bytes(&hb, hmac_key)
}

/// Structural integrity walk without credentials: header parses and every
/// frame is well-formed through EOF. (Cryptographic verification of chunk
/// tags requires the password.)
pub fn verify_structure(container: &Path, hmac_key: &[u8; 32]) -> Result<u64> {
    let mut f = File::open(container)?;
    let mut hb = [0u8; HEADER_LEN];
    f.read_exact(&mut hb)?;
    Header::from_bytes(&hb, hmac_key)?;
    let mut r = BufReader::with_capacity(CHUNK_SIZE, f);
    read_frame(&mut r, MAX_MANIFEST_LEN)?; // manifest
    let mut frames = 0u64;
    loop {
        let mut probe = [0u8; 1];
        match r.read(&mut probe)? {
            0 => break,
            _ => {
                let mut rest = [0u8; NONCE_LEN - 1];
                r.read_exact(&mut rest)?;
                let mut len_bytes = [0u8; 4];
                r.read_exact(&mut len_bytes)?;
                let len = u32::from_le_bytes(len_bytes) as u64;
                if (len as usize) < TAG_LEN || len as usize > CHUNK_SIZE + TAG_LEN {
                    return Err(VaultError::Tampered);
                }
                std::io::copy(&mut r.by_ref().take(len), &mut std::io::sink())
                    .ok()
                    .filter(|&n| n == len)
                    .ok_or(VaultError::Tampered)?;
                frames += 1;
            }
        }
    }
    Ok(frames)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_join_rejects_escapes() {
        let root = Path::new("out");
        assert!(safe_join(root, "a/b.txt").is_ok());
        assert!(safe_join(root, "..").is_err());
        assert!(safe_join(root, "a/../../b").is_err());
        assert!(safe_join(root, "/etc/passwd").is_err());
        assert!(safe_join(root, "C:/windows/system32").is_err());
        assert!(safe_join(root, "").is_err());
    }

    #[test]
    fn header_roundtrip_and_hmac() {
        let key = [9u8; 32];
        let h = Header {
            uuid: [1; 16],
            salt: [2; 16],
            kdf: KdfParams::default(),
            wrapped_dk_pw: [3; WRAPPED_KEY_LEN],
            wrapped_dk_mk: [4; MASTER_WRAP_LEN],
            lockout: LockoutState { fail_count: 2, locked_until: 42 },
            entry_count: 7,
            payload_len: 1234,
            hmac_ok: true,
        };
        let bytes = h.to_bytes(&key);
        let back = Header::from_bytes(&bytes, &key).unwrap();
        assert!(back.hmac_ok);
        assert_eq!(back.uuid, h.uuid);
        assert_eq!(back.wrapped_dk_mk, h.wrapped_dk_mk);
        assert_eq!(back.lockout, h.lockout);
        assert_eq!(back.entry_count, 7);
        // wrong hmac key -> parses but flagged foreign
        let foreign = Header::from_bytes(&bytes, &[8u8; 32]).unwrap();
        assert!(!foreign.hmac_ok);
        // flipped byte inside the hmac'd region -> flagged
        let mut bad = bytes;
        bad[30] ^= 1;
        assert!(!Header::from_bytes(&bad, &key).unwrap().hmac_ok);
        // bad magic
        bad[0] = b'X';
        assert!(matches!(Header::from_bytes(&bad, &key), Err(VaultError::BadMagic)));
    }
}
