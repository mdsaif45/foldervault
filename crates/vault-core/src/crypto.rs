//! Key derivation, key wrapping, and chunk encryption (SPEC.md "Keys").

use aes_gcm::aead::{Aead, KeyInit, OsRng, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand_core::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Result, VaultError};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
/// nonce (12) + encrypted key (32) + GCM tag (16)
pub const WRAPPED_KEY_LEN: usize = NONCE_LEN + KEY_LEN + TAG_LEN;
/// Reserved chunk sequence number used as AAD for the manifest blob.
pub const MANIFEST_SEQ: u64 = u64::MAX;

/// Fill `buf` from the OS CSPRNG (for callers that need non-key randomness,
/// e.g. the per-install HMAC key file).
pub fn random_bytes(buf: &mut [u8]) {
    OsRng.fill_bytes(buf);
}

/// 256-bit secret, zeroed on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey(pub(crate) [u8; KEY_LEN]);

impl SecretKey {
    pub fn random() -> Self {
        let mut k = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut k);
        Self(k)
    }

    pub fn from_bytes(b: [u8; KEY_LEN]) -> Self {
        Self(b)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub lanes: u32,
}

impl Default for KdfParams {
    /// 64 MiB, 3 passes, 4 lanes — ~100 ms on a modern desktop.
    fn default() -> Self {
        Self { m_cost_kib: 64 * 1024, t_cost: 3, lanes: 4 }
    }
}

/// Argon2id: password + salt -> 256-bit key-encryption key.
pub fn derive_kek(password: &[u8], salt: &[u8; 16], p: &KdfParams) -> Result<SecretKey> {
    let params = argon2::Params::new(p.m_cost_kib, p.t_cost, p.lanes, Some(KEY_LEN))
        .map_err(|e| VaultError::Other(format!("bad KDF params: {e}")))?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = [0u8; KEY_LEN];
    argon
        .hash_password_into(password, salt, &mut out)
        .map_err(|e| VaultError::Other(format!("kdf failed: {e}")))?;
    Ok(SecretKey(out))
}

/// Wrap (encrypt) the data key under a KEK. Output: nonce | ct | tag.
pub fn wrap_key(kek: &SecretKey, dk: &SecretKey) -> [u8; WRAPPED_KEY_LEN] {
    let cipher = Aes256Gcm::new_from_slice(&kek.0).expect("key length");
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), dk.0.as_slice())
        .expect("aes-gcm encrypt cannot fail");
    let mut out = [0u8; WRAPPED_KEY_LEN];
    out[..NONCE_LEN].copy_from_slice(&nonce);
    out[NONCE_LEN..].copy_from_slice(&ct);
    out
}

/// Unwrap the data key. `None` means the KEK is wrong (or the blob corrupt) —
/// GCM cannot distinguish the two, which is exactly what we want to expose.
pub fn unwrap_key(kek: &SecretKey, wrapped: &[u8; WRAPPED_KEY_LEN]) -> Option<SecretKey> {
    let cipher = Aes256Gcm::new_from_slice(&kek.0).expect("key length");
    let mut pt = cipher
        .decrypt(Nonce::from_slice(&wrapped[..NONCE_LEN]), &wrapped[NONCE_LEN..])
        .ok()?;
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&pt);
    pt.zeroize();
    Some(SecretKey(key))
}

/// Streaming chunk cipher bound to one container (uuid goes into the AAD so
/// chunks cannot be reordered within, or spliced across, containers).
pub struct ChunkCipher {
    cipher: Aes256Gcm,
    uuid: [u8; 16],
}

impl ChunkCipher {
    pub fn new(dk: &SecretKey, uuid: [u8; 16]) -> Self {
        Self { cipher: Aes256Gcm::new_from_slice(&dk.0).expect("key length"), uuid }
    }

    fn aad(&self, seq: u64) -> [u8; 24] {
        let mut aad = [0u8; 24];
        aad[..16].copy_from_slice(&self.uuid);
        aad[16..].copy_from_slice(&seq.to_le_bytes());
        aad
    }

    /// Frame: nonce (12) | blob_len u32 | ciphertext+tag (blob_len bytes).
    pub fn seal(&self, seq: u64, plain: &[u8]) -> Vec<u8> {
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let ct = self
            .cipher
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: plain, aad: &self.aad(seq) })
            .expect("aes-gcm encrypt cannot fail");
        let mut out = Vec::with_capacity(NONCE_LEN + 4 + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&(ct.len() as u32).to_le_bytes());
        out.extend_from_slice(&ct);
        out
    }

    pub fn open(&self, seq: u64, nonce: &[u8; NONCE_LEN], blob: &[u8]) -> Result<Vec<u8>> {
        self.cipher
            .decrypt(Nonce::from_slice(nonce), Payload { msg: blob, aad: &self.aad(seq) })
            .map_err(|_| VaultError::Tampered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cheap params so tests don't burn 64 MiB per derivation.
    pub fn test_kdf() -> KdfParams {
        KdfParams { m_cost_kib: 1024, t_cost: 1, lanes: 1 }
    }

    #[test]
    fn wrap_roundtrip_and_wrong_kek() {
        let kek = SecretKey::random();
        let dk = SecretKey::random();
        let wrapped = wrap_key(&kek, &dk);
        let got = unwrap_key(&kek, &wrapped).expect("correct kek unwraps");
        assert_eq!(got.0, dk.0);
        assert!(unwrap_key(&SecretKey::random(), &wrapped).is_none());
    }

    #[test]
    fn kdf_is_deterministic_and_salt_sensitive() {
        let p = test_kdf();
        let a = derive_kek(b"hunter2", &[7u8; 16], &p).unwrap();
        let b = derive_kek(b"hunter2", &[7u8; 16], &p).unwrap();
        let c = derive_kek(b"hunter2", &[8u8; 16], &p).unwrap();
        assert_eq!(a.0, b.0);
        assert_ne!(a.0, c.0);
    }

    #[test]
    fn chunk_aad_binds_seq_and_uuid() {
        let dk = SecretKey::random();
        let cc = ChunkCipher::new(&dk, [1u8; 16]);
        let framed = cc.seal(5, b"data");
        let nonce: [u8; NONCE_LEN] = framed[..NONCE_LEN].try_into().unwrap();
        let blob = &framed[NONCE_LEN + 4..];
        assert_eq!(cc.open(5, &nonce, blob).unwrap(), b"data");
        // wrong sequence number -> reordering detected
        assert!(cc.open(6, &nonce, blob).is_err());
        // different container uuid -> cross-splice detected
        let other = ChunkCipher::new(&dk, [2u8; 16]);
        assert!(other.open(5, &nonce, blob).is_err());
    }
}
