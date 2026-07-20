//! Master recovery key (X25519 sealed-box style).
//!
//! Setup generates a keypair. The PUBLIC key is stored on the machine and
//! used at every lock to seal the folder's data key; the PRIVATE key is
//! shown to the user once as a Crockford-base32 recovery code and never
//! written to disk. Recovery unlock therefore works on any machine, bypasses
//! the lockout (a 256-bit code cannot be brute-forced), and losing the code
//! only matters if the password is also forgotten.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::crypto::{random_bytes, unwrap_key, wrap_key, SecretKey, WRAPPED_KEY_LEN};

/// ephemeral X25519 public key (32) + AES-GCM-wrapped data key (60).
pub const MASTER_WRAP_LEN: usize = 32 + WRAPPED_KEY_LEN;

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// 256-bit secret -> 52 base32 chars, + 4 checksum chars = 14 groups of 4.
const CODE_DATA_CHARS: usize = 52;
const CODE_CHECK_CHARS: usize = 4;

pub struct MasterKeyPair {
    /// Safe to store anywhere (it can only ever *seal*, never open).
    pub public: [u8; 32],
    /// Shown to the user exactly once. `XXXX-XXXX-...` (14 groups).
    pub code: String,
}

pub fn generate() -> MasterKeyPair {
    let mut sk = [0u8; 32];
    random_bytes(&mut sk);
    let secret = StaticSecret::from(sk);
    let public = PublicKey::from(&secret).to_bytes();
    let code = encode_code(&sk);
    sk.zeroize();
    MasterKeyPair { public, code }
}

fn kek_from_shared(shared: &[u8; 32]) -> SecretKey {
    let mut mac = Hmac::<Sha256>::new_from_slice(b"fvlt-master-kek-v1").expect("hmac key");
    mac.update(shared);
    SecretKey::from_bytes(mac.finalize().into_bytes().into())
}

/// Seal the data key to the master public key (done at lock time).
pub fn seal_dk(master_pub: &[u8; 32], dk: &SecretKey) -> [u8; MASTER_WRAP_LEN] {
    let eph = EphemeralSecret::random_from_rng(aes_gcm::aead::OsRng);
    let eph_pub = PublicKey::from(&eph).to_bytes();
    let shared = eph.diffie_hellman(&PublicKey::from(*master_pub));
    let kek = kek_from_shared(shared.as_bytes());
    let mut out = [0u8; MASTER_WRAP_LEN];
    out[..32].copy_from_slice(&eph_pub);
    out[32..].copy_from_slice(&wrap_key(&kek, dk));
    out
}

/// Open a sealed data key with the user's recovery code.
/// `None` = bad code (or corrupt blob).
pub fn open_dk(code: &str, wrap: &[u8; MASTER_WRAP_LEN]) -> Option<SecretKey> {
    let mut sk = decode_code(code)?;
    let secret = StaticSecret::from(sk);
    sk.zeroize();
    let eph_pub: [u8; 32] = wrap[..32].try_into().ok()?;
    let shared = secret.diffie_hellman(&PublicKey::from(eph_pub));
    let wrapped: [u8; WRAPPED_KEY_LEN] = wrap[32..].try_into().ok()?;
    unwrap_key(&kek_from_shared(shared.as_bytes()), &wrapped)
}

pub fn is_enrolled(wrap: &[u8; MASTER_WRAP_LEN]) -> bool {
    wrap.iter().any(|&b| b != 0)
}

fn encode_code(secret: &[u8; 32]) -> String {
    let mut chars = Vec::with_capacity(CODE_DATA_CHARS + CODE_CHECK_CHARS);
    encode_base32(secret, CODE_DATA_CHARS, &mut chars);
    let check = Sha256::digest(secret);
    encode_base32(&check[..3], CODE_CHECK_CHARS, &mut chars);
    chars
        .chunks(4)
        .map(|g| String::from_utf8_lossy(g).into_owned())
        .collect::<Vec<_>>()
        .join("-")
}

fn encode_base32(bytes: &[u8], n_chars: usize, out: &mut Vec<u8>) {
    let mut acc: u32 = 0;
    let mut bits = 0;
    let mut emitted = 0;
    for &b in bytes {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 && emitted < n_chars {
            bits -= 5;
            out.push(CROCKFORD[((acc >> bits) & 31) as usize]);
            emitted += 1;
        }
    }
    if emitted < n_chars {
        // flush remaining bits, left-aligned
        out.push(CROCKFORD[((acc << (5 - bits)) & 31) as usize]);
    }
}

fn decode_code(code: &str) -> Option<[u8; 32]> {
    let mut vals = Vec::with_capacity(CODE_DATA_CHARS + CODE_CHECK_CHARS);
    for c in code.chars() {
        let c = c.to_ascii_uppercase();
        let c = match c {
            '-' | ' ' => continue,
            'I' | 'L' => '1', // Crockford ambiguity mapping
            'O' => '0',
            _ => c,
        };
        vals.push(CROCKFORD.iter().position(|&a| a == c as u8)? as u32);
    }
    if vals.len() != CODE_DATA_CHARS + CODE_CHECK_CHARS {
        return None;
    }
    let mut secret = [0u8; 32];
    let mut acc: u32 = 0;
    let mut bits = 0;
    let mut idx = 0;
    for &v in &vals[..CODE_DATA_CHARS] {
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            if idx < 32 {
                secret[idx] = ((acc >> bits) & 0xFF) as u8;
                idx += 1;
            }
        }
    }
    if idx != 32 {
        return None;
    }
    // verify checksum group
    let mut expect = Vec::new();
    let check = Sha256::digest(secret);
    encode_base32(&check[..3], CODE_CHECK_CHARS, &mut expect);
    let got: Vec<u8> = vals[CODE_DATA_CHARS..].iter().map(|&v| CROCKFORD[v as usize]).collect();
    if got != expect {
        return None;
    }
    Some(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_roundtrip_with_formatting_noise() {
        let kp = generate();
        let sk = decode_code(&kp.code).expect("clean code decodes");
        // lowercase + spaces instead of dashes + ambiguous chars still decode
        let messy = kp.code.to_lowercase().replace('-', " ").replace('1', "l");
        assert_eq!(decode_code(&messy), Some(sk));
    }

    #[test]
    fn checksum_catches_typos() {
        let kp = generate();
        let mut chars: Vec<char> = kp.code.chars().collect();
        let i = chars.iter().position(|&c| c != '-').unwrap();
        chars[i] = if chars[i] == '7' { '9' } else { '7' };
        let typo: String = chars.into_iter().collect();
        assert!(decode_code(&typo).is_none());
    }

    #[test]
    fn seal_open_roundtrip_and_wrong_code() {
        let kp = generate();
        let dk = SecretKey::random();
        let sealed = seal_dk(&kp.public, &dk);
        assert!(is_enrolled(&sealed));
        let opened = open_dk(&kp.code, &sealed).expect("correct code opens");
        assert_eq!(opened.0, dk.0);
        let other = generate();
        assert!(open_dk(&other.code, &sealed).is_none());
    }

    #[test]
    fn absent_wrap_is_not_enrolled() {
        assert!(!is_enrolled(&[0u8; MASTER_WRAP_LEN]));
    }
}
