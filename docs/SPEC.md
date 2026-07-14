# FolderVault Container Format (`.fvlt`) — v1

All integers little-endian. One container = one locked folder.

```
┌──────────────────────────────────────────────────────────┐
│ HEADER — 236 bytes (plaintext, HMAC-authenticated)       │
│  magic          4 B   "FVLT"                             │
│  version        4 B   u32 = 1                            │
│  container_uuid 16 B  random, stable for container life  │
│  kdf_salt       16 B  Argon2id salt                      │
│  kdf_params     12 B  m_cost(KiB) u32 | t_cost u32 |     │
│                       lanes u32   (default 65536, 3, 4)  │
│  wrapped_dk_pw  60 B  data key wrapped by password KEK   │
│                       (12 B nonce + 32 B ct + 16 B tag)  │
│  wrapped_dk_mk  60 B  data key wrapped by master KEK     │
│                       (all-zero = no master key, phase 2)│
│  lockout        16 B  fail_count u32 | reserved u32 |    │
│                       locked_until_unix u64              │
│  entry_count    8 B   u64                                │
│  payload_len    8 B   u64  total PLAINTEXT bytes         │
│                       (drives progress bars)             │
│  header_hmac    32 B  HMAC-SHA256 over bytes 0..204,     │
│                       keyed by install key (see below)   │
├──────────────────────────────────────────────────────────┤
│ MANIFEST — one frame (see framing below), seq = u64::MAX │
│  bincode list of entries:                                │
│   { rel_path, size, mtime, is_dir, readonly }            │
│  → filenames are never visible in the locked artifact    │
├──────────────────────────────────────────────────────────┤
│ PAYLOAD: file contents as a frame stream, manifest order │
│  frame = 12 B nonce | u32 blob_len | blob                │
│          where blob = AES-256-GCM ciphertext+tag         │
│  plaintext chunk size: 1 MiB (last chunk of a file short)│
│  AAD per frame = container_uuid ‖ chunk_seq u64 LE       │
│  (global seq across all files, starting at 0)            │
│  → chunks cannot be reordered/spliced across containers  │
└──────────────────────────────────────────────────────────┘
```

## Keys

```
password ──Argon2id(salt,params)──► KEK_pw ──unwrap──► DK (random 256-bit)
master recovery key (first run) ──HKDF──► KEK_mk ──unwrap──► DK
DK ──AES-256-GCM──► manifest + chunks
install.key (%LOCALAPPDATA%, DPAPI) ──► HMAC key for header/lockout state
```

- `DK` is generated fresh per lock operation (`OsRng`), zeroized after use
  (`zeroize` crate).
- Password change / master unlock only re-wraps `DK` — no payload rewrite.
- Nonces: 96-bit random per chunk; chunk sequence number in AAD prevents
  reorder attacks despite random nonces.

## Lockout state machine

```
UNLOCKED_STATE (fail_count = 0)
  wrong pw → fail_count++            (header rewritten + HMAC + registry mirror)
  fail_count == 3 → locked_until = now + 24 h
LOCKED_OUT
  password entry disabled until locked_until
  master key path always allowed → on success: fail_count = 0
Tamper / foreign check on every open:
  header_hmac invalid (container from another install, or edited bytes)
  → lockout fields are untrusted: clamp fail_count to MAX-1, i.e. exactly one
    attempt is allowed before a fresh 24 h lockout arms. A legitimate owner
    (right password, e.g. after reinstalling Windows) gets in first try; an
    attacker resetting the counter by re-copying the file gets one guess per
    copy, throttled by Argon2id. Registry mirror (vault-app, phase 3):
    higher fail_count wins.
```

## CLI surface (vault-cli, also the test harness)

```
fvlt lock   <folder> [--password-stdin] [--secure-delete]
fvlt unlock <file>   [--password-stdin] [--master-stdin]
fvlt inspect <file>          # header + lockout state, no secrets
fvlt verify <file>           # full integrity walk without extracting
```

## Test matrix (Phase 1 exit criteria)

- Round-trip: deep trees, empty files/dirs, >4 GiB file, unicode + >260-char paths.
- Wrong password → clean error, fail_count increments, plaintext never touched.
- Bit-flip in header / manifest / any chunk / any tag → detected, no partial extract.
- Chunk reorder / cross-container splice → AAD rejects.
- Lockout: 3 fails → locked; clock rollback → still locked; master key → unlocks.
- Kill -9 during lock and during unlock → journal recovery leaves no data loss.
