# FolderVault Container Format (`.fvlt`) — v1

All integers little-endian. One container = one locked folder.

```
┌──────────────────────────────────────────────────────────┐
│ HEADER — 268 bytes (plaintext, HMAC-authenticated)       │
│  magic          4 B   "FVLT"                             │
│  version        4 B   u32 = 1                            │
│  container_uuid 16 B  random, stable for container life  │
│  kdf_salt       16 B  Argon2id salt                      │
│  kdf_params     12 B  m_cost(KiB) u32 | t_cost u32 |     │
│                       lanes u32   (default 65536, 3, 4)  │
│  wrapped_dk_pw  60 B  data key wrapped by password KEK   │
│                       (12 B nonce + 32 B ct + 16 B tag)  │
│  wrapped_dk_mk  92 B  X25519-sealed data key for master  │
│                       recovery: ephemeral pubkey (32) +  │
│                       AES-GCM wrap (60).                 │
│                       all-zero = no master key enrolled  │
│  lockout        16 B  fail_count u32 | reserved u32 |    │
│                       locked_until_unix u64              │
│  entry_count    8 B   u64                                │
│  payload_len    8 B   u64  total PLAINTEXT bytes         │
│                       (drives progress bars)             │
│  header_hmac    32 B  HMAC-SHA256 over bytes 0..236,     │
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
DK ──AES-256-GCM──► manifest + chunks
install.key (%LOCALAPPDATA%, DPAPI in GUI) ──► HMAC key for header/lockout

Master recovery (X25519 sealed box):
  setup:  keypair generated once. master.pub stored on disk (can only SEAL);
          the private key is shown ONCE as the recovery code, never stored.
  code =  Crockford-base32: 52 data chars + 4 checksum chars, 14 groups of 4
          (I/L→1, O→0 mapping; case/dash/space insensitive on entry)
  lock:   eph = random X25519 key; shared = ECDH(eph, master.pub)
          KEK_mk = HMAC-SHA256(key="fvlt-master-kek-v1", shared)
          wrapped_dk_mk = eph.pub (32) ‖ AES-GCM-wrap(KEK_mk, DK) (60)
  rescue: code → private key → ECDH(private, eph.pub) → KEK_mk → DK.
          Bypasses lockout (256-bit code: brute force is not a concern)
          and resets it on success.
```

- `DK` is generated fresh per lock operation (`OsRng`), zeroized after use
  (`zeroize` crate).
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
fvlt lock   <folder> [--password-stdin] [--secure-delete] [--recycle] [--readonly]
fvlt unlock <file>   [--password-stdin | --master-stdin]
fvlt delete <file>   [--password-stdin | --master-stdin]  # verify -> recycle
fvlt inspect <file>          # header + lockout state, no secrets
fvlt verify <file>           # structural integrity walk, no credentials
fvlt master-init [--force]   # generate recovery code (printed once)
fvlt recover                 # replay crash-recovery journal (also automatic)
```

`delete` verifies the password/recovery code (sharing unlock's 3-attempt / 24 h
lockout, so it can't be used as an unlimited oracle) and, on success, sends the
container to the Recycle Bin without extracting. It is a *convenience gate*, not
enforcement — the OS's own delete still works (see THREAT-MODEL.md).

## Crash-recovery journal

Both operations follow *stage → rename → delete the other copy*; the only
dangerous window is between rename and delete (both copies on disk, never
zero). A journal record `{op, folder, container, staging}` is fsynced to
`%LOCALAPPDATA%\FolderVault\journal\<uuid>.jrec` just before the rename and
removed after the delete. Replay rule: **if staging still exists the rename
never happened** — remove staging only, the pre-rename copy stays the source
of truth; if staging is gone, the rename committed — finish the delete (for
lock, only after `verify_structure` passes on the container).

## Test matrix (Phase 1 exit criteria)

- Round-trip: deep trees, empty files/dirs, >4 GiB file, unicode + >260-char paths.
- Wrong password → clean error, fail_count increments, plaintext never touched.
- Bit-flip in header / manifest / any chunk / any tag → detected, no partial extract.
- Chunk reorder / cross-container splice → AAD rejects.
- Lockout: 3 fails → locked; clock rollback → still locked; master key → unlocks.
- Kill -9 during lock and during unlock → journal recovery leaves no data loss.
