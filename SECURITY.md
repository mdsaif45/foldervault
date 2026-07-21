# Security Policy

## Reporting a vulnerability

Please report security issues **privately**, not as a public issue:

- Use GitHub's **[Report a vulnerability](https://github.com/mdsaif45/foldervault/security/advisories/new)**
  (repository → Security → Advisories), or
- if that's unavailable, open a minimal issue asking for a private contact and
  we'll follow up — do not include exploit details in the public issue.

Please include: what you found, how to reproduce it, the FolderVault version,
and the potential impact. We'll acknowledge and work on a fix; security fixes
ship as a patch release as soon as they're ready
(see [docs/VERSIONING.md](docs/VERSIONING.md)).

## Supported versions

This is a pre-1.0 project; only the **latest release** is supported. Upgrade to
the newest version before reporting.

## Scope & honest limits

FolderVault's threat model — what it does and does **not** protect against — is
documented in [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md). In short: it
protects the *confidentiality* of a locked folder's contents (AES-256-GCM +
Argon2id), not its *availability* — the encrypted file can still be deleted by
anyone with access to it. Reports that amount to "the OS lets the owner delete
their own file" or "an administrator can bypass a user-space guard" are known
and documented, not vulnerabilities.

Genuinely in scope: anything that lets an attacker **read locked contents
without the password/recovery code**, bypass the attempt lockout, corrupt data
undetectably, or execute code / traverse paths from a crafted `.fvlt`.
