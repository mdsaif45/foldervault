# Contributing to FolderVault

Thanks for your interest. This is a small, security-sensitive project, so the
workflow is deliberately simple and explicit.

By participating, you agree to abide by our
[Code of Conduct](CODE_OF_CONDUCT.md).

## Development workflow

Every change flows through an issue, a branch, and a pull request:

1. **Open an issue** describing the bug or feature.
2. **Branch** off `main`, named for the work:
   - `fix/<slug>` — bug fixes
   - `feat/<slug>` — new features
   - `docs/<slug>` — documentation
   - `chore/<slug>` — build/tooling
3. **Commit** to the branch. Keep messages descriptive; no AI co-author
   trailers.
4. **Open a PR** that references the issue (e.g. "Closes #12") so merging it
   closes the issue automatically.
5. **Merge** into `main` once tests pass. `main` should always build and pass
   `cargo test --workspace`.

Small, safe chores may go straight to `main` at the maintainer's discretion;
anything touching crypto, the container format, or delete/lockout logic should
go through a PR.

## Before you push

```powershell
cargo test --workspace     # all tests must pass
cargo build --release      # must build clean
```

If you changed anything a user would notice, add an entry to the *Unreleased*
section of [CHANGELOG.md](CHANGELOG.md).

## Security

Crypto, container-format, path-handling (`safe_join`), and lockout code is the
sensitive core in `crates/vault-core`. Changes there need tests. See
[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) for what the tool does and does not
protect against — please keep claims honest.

To report a vulnerability privately, use GitHub's **Report a vulnerability**
button under the repository's Security tab rather than a public issue.

## Versioning

See [docs/VERSIONING.md](docs/VERSIONING.md). In short: SemVer, released when
ready, security fixes ship immediately as a patch.
