# DESIGN.md — claude-secrets architecture

## Goals

1. **Plaintext never lands in chat transcripts.** When a user pastes
   a secret, the AI agent stores it via `claude-secrets put NAME`
   and replies with the handle. From that point forward, chat and
   configs reference `${SECRET:NAME}` — safe to keep in transcripts.

2. **Plaintext lives in process memory, never on disk** (except in
   the at-rest-encrypted `.age` file). When a tool needs the value,
   it pipes from `claude-secrets get NAME` to the consumer process.
   The plaintext exists in one process's stdin/stdout for one call.

3. **No daemon, no network, no cloud.** Everything is local-only.
   The encrypted blobs are files. The audit log is a file. There's
   no service to attack, no API to authenticate to, no central
   server to compromise.

4. **Sovereign-friendly tooling.** age is open-source, authored
   by Filippo Valsorda (ex-Go security team lead), with both Rust
   (rage) and Go (age) implementations. No NATO/Western cloud
   vendor in the trust path.

5. **Auditable.** Every put / get / list / rm / init operation
   appends a line to `~/.claude-secrets/audit.log`. Tampering is
   detectable (the log is on the same disk, so root-level
   compromise wins — but accidental modification or non-root
   process behaviour is detectable).

## Non-goals

- **Multi-user secret sharing.** Each user has their own keypair.
  If you want to share with someone else, encrypt to their pubkey
  separately. This tool is single-recipient by default.
- **Secret rotation tracking.** The tool doesn't track which secrets
  are stale, due for rotation, etc. That's a separate concern.
- **Per-secret access policies.** All stored secrets are readable
  with the same private key. No "this secret only readable from
  this user / this time of day / this context." Use the operating
  system + filesystem permissions for that.
- **Encryption-in-use** (homomorphic / SGX / etc.). Plaintext
  values exist in memory when consumed. That's the design.
- **Protection against root.** If an attacker has root on the
  host, they can read the private key, ptrace running processes,
  and replace the `claude-secrets` binary with a logging
  wrapper. This tool defends against user-level compromise and
  accidental leakage, not adversarial root.

## File layout

```
~/.claude-secrets/                   (mode 700)
├── key.txt                          (mode 600) — age private key
├── identity.pub                     (mode 644) — recipient public key
├── audit.log                        (mode 600) — append-only log
└── store/                           (mode 700)
    ├── github-pat.age               (mode 600) — armored age ciphertext
    ├── hetzner-pw.age
    └── ...
```

The directory is per-user (`$HOME`), so paul + rdpuser have
independent vaults.

## Why age and not GPG / sops / vault / KMS

| Property                | age | GPG | sops | Vault | KMS |
|-------------------------|-----|-----|------|-------|-----|
| Daemon required         | no  | no  | no   | yes   | no  |
| Cloud dependency        | no  | no  | optional | no | yes |
| Network round-trip      | no  | no  | sometimes | yes | yes |
| Modern crypto           | yes | mixed | yes | yes | yes |
| Simple key management   | yes | no  | no   | no    | yes |
| Single binary           | yes | partial | partial | no | no |
| Sovereign-friendly      | yes | yes | mixed | yes | no |

age is the obvious answer for "encrypt a small file with a long-
lived recipient key, locally, with no daemon." That's the entire
shape of this problem.

## Why a shell wrapper, not Rust

This MVP is shell. The wrapper is ~150 lines, easy to audit, easy
to port to any POSIX system. Future iterations may rewrite in Rust
(via [PlausiDen-Forge](https://github.com/thepictishbeast/PlausiDen-Forge)
build pipeline) for:
- structured config (TOML)
- per-secret metadata (expiry, rotation reminders, tags)
- multiple-recipient support
- subprocess-safe escaping (current shell impl relies on `set -eu` + heredoc discipline)

The shell version is the floor, not the ceiling.

## Audit log format

```
2026-05-17T07:00:33Z get github-pat pid=12345 uid=1000
2026-05-17T07:05:00Z put aws-sts pid=12346 uid=1000
2026-05-17T07:06:00Z rm old-creds pid=12347 uid=1000
```

Fields are space-separated:
1. ISO-8601 UTC timestamp
2. Verb (init, put, get, list, rm)
3. Name (or `-` for init/list)
4. `pid=N` — process that performed the op
5. `uid=N` — effective UID at op time

Not cryptographically signed (would require a separate hash chain
or sigchain). For forensic-grade integrity, ship the audit log
periodically to an external host (out of scope for v0).

## Subprocess-safety in the shell wrapper

The CLI takes only one user-controlled value (the secret value)
via stdin, never argv. The NAME goes through `validate_name()`
which restricts to `[a-zA-Z0-9._-]` and refuses `/`, `..`, etc.
This prevents:
- Directory traversal (`claude-secrets put ../../etc/passwd`)
- Shell injection via name
- Glob abuse

The age binary itself is what consumes the secret value; the shell
wrapper never sees the plaintext in a variable.

## Future work

- **Multi-recipient support**: encrypt-to-list, so a team can
  share secrets without each member maintaining their own copy.
  age supports this natively via multiple `-r` flags.
- **Per-secret metadata**: rotation interval, last-rotated, tags,
  description. Stored next to the .age file as .meta.json.
- **`claude-secrets sync` to a backup target**: encrypted blobs
  are already safe to copy to any storage; would just need a
  Rust(rage)-aware sync.
- **Rust rewrite via Forge**: typed CLI, structured logs, better
  argv hygiene, no shell-injection class.
- **PAM / sudo integration**: require a fresh sudo prompt to
  decrypt high-stakes secrets (caching off).
- **Hardware-key recipients**: age supports YubiKey-backed
  recipients via the age-plugin-yubikey project. Drop-in.
