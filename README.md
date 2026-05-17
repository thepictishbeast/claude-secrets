# claude-secrets

Sovereign, local-first secrets manager for AI agent workflows.

When you tell Claude (or any AI agent) "the API key is X" or "the SSH password
is Y", that text lands in:
- the chat transcript that gets uploaded to the model provider
- the `.claude/projects/*/<session>.jsonl` history on disk
- screenshots, copy-paste buffers, terminal scrollback, `~/.bash_history`

`claude-secrets` is the discipline + tooling to stop that. Secrets live
encrypted at rest, referenced by handle (`${SECRET:hetzner-pat}`) in chat
and tool calls, and only decrypted at the exact moment a tool needs the value.

## Why

| Other options | Why this instead |
|---|---|
| AWS/GCP/Azure Secrets Manager | NATO/Western cloud KMS. Sovereign posture says no third-party. |
| HashiCorp Vault | Heavy, daemon-based, license drift. Overkill for solo workflows. |
| `pass` (GPG) | GPG is old and brittle; key management is a separate ordeal. |
| sops | Mozilla-led, deeply integrated with cloud KMS by default. |
| **`age`** | Modern, simple, Rust + Go implementations both production. Single binary. No daemon. No cloud. Authored by Filippo Valsorda (ex-Go security lead). |

## Stack

- **`age`** — file encryption (apt install age) — sovereign-friendly,
  audit-light, no daemon
- **Plain POSIX shell** for the wrapper — no Python/Node/runtime to maintain
- **Local-only storage** at `~/.claude-secrets/`, mode 600/700
- **Append-only audit log** at `~/.claude-secrets/audit.log`

## Install

```sh
# 1. install age (sovereign-friendly file encryption)
sudo apt install age              # Debian/Ubuntu
brew install age                  # macOS
# (or: cargo install rage; or download from https://github.com/FiloSottile/age/releases)

# 2. install this wrapper
git clone https://github.com/thepictishbeast/claude-secrets ~/code/claude-secrets
sudo ln -s ~/code/claude-secrets/bin/claude-secrets /usr/local/bin/claude-secrets

# 3. generate your key pair (one-time)
claude-secrets init
```

The init step prints your public-key recipient. Copy this anywhere
you want to encrypt secrets *to* (e.g. paste into a colleague's
`identity.pub` so they can `claude-secrets put` something only you
can read).

## Use

```sh
# store a secret (reads from stdin so it never lands in shell history)
$ echo -n 'github_pat_11ABCDEF...' | claude-secrets put github-pat
stored: github-pat

# pipe a secret straight from another tool
$ aws sts get-session-token --output text | claude-secrets put aws-sts

# read a secret out (the only place plaintext ever exists)
$ export GH_TOKEN=$(claude-secrets get github-pat)
$ gh repo list

# list stored secrets (names only, no values)
$ claude-secrets list
github-pat                     2026-05-17 06:30:11  233B
aws-sts                        2026-05-17 06:45:00  1024B

# in chat / configs / code, reference by handle
$ claude-secrets ref github-pat
${SECRET:github-pat}

# audit every access
$ claude-secrets audit
2026-05-17T06:30:11Z put github-pat pid=12345 uid=1000
2026-05-17T07:00:33Z get github-pat pid=23456 uid=1000
```

## How AI agents (Claude) use it

See [`CLAUDE.md`](./CLAUDE.md) — every AI agent that touches this user's
work reads CLAUDE.md before handling secrets. The contract:

1. **Never echo a plaintext secret back to the user.** When the user
   pastes one, immediately pipe it into `claude-secrets put NAME`
   and respond only with "stored as NAME".
2. **Always use `claude-secrets get` at the point of use**, not in
   intermediate steps. The plaintext lives in process memory only.
3. **Use `${SECRET:name}` references in chat, configs, and tool args.**
   These are safe to keep in transcripts.

See [`docs/SHARING_PROTOCOL.md`](./docs/SHARING_PROTOCOL.md) for the
full text-protocol AI agents follow.

## Storage layout

| Path | Mode | Contents |
|------|------|----------|
| `~/.claude-secrets/key.txt` | 600 | Your age private key. **Back this up offline.** |
| `~/.claude-secrets/identity.pub` | 644 | Your age public-key recipient (safe to share) |
| `~/.claude-secrets/store/<name>.age` | 600 | Each secret encrypted to your recipient |
| `~/.claude-secrets/audit.log` | 600 | Append-only access log (timestamp / op / name / pid / uid) |

The repo itself contains **no secrets** — only tooling and docs.

## Backup

The private key at `~/.claude-secrets/key.txt` is the only thing
standing between you and a lost-secret-vault. Two recommended patterns:

1. **Print the key.** Run `cat ~/.claude-secrets/key.txt` and physically
   print the output. Store the paper in your safe / safety deposit box.
   age private keys are short (~70 chars) and easy to type back in.
2. **Encrypt-to-passphrase.** Run `age -p key.txt > key.txt.passphrase.age`
   and store the result somewhere safe (Hetzner Storage Box, paper QR code).
   `age -d` it later with the passphrase.

**Do not** put the unencrypted private key in any git repo or cloud sync.

## Threat model

Short version: see [`docs/THREAT_MODEL.md`](./docs/THREAT_MODEL.md).

Defended against:
- ✓ Secrets in chat transcripts going to a model provider
- ✓ Secrets in `~/.bash_history`, shell scrollback, screenshots
- ✓ Casual `cat` / `cp` of a secrets directory
- ✓ Untrusted processes reading files (mode 600)

Not defended against:
- ✗ Root-level compromise of the host (root can read everything,
  ptrace running processes, etc.)
- ✗ Memory disclosure of a process that has the decrypted value
- ✗ Coerced disclosure of your private key
- ✗ The model provider seeing references to secret *names*
  (`${SECRET:hetzner-pat}` reveals you have a Hetzner PAT)

For very high-stakes secrets, an HSM + air-gap is the right answer.
This tool is for the messy middle: tens of credentials, used by
human + AI workflows daily, that should not be plaintext.

## Design

See [`docs/DESIGN.md`](./docs/DESIGN.md).

## License

MIT.
