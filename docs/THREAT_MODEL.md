# THREAT_MODEL.md — what claude-secrets defends against

## Assets

1. **Long-lived credentials**: API tokens, SSH passwords, recovery keys,
   passphrases, root passwords.
2. **The user's private age key** at `~/.claude-secrets/key.txt`. If
   this is compromised, every secret encrypted to its recipient is
   compromised retrospectively.
3. **The chat transcript** — a stream of text shared between user
   and AI agent, persisted to disk and uploaded to a model provider.

## Adversaries considered

### A1 — Model provider

Sees every line of every chat transcript. Forever. Even after the
user deletes the conversation locally, the provider may retain logs
per their privacy policy.

**Mitigation**: secrets never appear plaintext in chat. Handles
(`${SECRET:hetzner-pat}`) are safe.

**Residual**: the *name* of the secret reveals what kind of credential
the user has. `${SECRET:hetzner-pat}` reveals "this user has a Hetzner
PAT". Use generic names if even this is sensitive.

### A2 — Disk snapshot / backup leak

The user's disk gets cloned: a Time Machine backup, a ZFS snapshot
sent to an off-host target, a stolen laptop.

**Mitigation**: secrets at rest are age-encrypted (`X25519 + ChaCha20-Poly1305`).
An attacker with the disk image but not the private key cannot
decrypt them.

**Residual**: if the disk image *includes* `~/.claude-secrets/key.txt`,
the attacker can decrypt everything. Keep the private key out of
backups that don't have additional protection, or encrypt the backup
itself with a different recipient.

### A3 — Casual `cat` / `cp` / accidental commit

Another process or user runs `cat ~/.claude-secrets/store/*` or
copies the directory or commits the secrets to a repo by accident.

**Mitigation**: `.age` files are useless without the private key.
The wrapper sets mode 600 on every secret + the audit log + the
key, and mode 700 on directories.

**Residual**: a `.gitignore` is the user's responsibility. The repo
template includes `.claude-secrets/` in its gitignore.

### A4 — Shell history / scrollback / screenshots

The user types `echo my-secret | claude-secrets put NAME` and the
secret lands in `~/.bash_history` and shell scrollback.

**Mitigation**: the CLI reads only from stdin, never argv. Recommended
patterns:
- Heredoc: `claude-secrets put NAME <<'EOF'` (heredoc body bypasses history depending on shell config)
- Pipe from another tool: `aws sts ... | claude-secrets put NAME`
- Pipe from a file: `claude-secrets put NAME < secret.txt && shred secret.txt`

**Residual**: shell config-dependent. Recommend `HISTCONTROL=ignorespace`
and prefix the command with a space.

### A5 — Process listing / ps / proc

An attacker on the box runs `ps auxe` and sees command-line args.

**Mitigation**: secrets are never in argv. NAME goes in argv (and is
safe to expose). Plaintext only ever transits via stdin/stdout/file-
descriptor.

**Residual**: `/proc/<pid>/environ` for processes that have
`export SECRET=$(claude-secrets get NAME)`. CLAUDE.md tells agents
to avoid this pattern.

### A6 — Non-root local process

A malicious user-mode process scans `$HOME` for valuable files.

**Mitigation**: `~/.claude-secrets/` is mode 700, contents mode 600.
A process running as a different non-root user cannot read.

**Residual**: a process running as **the same** user can read
everything. This is the fundamental limit of file-permission-based
isolation.

### A7 — Coerced disclosure

The user is forced (legal process, physical coercion) to reveal
their private key.

**Not mitigated.** All secrets are decryptable with the private key.
Plausible-deniability would require steganography + duress keys; not
in scope.

## Adversaries NOT considered

### N1 — Root on the host

If an attacker has root, they can:
- Read `~/<user>/.claude-secrets/key.txt` directly
- ptrace any process that has decrypted a value
- Replace `claude-secrets` with a wrapper that exfiltrates
- Read `/proc/<pid>/mem` for in-flight values

The wrapper doesn't try to protect against this. If you're worried
about root compromise, the answer is an HSM or hardware-backed
key (TPM, YubiKey, Secure Enclave), not a shell wrapper around
age.

### N2 — Side-channel attacks on age

age uses ChaCha20-Poly1305. Known side-channel attacks on
ChaCha20-Poly1305 are theoretical; not practical for this threat
model.

### N3 — Quantum

X25519 is broken by sufficiently powerful quantum computers. If
quantum becomes practical: rotate to a post-quantum recipient
when age ships one.

### N4 — Backdoor in age itself

age is a maintained open-source project. The wrapper trusts age
to encrypt/decrypt correctly. If age has a hidden backdoor, this
wrapper inherits it.

**Mitigation**: pin to a specific age binary version + verify
checksum on install. Future work.

## Comparison to keeping secrets in chat

The implicit "do nothing" alternative is "the user just pastes
secrets in chat as needed."

| Risk | Status quo | With claude-secrets |
|------|-----------|---------------------|
| Model provider sees plaintext | YES (every paste) | NO (handles only) |
| Local disk has plaintext history | YES (`.jsonl` files) | NO (encrypted-at-rest) |
| Screenshot / scrollback / copy-paste exposure | YES | minimized |
| Audit trail of which secrets used when | NO | YES (audit.log) |
| Disk-snapshot backup leaks them | YES | NO (encrypted) |
| Effort to rotate after exposure | high (no inventory) | medium (`claude-secrets list`) |

The delta is "you can now share credentials with Claude / Codex /
Cursor / etc. without that credential being permanently part of
some company's training corpus."
