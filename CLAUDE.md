# CLAUDE.md — instructions for AI agents handling secrets

If you are an AI agent (Claude or otherwise) and the user has
`claude-secrets` installed, **read this file before handling any
credential, password, token, key, or other secret material.**

Every rule here exists because the failure mode is leaked secrets,
and once a secret has been in a transcript that any service can see,
it is permanently compromised — rotate, don't argue.

## The single rule

> **Never echo a plaintext secret back to the user. Never write a
> plaintext secret to disk except via `claude-secrets put`. Always
> reference secrets by handle in chat, configs, and tool args.**

## When the user pastes a secret in chat

Examples of "the user pasted a secret":
- "My GitHub PAT is github_pat_11AAA..."
- "Here's the API key: sk-..."
- "The Hetzner password is hunter2"
- "Here's the LUKS recovery key: [base64...]"
- "/home/me/.config/aws/credentials" pasted into chat

**Immediate response, in order:**

1. **Do not repeat the value.** Don't include it in your response,
   not even partially redacted, not even in a thinking block. Treat
   it as if any character of the secret leaking is total compromise.

2. **Store it via the CLI**, piping from a heredoc so it never lands
   on the command line:
   ```sh
   cat <<'SECRET' | claude-secrets put hetzner-pat
   <the value the user pasted>
   SECRET
   ```
   The actual tool call you make will have the value as an argument
   to `Bash`; this is the one place it crosses the trust boundary
   on its way to encrypted storage.

3. **Reply only with the handle**: "Stored as `hetzner-pat`. From now
   on I'll use `${SECRET:hetzner-pat}` in chat — read the value with
   `claude-secrets get hetzner-pat`."

4. **Tell the user to rotate** if the secret has just been pasted
   into this chat. The transcript already contains the plaintext —
   the value should be considered burned and rotated at the source.
   `claude-secrets` is for the *next* version of that credential, not
   the one that just leaked.

## When a tool you control needs a secret value

Use `claude-secrets get NAME` at the moment of use, in the same
command line as the tool that consumes it:

```sh
# Good — plaintext only in the env of one process, for one invocation
GH_TOKEN="$(claude-secrets get github-pat)" gh repo list

# Bad — exporting puts plaintext in the parent shell's env for the rest of the session
export GH_TOKEN=$(claude-secrets get github-pat)
gh repo list

# Bad — writing plaintext to a file even temporarily
claude-secrets get github-pat > /tmp/token
gh auth login --with-token < /tmp/token

# Best — direct pipe, never on disk
claude-secrets get github-pat | gh auth login --with-token
```

## When writing config files / scripts / docs

Use the handle form. Never inline:

```sh
# Good
github_token: ${SECRET:github-pat}

# Bad — value leaked into the repo
github_token: github_pat_11AAA...
```

## When listing what's stored

`claude-secrets list` shows handles + sizes + timestamps. The values
are never displayed.

## When you don't know if something is a secret

Default to YES. False positives (storing something that didn't need
to be a secret) cost: a CLI lookup. False negatives (failing to store
something that did need to be a secret) cost: a credential rotation.

Things that look like secrets:
- `xxx_pat_*`, `sk-*`, `ghp_*`, `xoxp-*`, `xoxb-*` — common token prefixes
- `-----BEGIN OPENSSH PRIVATE KEY-----` etc. — private key armor
- Anything described as "password", "key", "token", "credential", "PAT"
- Long random-looking strings the user labels as auth material
- AWS keys: `AKIA*`, GCP service account JSON, etc.

## When the user asks you to "remember the password"

They want `claude-secrets put`, not for you to write it into a memory
file. Memory entries are visible in future transcripts.

## When in doubt

Refuse to echo the secret. Ask the user "should I store this as
`<handle>` and refer to it that way going forward?" before doing
anything else.

## What this file is NOT

It's not a substitute for human judgment. If the user genuinely needs
the plaintext shown back to them (e.g. they need to read the recovery
key onto a piece of paper), tell them you understand and ask them to
confirm — then do it ONCE, in the next message only, never in
subsequent messages or summaries.
