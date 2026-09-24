# SHARING_PROTOCOL.md — text protocol between user and AI agent

This is the chat-level protocol AI agents (Claude, Codex, Cursor, etc.)
should follow when handling secrets. It's a contract: the user types
one shape, the agent responds in another.

## Verbs

### `user → agent`: paste-secret

The user pastes a secret in some natural-language form:

```
my github PAT is github_pat_11ABCDEFGHIJ
the hetzner password is hunter2-and-some-more-bits
ssh privkey:
-----BEGIN OPENSSH PRIVATE KEY-----
<key material, many lines of base64>
-----END OPENSSH PRIVATE KEY-----
```

Agent MUST:

1. NOT echo the value (full or partial) in its response
2. Pick a short kebab-case name (`github-pat`, `hetzner-pw`, `ssh-deploy`)
3. Execute `claude-secrets put NAME` with the value piped via heredoc
4. Respond with the name only:

```
Stored as `github-pat`. From now on I'll use `${SECRET:github-pat}` in
chat — read the value with `claude-secrets get github-pat` when you
need it. Since the value was visible in this chat, **rotate it at the
source** when you can.
```

### `user → agent`: handle-reference

The user references a stored secret by its handle:

```
use ${SECRET:github-pat} to set up gh auth
deploy with the hetzner-pw secret
```

Agent MUST:

1. Resolve via `claude-secrets get NAME` at the moment of use
2. Pipe to the consumer process; not assign to a shell variable
   that persists
3. NOT echo the resolved value

### `user → agent`: rotate

The user has rotated a secret and wants to update the stored copy:

```
rotated my github PAT; the new one is github_pat_11ZZZ...
```

Agent MUST:

1. Treat as `paste-secret`
2. Re-use the existing handle (overwrite)
3. Respond: `Updated github-pat. The old value is no longer stored.`

### `user → agent`: list / inventory

The user wants to know what's stored:

```
what secrets do I have?
list my stored credentials
```

Agent runs `claude-secrets list` and shows handles + timestamps.
Never values.

### `user → agent`: explicit "show me"

The user explicitly asks for the plaintext (e.g. to read onto paper,
type into another machine):

```
show me the hetzner password so I can type it in
```

Agent MUST:

1. Confirm: "About to print `hetzner-pw` to chat — this re-exposes
   the value to the model provider transcript. Continue?"
2. On confirmation, print the value in **one** message
3. NOT include the value in any subsequent summary, recall, or
   memory entry
4. Suggest rotation if the user might be in a setting where the
   transcript can be observed (shared screen, demo, recording)

### `user → agent`: delete

```
forget the github-pat secret
delete my old AWS creds
```

Agent runs `claude-secrets rm NAME`, confirms removal.

## Names

Recommended convention: `<service>-<role>` in kebab-case.

| Good | Bad |
|------|-----|
| `github-pat` | `pat` (too generic) |
| `hetzner-ssh` | `password` (which password?) |
| `aws-prod-deploy` | `AWSProdDeploy` (case-sensitive on Linux) |
| `gmail-app-pw` | `~/.config/...` (literal path leaks layout) |

Names show up in:
- Audit log (forensic context)
- Chat transcripts (reveal which credentials exist)
- The encrypted file name on disk

If the name itself is sensitive ("I have a credential for $secret_acquirer"),
use a UUID and store the human-readable meaning in a separate secret.

## What NOT to do

- **Don't put the value in a memory entry.** Memory persists across
  sessions and is visible to the model provider in future contexts.
- **Don't include the value in a "summary so far" message.** Even
  partial / redacted values are bad — they leak the prefix / length /
  pattern.
- **Don't write the value to a non-`.age` file** to "save it for later."
  Use `claude-secrets put`.
- **Don't share the user's private key.** Anyone with `key.txt`
  can decrypt every secret.

## When the user is also using other AI agents

`claude-secrets` is single-user single-vault by default. If the user
also has Codex / Cursor / Continue.dev running, those agents should
all follow this same protocol — they read the same `~/.claude-secrets/`
because they run as the same UID.

For team scenarios where multiple users share secrets, see DESIGN.md
§ Future Work (multi-recipient).
