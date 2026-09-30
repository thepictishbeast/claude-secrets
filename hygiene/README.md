# claude-secrets-hygiene

Finds credentials on one machine that are **reused** (the same secret in
more than one place) or **unrotated** (unchanged past a limit, 180 days by
default), without storing or printing any of them.

```sh
sudo claude-secrets hygiene init     # once: create the pepper
sudo claude-secrets hygiene check    # audit, read-only, prints the report
sudo claude-secrets hygiene scan     # audit + remember history + write the report
sudo claude-secrets hygiene scan --notify you@example.com   # mail when findings change
```

Exit status: `0` nothing found, `1` findings, `2` could not run.

## What "zero knowledge" means here, exactly

It reads each secret, transiently, in memory. There is no way to notice
that two secrets are equal without looking at them. What it guarantees is
that nothing it **keeps, prints or mails** can reveal one:

- Each secret becomes `HMAC-SHA256(pepper, secret)` as soon as it is read, and
  the plaintext buffer is zeroized when it is dropped.
- The pepper is a separate, root-only file. Without it, the fingerprints in the
  state file cannot be tested against guesses, so a leaked state file cannot be
  dictionary-attacked. If the pepper is missing or readable by anyone else, the
  tool refuses to run. It never falls back to unkeyed hashing.
- Reports carry locations (a path plus a key or section name) and short labels
  derived from fingerprints. They never carry a credential or a fingerprint.
  A test checks this against the real outputs, and a mutation that leaks is
  caught by it.
- For `/etc/shadow` only the date field is used. Password hashes are salted per
  account, are never compared, and this tool does not crack them.

## How age is known

Nobody records rotations, so the tool observes them. A location's fingerprint
changing between scans **is** a rotation, and from then on its age is exact.
Before one has been seen, the age is a *lower bound*: the longer of how long it
has been watched unchanged and how long its file has gone unmodified. The report
says which ("rotated N days ago" vs "unchanged for at least N days"). Moving or
copying a file resets its mtime, so after a move the bound starts again from
that day.

## Config — `/etc/claude-secrets/hygiene.conf` (keep it 0600: it maps every credential)

```text
env    /srv/secrets/*.env          KEY=value, export KEY=value, or KEY: value
file   /srv/secrets/*.token        the whole file is one secret
ini    /etc/asterisk/pjsip.conf     password= / secret= per [section]
wg     /etc/wireguard/*.conf        PrivateKey, and PresharedKey per peer
shadow /etc/shadow                  account password ages
stale-days 180
same   wg:/etc/wireguard/wg0.conf#PrivateKey file:/etc/wireguard/server.key
```

A `*` is allowed in the last path component only. A bad line is an error, not
something skipped.

**`same`** declares places that hold one credential on purpose: a key file and
the config that embeds it, or both ends of one API key. A reuse group entirely
inside a declaration is counted, not reported. If the declared copies stop
matching, because one was rotated and the others weren't, that is reported as
**DRIFT**. Reuse that reaches even one place beyond the declaration is still
reported. The location strings are exactly as the report prints them.

## What it reports

| Line | Meaning |
| --- | --- |
| `REUSED` | one credential found in several places |
| `STALE` | not rotated within the limit (exact or lower bound, as stated) |
| `DRIFT` | declared copies no longer match: a half-finished rotation |
| `MISSING` | a declared location no longer holds a credential |
| `BLIND` | a source matched nothing, or several secrets share one name, so the report cannot vouch for it |

Every report ends with a **coverage** table: for each source, how many files and
secrets it reached, and which matched files yielded nothing. A clean report is
only as good as its coverage, and the table is how you check it.

## Finding known credentials in other files

```
claude-secrets-hygiene find-in PATH...     # count occurrences; exit 1 if any
claude-secrets-hygiene redact-in PATH...   # replace them in place
claude-secrets-hygiene labels              # label, length and character classes per location
```

`find-in` and `redact-in` search for every credential the configured sources
hold. Each credential is matched in the forms it takes when it leaks: as
written, JSON-escaped (a transcript line), percent-encoded (a URL), inside
base64 at any byte alignment (an `Authorization: Basic` header), and, for a
multi-line key, line by line. Directories are read recursively, `.gz` files
through gzip, and `-` means stdin. `redact-in` writes `[REDACTED:cred-xxxxxx]`,
the report label, so two redactions of one credential are recognisable without
showing where it lives.

Two kinds of credential are counted rather than searched, and the coverage line
says so: those shorter than 8 bytes, and **word-like** ones (under 12 bytes and
all one character class). Searching for a word-like password flags ordinary
text, and replacing every occurrence would spell it out by context. Treat a
word-like credential as a finding: rotate it.

`labels` shows no values. It is how you map a label from `find-in` back to its
location, and judge a false alarm by the secret's shape.

## Files

| Path | Mode | Holds |
| --- | --- | --- |
| `/etc/claude-secrets/hygiene.pepper` | root 0400 | the HMAC key; keep it off backups that leave the machine |
| `/etc/claude-secrets/hygiene.conf` | root 0600 | where credentials live |
| `/var/lib/claude-secrets/hygiene.state` | root 0600 | location, fingerprint, since, exact |
| `/var/lib/claude-secrets/hygiene-report.txt` | root 0600 | the last report |

Replacing the pepper resets every age, so `init` refuses to overwrite one.
