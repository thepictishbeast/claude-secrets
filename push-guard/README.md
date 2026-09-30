# push-guard

Nothing leaves this machine through `git push` until the destination's
visibility is confirmed and the outgoing commits are checked.

**Every push, private or public, is refused if the outgoing commits contain:**
- a known credential, in any leaked form. This is checked by
  `claude-secrets-hygiene find-in`, which runs as root behind a socket so
  that paul's pushes are covered too.
- anything gitleaks recognises.
- a newly added credential-shaped file: `.env`, private keys, keystores,
  databases.

**A push to a PUBLIC repository is also refused** if an added line or a commit
message matches `/etc/claude-secrets/public-denylist`. That list covers
personal data, internal addresses and where credentials live.

Visibility comes from the GitHub API. If it can't be confirmed, the push is
refused. Output names labels, rules, commits and files, never a matched value.

## Parts

| File | Installed as | Role |
|---|---|---|
| `git-push-guard` | `/usr/local/bin/git-push-guard` | The checks; called by the pre-push hook |
| `hook-dispatch` | `/usr/local/lib/git-guard/hooks/*` | System-wide `core.hooksPath`. Runs the guard for pre-push, then hands every hook to the repository's own `.git/hooks/<name>`, so repo hooks keep working |
| `contrib/push-scan.socket`, `push-scan@.service` | systemd | Root scanner on `/run/push-scan.sock`, group `paul`, started per push, idle at zero |
| `claude-hook` | `/usr/local/bin/push-guard-claude-hook` | Claude Code PreToolUse hook (Bash). Denies routes around the guard: `--no-verify`, touching `core.hooksPath`, making or creating anything public, and writes through the GitHub contents API |
| `install.sh` | — | Installs all of the above. Idempotent |
| `tests/run.sh` | — | Every refusal case plants the thing it must catch. Every allow case proves ordinary work passes |

## Private configuration (not in this repo)

- `/etc/claude-secrets/public-denylist`, root:paul 0640. Format:
  `label<TAB>extended-regex`. It applies to public pushes only. Add a line
  and it applies from the next push.
- `/etc/claude-secrets/push-allow`, root:paul 0640. Format:
  `owner/repo<TAB>label`. It accepts one denylist label for one repository.
  Use it sparingly, and never for credentials.

## Getting past a refusal

Fix the commits. If they're unpushed, rewrite them: use `--amend`, or
`git filter-branch --tree-filter` over the unpushed range. A fix-up commit on
top would still publish the originals.

The only bypass is a person running `git push --no-verify` themselves. Claude
sessions are denied that flag.

## Known limits

- **Hooks only see git.** Uploads by other tools aren't checked: release
  assets, package registries. The Claude hook covers the GitHub contents API
  and visibility changes.
- **New Claude hooks load when a session starts.** Sessions started before the
  install only get the git-level guard.
- **A repository that sets its own `core.hooksPath` overrides the system
  one.** None did on 2026-09-30.
- **A credential that is neither known nor shaped like one can't be caught.**
  Keep the credential sources in `hygiene.conf` complete.
- **The Claude hook reads command text, so it is a tripwire, not a wall.** A
  command written to a script file and then run isn't seen. Neither is a root
  session editing `/etc/gitconfig` or the files under
  `/usr/local/lib/git-guard/` directly, nor `git config --edit` with an editor
  of its choosing. Stopping those would take file permissions, not pattern
  matching.
