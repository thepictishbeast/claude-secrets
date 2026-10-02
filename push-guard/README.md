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

The intended way past is a person running `git push --no-verify` themselves.
Claude sessions are denied that flag, and the other routes the Claude hook
can recognise are listed under Parts. Routes it cannot recognise are under
Known limits.

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
- **The Claude hook reads command text, so it is a tripwire, not a wall.**
  It denies `--no-verify` (abbreviated too), absolute paths and quoted forms
  of git, `-c`/`--config-env` and include overrides, `GIT_CONFIG_NOSYSTEM`,
  `GIT_CONFIG_SYSTEM` and `GIT_CONFIG_GLOBAL`, section removal, `git config
  --edit`, shell writes to git config files (named or by wildcard), option
  names built from `$…` or backticks, `git push` arguments taken from a
  variable, and `gh` visibility or settings values built at run time. It
  does not see:
  - a command string assembled from pieces and run with `eval` or
    `bash -c`;
  - a command written to a script file and then run;
  - a root session editing `/etc/gitconfig` or the files under
    `/usr/local/lib/git-guard/` with the Write or Edit tools;
  - `HOME=` or `XDG_CONFIG_HOME=` pointing git at a prepared global config;
  - shell tools other than Bash, such as an MCP server's command runner,
    because the hook's matcher is `Bash`.

  Stopping those would take file permissions, not pattern matching. The git
  pre-push hook still runs in every one of these cases unless the system
  config was also bypassed.
