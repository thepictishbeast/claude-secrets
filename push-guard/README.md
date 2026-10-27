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

**A push to a PUBLIC repository is refused unless the destination is listed in
`/etc/claude-secrets/public-push-allow`.** The scans above answer whether the
content is a secret. They cannot answer whether it should be published at all,
and a wrong answer there is permanent: a public push ends European and Chinese
patent rights in whatever it discloses the same day, and starts a one-year US
clock. So it isn't guessed — an unlisted public destination is refused.

A public push **is also refused** if an added line or a commit message matches
`/etc/claude-secrets/public-denylist`. That list covers personal data,
internal addresses and where credentials live.

**Any push, public or private, is refused if it adds or changes a licence file
carrying an express patent grant** — Apache-2.0 §3, GPL/AGPL-3.0 §11, MPL-2.0
§2.1, the FSL Patents section. That grant reaches every recipient and can't be
withdrawn from anyone who already has a copy; making the repository private
later doesn't undo it.

Visibility comes from the GitHub API. If it can't be confirmed, the push is
refused. Output names labels, rules, commits and files, never a matched value.

## Parts

| File | Installed as | Role |
|---|---|---|
| `git-push-guard` | `/usr/local/bin/git-push-guard` | The checks; called by the pre-push hook |
| `hook-dispatch` | `/usr/local/lib/git-guard/hooks/*` | System-wide `core.hooksPath`. Runs the guard for pre-push, then hands every hook to the repository's own `.git/hooks/<name>`, so repo hooks keep working |
| `contrib/push-scan.socket`, `push-scan@.service` | systemd | Root scanner on `/run/push-scan.sock`, group `paul`, started per push, idle at zero |
| `claude-hook` | `/usr/local/bin/push-guard-claude-hook` | Claude Code PreToolUse hook (`Bash\|Write\|Edit\|MultiEdit`). Denies routes around the guard: `--no-verify`, touching `core.hooksPath`, making or creating anything public, writes through the GitHub contents API, writes to the guard's own configuration, and publishing by a route no git hook sees — a release on an unlisted repository, `cargo`/`npm` publish, `twine upload` |
| `install.sh` | — | Installs all of the above. Idempotent |
| `tests/run.sh` | — | Every refusal case plants the thing it must catch. Every allow case proves ordinary work passes |

## Private configuration (not in this repo)

- `/etc/claude-secrets/public-denylist`, root:paul 0640. Format:
  `label<TAB>extended-regex`. It applies to public pushes only. Add a line
  and it applies from the next push.
- `/etc/claude-secrets/push-allow`, root:paul 0640. Format:
  `owner/repo<TAB>label`. It accepts one denylist label for one repository.
  Use it sparingly, and never for credentials.
- `/etc/claude-secrets/public-push-allow`, root:paul 0640. One `owner/repo`
  per line, case-insensitive, `#` comments. A repository not listed here
  cannot be pushed to while it is public, and cannot receive a release.
  Removing a line locks that repository from the next push. An unreadable or
  missing file refuses every public push.

## Getting past a refusal

Fix the commits. If they're unpushed, rewrite them: use `--amend`, or
`git filter-branch --tree-filter` over the unpushed range. A fix-up commit on
top would still publish the originals.

The intended way past is a person running `git push --no-verify` themselves.
Claude sessions are denied that flag, and the other routes the Claude hook
can recognise are listed under Parts. Routes it cannot recognise are under
Known limits.

## Known limits

- **Hooks only see git.** The git hook checks pushes and nothing else. The
  Claude hook covers the other publishing routes it can recognise — the
  GitHub contents API, visibility changes, releases, `cargo`/`npm` publish,
  `twine upload` — but only in a `Bash` tool call, and it checks the
  *destination*, never the content being uploaded. A release asset itself is
  not scanned.
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
    `/usr/local/lib/git-guard/` with the Write or Edit tools. Writes to
    `/etc/claude-secrets` **are** denied for Write and Edit as well as Bash,
    but a session running as root can still reach every one of these files
    another way. The allow list is a record of a decision, not a permission
    boundary;
  - `HOME=` or `XDG_CONFIG_HOME=` pointing git at a prepared global config;
  - shell tools other than Bash, such as an MCP server's command runner,
    because the hook's matcher is `Bash`, `Write`, `Edit` and `MultiEdit`
    and nothing else.

  A release must name its repository with `-R`. The hook sees the session's
  working directory as it was when the hook ran, so `cd elsewhere && gh
  release create` would be checked against one repository and published to
  another; requiring `-R` removes the question.

  Stopping those would take file permissions, not pattern matching. The git
  pre-push hook still runs in every one of these cases unless the system
  config was also bypassed.
