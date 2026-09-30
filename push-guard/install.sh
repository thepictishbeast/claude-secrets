#!/usr/bin/env bash
# Install the push guard system-wide. Run as root. Idempotent.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
hooks=/usr/local/lib/git-guard/hooks

install -m 755 "$here/git-push-guard" /usr/local/bin/git-push-guard
install -m 755 "$here/claude-hook" /usr/local/bin/push-guard-claude-hook
install -d -m 755 "$hooks"
install -m 755 "$here/hook-dispatch" "$hooks/hook-dispatch"
# Every client-side hook a repository might have, so a system-wide hooksPath
# never silently switches a repo's own hook off. (reference-transaction and
# fsmonitor-watchman are left out: no repo here uses them, and the first runs
# on every ref update.)
for h in applypatch-msg pre-applypatch post-applypatch pre-commit pre-merge-commit \
         prepare-commit-msg commit-msg post-commit pre-rebase post-checkout post-merge \
         pre-push post-rewrite pre-auto-gc push-to-checkout sendemail-validate; do
  ln -sfn hook-dispatch "$hooks/$h"
done

install -m 644 "$here/contrib/push-scan.socket" /etc/systemd/system/push-scan.socket
install -m 644 "$here/contrib/push-scan@.service" /etc/systemd/system/push-scan@.service
systemctl daemon-reload
systemctl enable --now push-scan.socket

# The denylist and allowlist are Paul's to edit; paul-group read so paul's
# pushes can be checked too. Created empty if missing, never overwritten.
for f in /etc/claude-secrets/public-denylist /etc/claude-secrets/push-allow; do
  [ -e "$f" ] || install -m 640 /dev/null "$f"
  chown root:paul "$f"; chmod 640 "$f"
done

git config --system core.hooksPath "$hooks"
# git creates /etc/gitconfig under root's umask (027 here): every other user's
# git then dies with "unable to access /etc/gitconfig". It must be world-readable.
chmod 644 /etc/gitconfig
echo "push guard installed: core.hooksPath=$(git config --system --get core.hooksPath)"
