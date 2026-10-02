#!/usr/bin/env bash
# Tests for the push guard. Every refusal case is a case that can fail: each
# plants the exact thing the guard must catch, and each allow case proves the
# guard does not block ordinary work. Run as root (it starts a lab scanner).
#
#   bash push-guard/tests/run.sh
set -uo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
T=$(mktemp -d /tank/scratch/push-guard-test.XXXXXX)
trap 'kill "${lab_pid:-0}" 2>/dev/null; rm -rf "$T"' EXIT
pass=0; fail=0
ok() { pass=$((pass + 1)); printf 'ok    %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL  %s\n' "$1"; }

# Lab scanner: a dictionary holding one invented credential, served on a
# socket the same way push-scan@.service serves the real one.
mkdir -p "$T/lab"
printf 'Zq7-lab-only-invented-credential-1142\n' > "$T/lab/known.token"
printf 'file %s/lab/known.token\n' "$T" > "$T/lab/hyg.conf"
claude-secrets-hygiene init --pepper "$T/lab/pepper" >/dev/null
python3 - "$T/lab/scan.sock" "$T/lab/hyg.conf" "$T/lab/pepper" <<'PY' &
import os, socket, subprocess, sys
path, cfg, pep = sys.argv[1:4]
s = socket.socket(socket.AF_UNIX); s.bind(path); os.chmod(path, 0o666); s.listen(8)
while True:
    c, _ = s.accept()
    data = b"".join(iter(lambda: c.recv(65536), b""))
    r = subprocess.run(["claude-secrets-hygiene", "find-in", "--config", cfg, "--pepper", pep, "-"],
                       input=data, capture_output=True)
    c.sendall(r.stdout + r.stderr); c.close()
PY
lab_pid=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do [ -S "$T/lab/scan.sock" ] && break; sleep 0.2; done

# A lab denylist with fictional entries: the real list is private, and these
# tests are published, so they must not contain what the real list protects.
printf 'lab-phone\t212[^0-9]{0,3}555[^0-9]{0,3}0199\nlab-name\t\\b[Zz]ebulon\\b\nlab-subnet\t\\b10\\.77\\.[0-9]{1,3}\\.[0-9]{1,3}\\b\n' > "$T/lab/denylist"

# A work repo whose hooks are the dispatcher, as the system-wide install
# would make them, but set locally so this test does not depend on it.
mkdir -p "$T/hooks"; cp "$here/hook-dispatch" "$T/hooks/hook-dispatch"
for h in pre-push pre-commit; do ln -sfn hook-dispatch "$T/hooks/$h"; done
new_repo() { # name visibility(private|public)
  git init -q --bare "$T/$1-remote.git"
  git init -q -b main "$T/$1"
  git -C "$T/$1" config core.hooksPath "$T/hooks"
  git -C "$T/$1" config user.name test; git -C "$T/$1" config user.email test@example.com
  git -C "$T/$1" config push-guard.socket "$T/lab/scan.sock"
  git -C "$T/$1" config push-guard.denylist "$T/lab/denylist"
  [ "$2" = public ] && git -C "$T/$1" config push-guard.visibility public
  git -C "$T/$1" remote add origin "$T/$1-remote.git"
  echo base > "$T/$1/README"; git -C "$T/$1" add README; git -C "$T/$1" commit -qm base
}
commit() { printf '%s\n' "$3" > "$T/$1/$2"; git -C "$T/$1" add "$2"; git -C "$T/$1" commit -qm "${4:-change}"; }
push() { git -C "$T/$1" push -q origin main 2>"$T/$1.err"; }
expect_refused() { # name label-substring description
  if push "$1"; then bad "$3 (was allowed)"; elif /usr/bin/grep -q "$2" "$T/$1.err"; then ok "$3"; else bad "$3 (refused, but without '$2')"; cat "$T/$1.err"; fi
}
# An allowed push proves nothing unless the guard actually ran: git silently
# skips a hook it cannot execute.
expect_allowed() {
  if ! push "$1"; then bad "$2 (was refused)"; cat "$T/$1.err"
  elif /usr/bin/grep -q "push-guard: ok" "$T/$1.err"; then ok "$2"
  else bad "$2 (allowed, but the guard never ran)"; fi
}

new_repo clean private; commit clean a.txt "ordinary change"; expect_allowed clean "private push of ordinary work is allowed"
new_repo pubclean public; commit pubclean a.txt "call 212-555-0142"; expect_allowed pubclean "public push of data not on the denylist is allowed"
new_repo phone public; commit phone a.txt "call me at (212) 555-0199"; expect_refused phone lab-phone "public: a denylisted phone number in an added line is refused"
new_repo name public; commit name a.txt "fine" "reply to Zebulon"; expect_refused name lab-name "public: a denylisted name in a commit message is refused"
new_repo vpn public; commit vpn wg.conf "AllowedIPs = 10.77.0.4/32"; expect_refused vpn lab-subnet "public: a denylisted subnet is refused"
new_repo privphone private; commit privphone a.txt "call me at 212-555-0199"; expect_allowed privphone "private: the denylist does not apply"
# Token-shaped, assembled at run time so this file itself is not flagged.
tok="ghp_$(printf '%s' A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8)"
new_repo leak private; commit leak cfg.txt "token = $tok"; expect_refused leak gitleaks "any: a token gitleaks recognises is refused, even private"
new_repo known private; commit known notes.txt "the key is Zq7-lab-only-invented-credential-1142 ok"; expect_refused known "known credential" "any: a known credential by value is refused, even private"
new_repo envf private; commit envf .env "X=1"; expect_refused envf "credential-shaped file added: .env" "any: an added .env file is refused"
new_repo nosock private; git -C "$T/nosock" config push-guard.socket "$T/lab/missing.sock"; commit nosock a.txt "fine"
expect_refused nosock "did not run" "fail closed: an unreachable scanner refuses the push"
# git itself stops before the hook for a repo that does not exist, so the
# guard is called directly, the way git calls it, to test this path.
new_repo gh private; commit gh a.txt "fine"
if printf 'refs/heads/main %s refs/heads/main 0000000000000000000000000000000000000000\n' "$(git -C "$T/gh" rev-parse HEAD)" |
   (cd "$T/gh" && /usr/local/bin/git-push-guard origin https://github.com/thepictishbeast/no-such-repo-push-guard-test.git) 2>"$T/gh.err"; then
  bad "fail closed: unknown GitHub visibility (was allowed)"
elif /usr/bin/grep -q "could not confirm" "$T/gh.err"; then ok "fail closed: unknown GitHub visibility refuses the push"
else bad "fail closed: unknown GitHub visibility (refused without the reason)"; cat "$T/gh.err"; fi
new_repo real private; git -C "$T/real" remote set-url origin https://github.com/thepictishbeast/claude-secrets.git; commit real a.txt "call 212-555-0142"
if printf 'refs/heads/main %s refs/heads/main 0000000000000000000000000000000000000000\n' "$(git -C "$T/real" rev-parse HEAD)" |
   (cd "$T/real" && /usr/local/bin/git-push-guard origin https://github.com/thepictishbeast/claude-secrets.git) 2>"$T/real.err" &&
   /usr/bin/grep -q "(public)" "$T/real.err"; then ok "a real public GitHub repo is detected as public and clean content passes"
else bad "real public GitHub repo check"; cat "$T/real.err"; fi
new_repo del private; push del; git -C "$T/del" push -q origin :main 2>/dev/null && ok "a branch deletion is allowed" || bad "a branch deletion was refused"

# A root session runs git as paul, and paul inherits root's TMPDIR, which paul
# cannot write. The guard must still check everything (this once made the
# denylist read an empty file and pass).
P=$(mktemp -d /tank/scratch/push-guard-paul.XXXXXX); chown paul "$P"
cp "$T/lab/denylist" "$P/denylist"; chown paul "$P/denylist"
as_paul_push() { # name visibility content
  runuser -u paul -- env TMPDIR=/root/.push-guard-no-access bash -c '
    set -e; cd "$1"; git init -q --bare "$2-remote.git"; git init -q -b main "$2"; cd "$2"
    git config core.hooksPath "$3"; git config user.name t; git config user.email t@example.com
    git config push-guard.denylist "$1/denylist"; git config push-guard.visibility "$4"
    git remote add origin "../$2-remote.git"; echo base > README; git add README; git commit -qm base
    printf "%s\n" "$5" > a.txt; git add a.txt; git commit -qm change
    git push -q origin main' _ "$P" "$1" "$T/hooks" "$2" "$3" 2>"$P/$1.err"
}
# Root's umask (027) left the copied hook unexecutable for paul, and git then
# skipped it silently: open the hooks up the way install.sh installs them.
chmod o+rx "$T"; chmod -R o+rX "$T/hooks"
if as_paul_push pdeny public "call me at (212) 555-0199"; then bad "as paul with an unwritable TMPDIR: a denylisted line was allowed"
elif /usr/bin/grep -q lab-phone "$P/pdeny.err"; then ok "as paul with an unwritable TMPDIR: a denylisted line is still refused"
else bad "as paul with an unwritable TMPDIR: refused without the label"; cat "$P/pdeny.err"; fi
if ! as_paul_push pclean public "call 212-555-0142"; then bad "as paul with an unwritable TMPDIR: a clean push was refused"; cat "$P/pclean.err"
elif /usr/bin/grep -q "push-guard: ok" "$P/pclean.err"; then ok "as paul with an unwritable TMPDIR: a clean public push is allowed"
else bad "as paul: a clean push was allowed but the guard never ran"; fi

# The installed hooks must be executable by every user, or git skips them.
for f in /usr/local/lib/git-guard/hooks/pre-push /usr/local/bin/git-push-guard; do
  if runuser -u paul -- test -x "$f"; then ok "installed $(basename "$f") is executable by paul"
  else bad "installed $f is NOT executable by paul: the guard would be skipped"; fi
done
rm -rf "$P"

# The dispatcher still runs a repository's own hook.
new_repo own private
printf '#!/bin/sh\ntouch "%s/own-hook-ran"\n' "$T" > "$T/own/.git/hooks/pre-commit"; chmod +x "$T/own/.git/hooks/pre-commit"
commit own a.txt "x"; [ -e "$T/own-hook-ran" ] && ok "a repository's own pre-commit hook still runs" || bad "the repository's own pre-commit hook did not run"

# The Claude hook denies routes around the guard, and nothing else.
hook() { jq -cn --arg c "$1" '{tool_name: "Bash", tool_input: {command: $c}}' | "$here/claude-hook"; }
deny_case() { if hook "$1" | /usr/bin/grep -q '"deny"'; then ok "claude hook denies: $1"; else bad "claude hook allowed: $1"; fi; }
allow_case() { if hook "$1" | /usr/bin/grep -q '"deny"'; then bad "claude hook denied: $1"; else ok "claude hook allows: $1"; fi; }
deny_case "git push --no-verify origin main"
deny_case "runuser -u paul -- git -C /x push --no-verify"
deny_case "git -c core.hooksPath=/dev/null push origin main"
deny_case "git config --global core.hooksPath /tmp/h"
deny_case "gh repo create thepictishbeast/x --public"
deny_case "gh repo edit thepictishbeast/x --visibility public --accept-visibility-change-consequences"
deny_case "gh api -X PATCH repos/thepictishbeast/x -F private=false"
deny_case "gh gist create --public notes.md"
deny_case "gh api -X PUT repos/thepictishbeast/x/contents/a.md -f message=m -f content=Zm9v"
allow_case "git push origin main"
allow_case "runuser -u paul -- git -c credential.helper= push -q origin main"
allow_case "gh repo create thepictishbeast/x --private"
allow_case "gh api repos/thepictishbeast/x --jq .private"
allow_case "git commit -n -m wip"
deny_case "git config --system --unset core.hooksPath"
deny_case "GIT_CONFIG_KEY_0=core.hooksPath GIT_CONFIG_VALUE_0=/tmp git push"
allow_case "git config --get core.hooksPath"
allow_case "runuser -u paul -- git config --system --get core.hooksPath"
# A read must not vouch for a write elsewhere in the same command.
deny_case "git config --get core.hooksPath; git config core.hooksPath /dev/null"
deny_case "git config --get core.hooksPath && git config --global core.hooksPath /tmp/h"
deny_case "x=\$(git config --get core.hooksPath) || git config --unset-all core.hooksPath"
deny_case "git config set core.hooksPath /tmp/h"
deny_case "git config --file /etc/gitconfig core.hooksPath /tmp/h"
deny_case "git config core.hooksPath /tmp/h --get"
# Routes around the text match: absolute paths, quoting, abbreviated flags,
# config the guard's setting lives in never being read, keys that remove it
# without naming it, and includes that override it.
deny_case "/usr/bin/git push --no-verify origin main"
deny_case "\\git push --no-verify origin main"
deny_case "\"git\" push --no-verify origin main"
deny_case "git push --no-veri origin main"
deny_case "/usr/bin/git config --system core.hooksPath /dev/null"
deny_case "GIT_CONFIG_NOSYSTEM=1 git push origin main"
deny_case "export GIT_CONFIG_NOSYSTEM=1; git push origin main"
deny_case "GIT_CONFIG_SYSTEM=/dev/null git push origin main"
deny_case "GIT_CONFIG_GLOBAL=/tmp/g git push origin main"
deny_case "git --config-env=core.hooksPath=X push origin main"
deny_case "git -c include.path=/tmp/g push origin main"
deny_case "git config --system --remove-section core"
deny_case "git config --system --rename-section core old"
deny_case "git config --system include.path /tmp/g"
deny_case "GIT_EDITOR='sed -i /hooksPath/d' git config --system --edit"
deny_case "printf '[core]\\n\\thooksPath = /tmp/h\\n' >> .git/config"
deny_case "sed -i '/hooksPath/d' /etc/gitconfig"
deny_case "git -c alias.p=push --no-verify p origin main"
deny_case "git -C /x --no-pager config --system core.hooksPath /tmp/h"
allow_case "git commit -q -m 'edit config docs'"
allow_case "git log --grep config -3"
allow_case "runuser -u paul -- git config --global user.name paul"
allow_case "git status -sb; git diff --stat origin/main..HEAD"
allow_case "stat -c %a /etc/gitconfig; chmod 644 /etc/gitconfig"
allow_case "cat > /tmp/body.html <<'HTML'
<p>The guard lives in <code>/etc/gitconfig</code> as core.hooksPath.</p>
HTML"
deny_case "echo x 2>/dev/null >> ~/.gitconfig"
# File operations: only a real config file as the DESTINATION counts, and
# deletion only matters for the system and global configs.
deny_case "install -m 644 /tmp/gitconfig /etc/gitconfig"
deny_case "ln -sf /tmp/g /etc/gitconfig"
deny_case "cp /tmp/gitconfig /etc/"
deny_case "rm -f /etc/gitconfig"
deny_case "truncate -s0 ~/.gitconfig"
deny_case "dd if=/tmp/g of=/etc/gitconfig"
deny_case "echo x >/etc/gitconfig"
deny_case "mv /tmp/c /x/repo/.git/config"
# Expansions and wildcards that build a blocked string at run time (from the
# 2026-10-01 adversarial review; each was allowed before).
deny_case "git push --\${EMPTY}no-verify origin main"
deny_case "git push --no-verify\$(echo) origin main"
deny_case "git push --no\`echo -verify\` origin main"
deny_case "git rebase --exec 'git push --no-verify' main"
deny_case "gh api -X POST user/repos -f name=x"
# False denials found by replaying 12,447 real commands; each must pass.
allow_case "git -C \$R push -q origin \$def"
allow_case "sudo -u paul git -C /x commit --no-verify -q -F - -- a.sh <<'MSG'
skip the line-count ratchet
MSG"
allow_case "gh api -X GET user/repos --paginate -f per_page=100 -q '.[] | select(.private==false) | .name'"
allow_case "git log -p --all -S\"\$(echo x)\" --oneline"
allow_case "cat > notes.md <<'EOF'
Never run \`git push --no-verify\` to get past it.
EOF"
allow_case "cd /tank/scratch/build && rm -rf *"
# Wildcards that are quoted, or only read, never replace a config.
allow_case "sed -E 's/.*//' notes.txt > out.txt"
allow_case "ls .git/* 2>/dev/null | head"
allow_case "for c in /home/paul/projects/*/.git/config; do grep -c hooksPath \$c; done 2>/dev/null"
allow_case "grep -E 'a.*b' src/*.rs > /tmp/hits.txt"
deny_case "rm -rf .*"
deny_case "cp /tmp/c /x/*/.git/config"
allow_case "cargo test 2>&1 | grep -E 'test result|FAILED' > /tmp/out.txt"
allow_case "gh api -X POST user/repos -f name=x -F private=true"
deny_case "sed -i 's/a/b/' ~/.g*config"
deny_case "sed -i 's/h.*/h=x/' ~/.*git/config"
deny_case "perl -i.bak -pe 's/a/b/' ~/.config/g*/config"
deny_case "cp /tmp/m ~/.g*config"
deny_case "echo x >> /etc/git*"
deny_case "printf x | tee /etc/g*config > /dev/null"
deny_case "gh api repos/u/r -X PATCH -f \$(echo private)=false"
deny_case "gh repo edit u/r --visibility \`echo public\`"
deny_case "gh api -X PATCH repos/u/r --input settings.json"
allow_case "git log --since=\$SINCE --format=%h -5"
allow_case "runuser -u paul -- git -C \$W push origin fix:main"
allow_case "git push origin HEAD:\$BRANCH"
allow_case "rm -rf /tank/scratch/fix-* ~/.cache/x*"
allow_case "sed -i 's/a/b/' src/*.rs"
allow_case "gh repo edit u/r --visibility private"
allow_case "gh api -X PATCH repos/u/r/issues/3 -f body=\"\$(cat note.md)\""
allow_case "gh api repos/u/r/issues?per_page=5 --jq '.[].title'"
allow_case "cp /etc/git/config /backup/git/config.bak"
allow_case "rm .git/config.orig"
allow_case "dd if=/src/git/config of=/dst/git/config"
allow_case "rm /tmp/.git/config"
allow_case "rm -rf /tmp/git/config"
allow_case "mv /tmp/old.gitconfig /tmp/new.gitconfig"
allow_case "mv .git/config.orig .git/config.new"
allow_case "cp ~/.gitconfig ~/gitconfig.bak"
allow_case "mv /src/git/config /dst/git/config"
allow_case "cat .git/config"
allow_case "/usr/bin/grep -i hookspath /etc/gitconfig 2>/dev/null"
allow_case "git -C /x log --oneline -3 2>/dev/null"
allow_case "/usr/local/bin/git-push-guard origin https://github.com/x/y.git"
allow_case "git config --get-regexp '^core\\.'"
allow_case "git config --system --get include.path"
allow_case "runuser -u paul -- git config --show-origin --get-all core.hooksPath"
allow_case "git config get core.hooksPath"
allow_case "git config --file /etc/gitconfig --get core.hooksPath"
allow_case "h=\$(git -C /x config --get core.hooksPath); echo \"\$h\""
allow_case "echo 'the guard sets core.hooksPath system-wide' > notes.md"
allow_case "cat > msg <<'EOF'
push-guard: uses core.hooksPath with a dispatcher; denies --no-verify
EOF
git commit -q -F msg"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
