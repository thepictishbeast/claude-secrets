#!/bin/sh
# Install claude-secrets — verify dependencies + symlink to /usr/local/bin
set -eu

REPO="$(cd "$(dirname "$0")" && pwd)"
BIN="$REPO/bin/claude-secrets"
TARGET="${INSTALL_TARGET:-/usr/local/bin/claude-secrets}"

# 1. Check age is installed
if ! command -v age >/dev/null 2>&1; then
    echo >&2 "claude-secrets requires 'age'. Install with:"
    echo >&2 "  Debian/Ubuntu: sudo apt install age"
    echo >&2 "  macOS:         brew install age"
    echo >&2 "  Or:            cargo install rage"
    exit 1
fi

if ! command -v age-keygen >/dev/null 2>&1; then
    echo >&2 "claude-secrets requires 'age-keygen' (usually ships with age)."
    exit 1
fi

# 2. Check the wrapper script exists + is executable
if [ ! -x "$BIN" ]; then
    chmod +x "$BIN" 2>/dev/null || {
        echo >&2 "cannot chmod +x $BIN"; exit 1
    }
fi

# 3. Install (symlink, so updates from git pull take effect immediately)
if [ -e "$TARGET" ]; then
    printf "%s already exists. Overwrite? [y/N] " "$TARGET"
    read -r ans
    case "$ans" in
        [Yy]*) ;;
        *) echo "skipped"; exit 0 ;;
    esac
fi

# Need sudo if the target dir isn't writable by us
if [ -w "$(dirname "$TARGET")" ]; then
    ln -sf "$BIN" "$TARGET"
else
    sudo ln -sf "$BIN" "$TARGET"
fi

echo "Installed: $TARGET → $BIN"
echo ""
echo "Next: run 'claude-secrets init' to generate your keypair."
