#!/bin/sh
# Install claude-secrets — install the symlink, then verify (or
# offer to install) the age dependency.
set -eu

REPO="$(cd "$(dirname "$0")" && pwd)"
BIN="$REPO/bin/claude-secrets"
TARGET="${INSTALL_TARGET:-/usr/local/bin/claude-secrets}"

# 1. Make sure the wrapper script is executable
if [ ! -x "$BIN" ]; then
    chmod +x "$BIN" 2>/dev/null || {
        echo >&2 "error: cannot chmod +x $BIN"; exit 1
    }
fi

# 2. Symlink into $PATH FIRST so partial installs are still discoverable
if [ -e "$TARGET" ]; then
    # If it's already a symlink pointing at our BIN, no prompt
    existing="$(readlink "$TARGET" 2>/dev/null || true)"
    if [ "$existing" = "$BIN" ]; then
        echo "Symlink already in place: $TARGET → $BIN"
    else
        printf "%s already exists. Overwrite? [y/N] " "$TARGET"
        read -r ans
        case "$ans" in
            [Yy]*) ;;
            *) echo "Skipped symlink. claude-secrets is at $BIN"; ;;
        esac
        if [ -w "$(dirname "$TARGET")" ]; then
            ln -sf "$BIN" "$TARGET"
        else
            sudo ln -sf "$BIN" "$TARGET"
        fi
    fi
else
    if [ -w "$(dirname "$TARGET")" ]; then
        ln -sf "$BIN" "$TARGET"
    else
        sudo ln -sf "$BIN" "$TARGET"
    fi
    echo "Installed: $TARGET → $BIN"
fi

# 3. Check for age — warn, don't fail. The tool errors clearly at
#    runtime if age is missing.
if ! command -v age >/dev/null 2>&1 || ! command -v age-keygen >/dev/null 2>&1; then
    echo ""
    echo "WARNING: 'age' / 'age-keygen' is not installed yet."
    echo "The symlink is in place but claude-secrets won't work until you install age:"
    echo ""
    echo "  Debian / Ubuntu / Kali:  sudo apt install age"
    echo "  macOS (Homebrew):        brew install age"
    echo "  Arch:                    sudo pacman -S age"
    echo "  From Rust source:        cargo install rage"
    echo "  Direct download:         https://github.com/FiloSottile/age/releases"
    echo ""

    # Offer auto-install on Debian-family (paul's laptop is Kali)
    if command -v apt-get >/dev/null 2>&1 && [ "$(id -u)" -eq 0 ]; then
        printf "Detected apt + running as root. Install age now? [y/N] "
        read -r ans
        case "$ans" in
            [Yy]*)
                apt-get update -qq
                apt-get install -y age
                echo ""
                echo "age installed:"
                age --version
                ;;
            *) echo "Skipped. Install age manually before running claude-secrets." ;;
        esac
    fi
fi

echo ""
echo "Next: run 'claude-secrets init' to generate your keypair."
echo "Docs: https://github.com/thepictishbeast/claude-secrets"
