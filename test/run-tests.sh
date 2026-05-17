#!/bin/sh
# Local test suite for claude-secrets. Uses an ephemeral
# CLAUDE_SECRETS_DIR so it doesn't touch the user's real vault.
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CLI="$REPO_ROOT/bin/claude-secrets"

PASS=0
FAIL=0
pass() { echo "  pass: $*"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $*"; FAIL=$((FAIL+1)); }

CLAUDE_SECRETS_DIR="$(mktemp -d)"
export CLAUDE_SECRETS_DIR
trap 'rm -rf "$CLAUDE_SECRETS_DIR"' EXIT

# ----------------------------------------------------------------------
echo "[1] CLI syntax + help"

if sh -n "$CLI"; then pass "claude-secrets: syntax OK"; else fail "claude-secrets: syntax error"; fi

if "$CLI" --help 2>&1 | grep -qF "init"; then
    pass "help: shows subcommand list"
else
    fail "help: missing subcommand list"
fi

# ----------------------------------------------------------------------
echo ""
echo "[2] init"

"$CLI" init >/dev/null
if [ -f "$CLAUDE_SECRETS_DIR/key.txt" ]; then
    pass "init: created key.txt"
else
    fail "init: no key.txt"
fi

# Mode must be 600 on the key
mode="$(stat -c '%a' "$CLAUDE_SECRETS_DIR/key.txt" 2>/dev/null)"
if [ "$mode" = "600" ]; then
    pass "init: key.txt is mode 600"
else
    fail "init: key.txt mode is $mode (want 600)"
fi

# Refuses to clobber on re-init
if "$CLI" init >/dev/null 2>&1; then
    fail "init: re-init should have refused"
else
    pass "init: refuses to clobber existing key"
fi

# ----------------------------------------------------------------------
echo ""
echo "[3] put + get round-trip"

testval="round-trip-secret-value-12345"
printf '%s' "$testval" | "$CLI" put roundtrip >/dev/null
if [ -f "$CLAUDE_SECRETS_DIR/store/roundtrip.age" ]; then
    pass "put: created store/roundtrip.age"
else
    fail "put: no store/roundtrip.age"
fi

mode="$(stat -c '%a' "$CLAUDE_SECRETS_DIR/store/roundtrip.age" 2>/dev/null)"
if [ "$mode" = "600" ]; then
    pass "put: secret file is mode 600"
else
    fail "put: secret file mode is $mode (want 600)"
fi

got="$("$CLI" get roundtrip)"
if [ "$got" = "$testval" ]; then
    pass "get: round-trip value matches"
else
    fail "get: round-trip mismatch (got '$got')"
fi

# ----------------------------------------------------------------------
echo ""
echo "[4] input validation"

# Path traversal must refuse
if echo "x" | "$CLI" put ../escape 2>/dev/null; then
    fail "put: accepted path-traversal name"
else
    pass "put: refused path-traversal name"
fi

# Empty name must refuse
if echo "x" | "$CLI" put "" 2>/dev/null; then
    fail "put: accepted empty name"
else
    pass "put: refused empty name"
fi

# Invalid characters must refuse
if echo "x" | "$CLI" put "bad name with spaces" 2>/dev/null; then
    fail "put: accepted name with spaces"
else
    pass "put: refused name with spaces"
fi

# ----------------------------------------------------------------------
echo ""
echo "[5] list + rm"

echo "first"  | "$CLI" put alpha >/dev/null
echo "second" | "$CLI" put beta >/dev/null

if "$CLI" list | grep -qF alpha && "$CLI" list | grep -qF beta; then
    pass "list: shows both stored names"
else
    fail "list: missing one or both names"
fi

# list must NOT contain the values
if "$CLI" list | grep -qF "first" || "$CLI" list | grep -qF "second"; then
    fail "list: leaked plaintext value"
else
    pass "list: does not leak plaintext"
fi

"$CLI" rm alpha >/dev/null
if "$CLI" list 2>/dev/null | grep -qF alpha; then
    fail "rm: alpha still listed after rm"
else
    pass "rm: alpha removed"
fi

# ----------------------------------------------------------------------
echo ""
echo "[6] ref + pubkey"

# shellcheck disable=SC2016  # comparing literal $-string, not a shell variable
if [ "$("$CLI" ref my-secret)" = '${SECRET:my-secret}' ]; then
    pass "ref: emits correct handle form"
else
    fail "ref: incorrect format"
fi

if "$CLI" pubkey | grep -qE '^age1[a-z0-9]+$'; then
    pass "pubkey: emits valid age recipient"
else
    fail "pubkey: not a valid age recipient string"
fi

# ----------------------------------------------------------------------
echo ""
echo "[7] audit log"

# Audit must contain entries for every prior op
if [ -f "$CLAUDE_SECRETS_DIR/audit.log" ]; then
    pass "audit: log file exists"
else
    fail "audit: log file missing"
fi

mode="$(stat -c '%a' "$CLAUDE_SECRETS_DIR/audit.log" 2>/dev/null)"
if [ "$mode" = "600" ]; then
    pass "audit: log is mode 600"
else
    fail "audit: log mode is $mode (want 600)"
fi

# Should contain at least one put + get + rm + init
for verb in init put get rm; do
    if grep -qE "^[0-9TZ:.-]+ $verb " "$CLAUDE_SECRETS_DIR/audit.log"; then
        pass "audit: log contains $verb entries"
    else
        fail "audit: log missing $verb entries"
    fi
done

# ----------------------------------------------------------------------
echo ""
echo "[8] doc files exist + reference each other"

for f in README.md CLAUDE.md docs/DESIGN.md docs/THREAT_MODEL.md docs/SHARING_PROTOCOL.md; do
    if [ -f "$REPO_ROOT/$f" ]; then
        pass "doc: $f exists"
    else
        fail "doc: $f missing"
    fi
done

# README must point at age and at the CLAUDE.md
if grep -qF "age" "$REPO_ROOT/README.md" && grep -qF "CLAUDE.md" "$REPO_ROOT/README.md"; then
    pass "README: references age + CLAUDE.md"
else
    fail "README: missing key references"
fi

# ----------------------------------------------------------------------
echo ""
echo "summary: $PASS pass, $FAIL fail"
[ "$FAIL" -eq 0 ]
