#!/usr/bin/env bash
# test-envelope-mirror.sh — self-test for envelope-mirror-check.sh (ADR-0022 §2).
#
# Exercises the five scenarios the conflict-only guard must handle correctly:
#   1. Identical files in both repos          → pass (exit 0)
#   2. File present only in collector         → pass (in-flight addition, not a conflict)
#   3. File present only in monorepo          → pass (in-flight addition, not a conflict)
#   4. Same relative path, different content  → fail (exit 1, real conflict caught)
#   5. Empty collector fixture dir            → error (exit 2, vacuous pass prevented)
#
# Run locally:
#   bash .github/scripts/test-envelope-mirror.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MIRROR_CHECK="$SCRIPT_DIR/envelope-mirror-check.sh"

if [ ! -f "$MIRROR_CHECK" ]; then
    echo "error: envelope-mirror-check.sh not found at $MIRROR_CHECK" >&2
    exit 2
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

pass=0
fail=0

run_test() {
    local name="$1"
    local expected_exit="$2"
    local collector_dir="$3"
    local monorepo_dir="$4"
    local actual_exit=0

    bash "$MIRROR_CHECK" "$collector_dir" "$monorepo_dir" >/dev/null 2>&1 || actual_exit=$?

    if [ "$actual_exit" -eq "$expected_exit" ]; then
        echo "PASS  $name (exit $actual_exit as expected)"
        pass=$((pass + 1))
    else
        echo "FAIL  $name (expected exit $expected_exit, got exit $actual_exit)"
        fail=$((fail + 1))
    fi
}

# Test 1 — identical content in both repos: should pass (exit 0).
{
    COL="$WORK/t1/collector/valid" && MON="$WORK/t1/monorepo/valid"
    mkdir -p "$COL" "$MON"
    printf '{"event_source":"argocd"}' > "$COL/argocd.json"
    cp "$COL/argocd.json"              "$MON/argocd.json"
    run_test "identical files pass" 0 "$WORK/t1/collector" "$WORK/t1/monorepo"
}

# Test 2 — file present only in collector (in-flight addition): should pass (exit 0).
{
    COL="$WORK/t2/collector/valid" && MON="$WORK/t2/monorepo/valid"
    mkdir -p "$COL" "$MON"
    printf '{"event_source":"argocd"}' > "$COL/argocd.json"
    printf '{"event_source":"github"}'  > "$COL/github.json"   # collector-only fixture
    cp "$COL/argocd.json"               "$MON/argocd.json"
    run_test "collector-only fixture is not a conflict" 0 "$WORK/t2/collector" "$WORK/t2/monorepo"
}

# Test 3 — file present only in monorepo (in-flight addition): should pass (exit 0).
{
    COL="$WORK/t3/collector/valid" && MON="$WORK/t3/monorepo/valid"
    mkdir -p "$COL" "$MON"
    printf '{"event_source":"argocd"}' > "$COL/argocd.json"
    cp "$COL/argocd.json"               "$MON/argocd.json"
    printf '{"event_source":"github"}'  > "$MON/github.json"   # monorepo-only fixture
    run_test "monorepo-only fixture is not a conflict" 0 "$WORK/t3/collector" "$WORK/t3/monorepo"
}

# Test 4 — same path, different content: should fail (exit 1, conflict detected).
{
    COL="$WORK/t4/collector/valid" && MON="$WORK/t4/monorepo/valid"
    mkdir -p "$COL" "$MON"
    printf '{"event_source":"argocd","collector_id":"AAA"}' > "$COL/argocd.json"
    printf '{"event_source":"argocd","collector_id":"BBB"}' > "$MON/argocd.json"
    run_test "same-path different-content is caught (exit 1)" 1 "$WORK/t4/collector" "$WORK/t4/monorepo"
}

# Test 5 — empty collector fixture directory: should error (exit 2, vacuous pass prevented).
{
    COL="$WORK/t5/collector" && MON="$WORK/t5/monorepo/valid"
    mkdir -p "$COL" "$MON"
    # No *.json in collector dir.
    printf '{"event_source":"argocd"}' > "$MON/argocd.json"
    run_test "empty collector dir is an error (exit 2)" 2 "$COL" "$WORK/t5/monorepo"
}

echo ""
echo "Self-test: $pass/$((pass + fail)) passed"
if [ "$fail" -gt 0 ]; then
    echo "FAILED: $fail test(s) did not produce the expected exit code." >&2
    exit 1
fi
exit 0
