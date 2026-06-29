#!/usr/bin/env bash
# envelope-mirror-check.sh — conflict-only fixture mirror check (ADR-0022 §2).
#
# Usage: envelope-mirror-check.sh <collector_fixtures_dir> <monorepo_fixtures_dir>
#
# Exit codes:
#   0 — no conflicts: every fixture present in BOTH repos has identical content.
#   1 — one or more conflicts detected (same path, different sha256 in both repos).
#   2 — usage error, missing/empty fixture directory (vacuous pass prevented per ADR-0022 §1).
#
# Conflict-only semantics (ADR-0022 §2):
#   A fixture present in only one repo is NOT a conflict — it is an in-flight
#   lock-step addition. Only a fixture present in BOTH repos with different
#   content is a conflict. This avoids the bootstrap deadlock that exact-equality
#   bidirectional mirrors create when one repo lands a new fixture first.
#
# Run locally:
#   bash .github/scripts/envelope-mirror-check.sh \
#     internal/envelope/testdata/fixtures \
#     /path/to/monorepo/infra/schemas/fixtures/envelope

set -euo pipefail

if [ $# -ne 2 ]; then
    echo "usage: $(basename "$0") <collector_fixtures_dir> <monorepo_fixtures_dir>" >&2
    exit 2
fi

COLLECTOR_DIR="$1"
MONOREPO_DIR="$2"

# Validate: directories must exist and contain at least one *.json file.
# The second check prevents the script from passing vacuously if a checkout
# silently failed or was scoped to the wrong path.
if [ ! -d "$COLLECTOR_DIR" ]; then
    echo "error: collector fixtures directory not found: $COLLECTOR_DIR" >&2
    exit 2
fi
if [ ! -d "$MONOREPO_DIR" ]; then
    echo "error: monorepo fixtures directory not found: $MONOREPO_DIR" >&2
    exit 2
fi

count_json() {
    find "$1" -name '*.json' -type f | wc -l
}

if [ "$(count_json "$COLLECTOR_DIR")" -eq 0 ]; then
    echo "error: no *.json fixtures found in collector dir: $COLLECTOR_DIR" >&2
    exit 2
fi
if [ "$(count_json "$MONOREPO_DIR")" -eq 0 ]; then
    echo "error: no *.json fixtures found in monorepo dir: $MONOREPO_DIR" >&2
    exit 2
fi

# Build manifest: "<relpath> <sha256hex>" per *.json, sorted by relpath.
# Relative paths use forward slashes regardless of OS.
build_manifest() {
    local root="$1"
    (
        cd "$root"
        find . -name '*.json' -type f | LC_ALL=C sort | while IFS= read -r fpath; do
            hash=$(sha256sum "$fpath" | awk '{print $1}')
            # Strip leading "./" so relative paths are clean ("valid/argocd.json", not "./valid/argocd.json").
            echo "${fpath#./} $hash"
        done
    )
}

COLLECTOR_MANIFEST=$(build_manifest "$COLLECTOR_DIR")
MONOREPO_MANIFEST=$(build_manifest "$MONOREPO_DIR")

# Load manifests into associative arrays keyed by relative path.
declare -A collector_hashes
declare -A monorepo_hashes

while IFS=' ' read -r fpath hash; do
    [ -n "$fpath" ] && collector_hashes["$fpath"]="$hash"
done <<< "$COLLECTOR_MANIFEST"

while IFS=' ' read -r fpath hash; do
    [ -n "$fpath" ] && monorepo_hashes["$fpath"]="$hash"
done <<< "$MONOREPO_MANIFEST"

# Conflict-only comparison: fail only when the same relative path appears in
# BOTH repos with different content.
conflicts=0
for fpath in "${!collector_hashes[@]}"; do
    # Test key existence without treating an empty value as absent.
    if [ -n "${monorepo_hashes[$fpath]+set}" ]; then
        if [ "${collector_hashes[$fpath]}" != "${monorepo_hashes[$fpath]}" ]; then
            echo "CONFLICT: $fpath" >&2
            echo "  collector sha256: ${collector_hashes[$fpath]}" >&2
            echo "  monorepo  sha256: ${monorepo_hashes[$fpath]}" >&2
            conflicts=$((conflicts + 1))
        fi
    fi
done

if [ "$conflicts" -gt 0 ]; then
    echo "" >&2
    echo "FIXTURE CONFLICT DETECTED: $conflicts file(s) present in both repos with different content." >&2
    echo "The two validators test different things for the same fixture." >&2
    echo "Update both repos' copies of the listed fixture(s) to the same content in lock-step (manifest §0)." >&2
    exit 1
fi

# Summary (stdout so it appears in CI logs).
collector_count=${#collector_hashes[@]}
monorepo_count=${#monorepo_hashes[@]}
shared=0
for fpath in "${!collector_hashes[@]}"; do
    if [ -n "${monorepo_hashes[$fpath]+set}" ]; then
        shared=$((shared + 1))
    fi
done

echo "Conflict-only envelope mirror check passed."
echo "  collector fixtures: $collector_count"
echo "  monorepo  fixtures: $monorepo_count"
echo "  shared (conflict-checked): $shared — all content-identical"
exit 0
