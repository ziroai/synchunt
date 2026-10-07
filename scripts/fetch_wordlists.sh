#!/usr/bin/env bash
#
# fetch_wordlists.sh — download the wordlists SyncHunt phases use.
#
# Usage:
#   ./scripts/fetch_wordlists.sh            # download missing lists
#   ./scripts/fetch_wordlists.sh --force    # re-download everything
#
# Files land in ./wordlists/ (git-ignored, they are large):
#   subdomains.txt    puredns brute-force / gotator permutations
#   resolvers.txt     puredns / massdns resolvers
#   directories.txt   dirsearch / feroxbuster / ffuf
#   common.txt        dirsearch default
#   parameters.txt    x8 / paramspider parameter names
#   permutations.txt  generated locally from common prefixes/suffixes

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="$ROOT/wordlists"
FORCE=0

for arg in "$@"; do
    case "$arg" in
        --force|-f) FORCE=1 ;;
        -h|--help)
            sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) echo "Unknown option: $arg" >&2; exit 2 ;;
    esac
done

mkdir -p "$DEST"

SECLISTS="https://raw.githubusercontent.com/danielmiessler/SecLists/master"
MISSING=0

fetch() {
    local url="$1" name="$2"
    local out="$DEST/$name"

    if [[ -s "$out" && "$FORCE" -ne 1 ]]; then
        echo "  ✓ $name (exists, $(wc -c <"$out") bytes)"
        return 0
    fi

    echo "  ↓ $name"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --retry 3 -o "$out.tmp" "$url" || { rm -f "$out.tmp"; MISSING=1; echo "    ✗ failed: $url" >&2; return 1; }
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$out.tmp" "$url" || { rm -f "$out.tmp"; MISSING=1; echo "    ✗ failed: $url" >&2; return 1; }
    else
        echo "    ✗ neither curl nor wget is installed" >&2
        MISSING=1
        return 1
    fi
    mv "$out.tmp" "$out"
}

echo "SyncHunt wordlist fetcher → $DEST"
echo

fetch "$SECLISTS/Discovery/DNS/subdomains-top1million-110000.txt" "subdomains.txt"
fetch "$SECLISTS/Discovery/Web-Content/raft-medium-directories.txt" "directories.txt"
fetch "$SECLISTS/Discovery/Web-Content/common.txt" "common.txt"
fetch "$SECLISTS/Discovery/Web-Content/burp-parameter-names.txt" "parameters.txt"
fetch "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt" "resolvers.txt"

# permutations.txt is deterministic and tiny — generate it instead of downloading.
if [[ ! -s "$DEST/permutations.txt" || "$FORCE" -eq 1 ]]; then
    echo "  ✎ permutations.txt (generated)"
    cat > "$DEST/permutations.txt" <<'EOF'
dev
development
staging
stage
stg
test
testing
qa
uat
prod
production
preprod
pre
demo
sandbox
beta
alpha
internal
int
corp
admin
api
api-dev
api-staging
web
www
app
app-dev
portal
gateway
-v2
-v1
-old
-new
EOF
else
    echo "  ✓ permutations.txt (exists)"
fi

echo
if [[ "$MISSING" -ne 0 ]]; then
    echo "Some downloads failed — check your network/proxy and retry." >&2
    exit 1
fi
echo "Done. Wordlists:"
ls -lh "$DEST" | grep -v '^total'
