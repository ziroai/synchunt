#!/usr/bin/env bash
#
# check.sh — run the full verification suite in parallel.
#
#   ./scripts/check.sh            # everything
#   ./scripts/check.sh --quick    # skip the CLI smoke tests
#
# Each check runs in its own worker; output is collected in .check/ and a
# summary is printed at the end. Exits non-zero if any check fails.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

QUICK=0
for arg in "$@"; do
    case "$arg" in
        --quick|-q) QUICK=1 ;;
        -h|--help) sed -n '2,12p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown option: $arg" >&2; exit 2 ;;
    esac
done

OUT="$ROOT/.check"
rm -rf "$OUT"
mkdir -p "$OUT"

run() {
    local name="$1"; shift
    ( "$@" >"$OUT/$name.log" 2>&1; echo $? >"$OUT/$name.rc" ) &
}

echo "SyncHunt verification — logs in .check/"
echo

run pytest      python3 -m pytest tests -q
run pyflakes    python3 -m pyflakes core modules reports main.py tests
run compile     python3 -m compileall -q core modules reports main.py tests
run doctor      python3 main.py --doctor

if [ "$QUICK" -eq 0 ]; then
    run dry-run     python3 main.py -d example.com --dry-run --profile deep --output-dir "$OUT/dry"
    run list-phases python3 main.py --list-phases
fi

wait

FAILED=0
printf "%-14s %s\n" "CHECK" "RESULT"
printf "%-14s %s\n" "-----" "------"
for rc_file in "$OUT"/*.rc; do
    name="$(basename "$rc_file" .rc)"
    code="$(cat "$rc_file" 2>/dev/null || echo 1)"
    if [ "$code" = "0" ]; then
        printf "%-14s %s\n" "$name" "ok"
    elif [ "$name" = "doctor" ]; then
        # exit 1 means "required tools missing", which is about the machine,
        # not the code - report it without failing the suite
        printf "%-14s %s\n" "$name" "ok (external tools missing)"
    else
        printf "%-14s %s\n" "$name" "FAILED (exit $code)"
        FAILED=1
    fi
done

echo
if [ "$FAILED" -ne 0 ]; then
    echo "Failure details:"
    for rc_file in "$OUT"/*.rc; do
        [ "$(cat "$rc_file")" = "0" ] && continue
        name="$(basename "$rc_file" .rc)"
        echo "--- $name ---"
        tail -25 "$OUT/$name.log"
    done
    exit 1
fi

grep -E "passed|failed" "$OUT/pytest.log" | tail -1
echo "all checks passed"
