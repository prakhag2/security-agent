#!/bin/bash
# Run Juice Shop vulnerability scans in parallel (5 concurrent)
# Each scan hits the SSE endpoint and waits for completion

BASE_URL="https://d3v0tyjuygpl5i.cloudfront.net"
CONCURRENCY=5
RESULTS_DIR="/tmp/scan_results"
mkdir -p "$RESULTS_DIR"

TESTS_FILE="/tmp/juice_50_tests.txt"
TOTAL=$(wc -l < "$TESTS_FILE")
echo "Starting parallel scans: $TOTAL tests, $CONCURRENCY concurrent"
echo "Start time: $(date)"

run_scan() {
    local test_name="$1"
    local idx="$2"
    local outfile="$RESULTS_DIR/${test_name}.log"

    echo "[$idx/$TOTAL] Starting: $test_name"

    # Hit the SSE endpoint, wait for completion (timeout 30 min per scan)
    curl -s -N "${BASE_URL}/api/juiceshop/vuln-scan?test=${test_name}" \
        --max-time 1800 \
        > "$outfile" 2>&1

    local status=$?
    if [ $status -eq 0 ] || [ $status -eq 28 ]; then
        # Check if we got results
        if grep -q '"verdict"' "$outfile" 2>/dev/null; then
            local confirmed=$(grep -o '"confirmed_vulnerability"' "$outfile" | wc -l)
            echo "[$idx/$TOTAL] DONE: $test_name - $confirmed confirmed vulns"
        else
            echo "[$idx/$TOTAL] DONE: $test_name - (check log for details)"
        fi
    else
        echo "[$idx/$TOTAL] FAILED: $test_name (curl exit=$status)"
    fi
}

export -f run_scan
export BASE_URL RESULTS_DIR TOTAL

# Run with GNU parallel if available, otherwise use xargs
if command -v parallel &>/dev/null; then
    cat "$TESTS_FILE" | nl -ba | parallel -j $CONCURRENCY --colsep '\t' run_scan {2} {1}
else
    # Fallback: background jobs with a semaphore
    idx=0
    while IFS= read -r test_name; do
        idx=$((idx + 1))
        run_scan "$test_name" "$idx" &

        # Limit concurrency
        if (( idx % CONCURRENCY == 0 )); then
            wait
        fi
    done < "$TESTS_FILE"
    wait
fi

echo ""
echo "All scans complete: $(date)"
echo "Checking results..."

# Summary
curl -s "${BASE_URL}/api/scan-results?project=juiceshop" | python3 -c "
import json, sys
results = json.load(sys.stdin)
print(f'Total saved scans: {len(results)}')
confirmed_total = sum(r.get('confirmed', 0) for r in results)
targets_total = sum(r.get('targets', 0) for r in results)
print(f'Total targets: {targets_total}')
print(f'Total confirmed: {confirmed_total}')
"
