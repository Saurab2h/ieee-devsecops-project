#!/usr/bin/env bash
# =============================================================
# scripts/run-zap-vulnapp-extra.sh
#
# PURPOSE: Run ZAP against vulnapp 5 additional times so we
#          have n>=6 data points — resolving Reviewer 2 concern
#          about n=1 for ZAP/vulnapp in Table II.
#
# USAGE:
#   chmod +x scripts/run-zap-vulnapp-extra.sh
#   ./scripts/run-zap-vulnapp-extra.sh
#
# OUTPUT:
#   Appends vulnapp_zap_seconds=N to results/multiapp/timings.txt
#   for each run. Then prints updated mean and SD.
# =============================================================

set -e

TIMINGS_FILE="results/multiapp/timings.txt"
ZAP_IMAGE="ghcr.io/zaproxy/zaproxy:stable"
APP_PORT=8081
EXTRA_RUNS=5

mkdir -p results/multiapp/vulnapp results/multiapp/zap-extra

echo "============================================="
echo " ZAP vulnapp — Extra Runs for Statistical Validity"
echo " Target: ${EXTRA_RUNS} additional runs (total will be n>=6)"
echo " Started: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "============================================="

# ── Pre-pull ZAP image so pull time doesn't contaminate timing ──
echo "Pre-pulling ZAP image..."
docker pull "$ZAP_IMAGE" || true

for i in $(seq 1 $EXTRA_RUNS); do
    echo ""
    echo "--- ZAP vulnapp run $i of $EXTRA_RUNS ---"

    # Start vulnapp container
    docker rm -f vulnapp-zap-target 2>/dev/null || true
    docker run -d \
        --name vulnapp-zap-target \
        -p ${APP_PORT}:8080 \
        vulnapp

    # Wait for app to be ready
    echo "  Waiting for vulnapp to be ready..."
    for attempt in $(seq 1 20); do
        if curl -sf "http://localhost:${APP_PORT}/actuator/health" > /dev/null 2>&1; then
            echo "  vulnapp ready after ${attempt} seconds"
            break
        fi
        sleep 1
    done

    # Time the ZAP scan
    START=$(date +%s)

    docker run --rm \
        --network host \
        -v "$(pwd)/results/multiapp/zap-extra:/zap/wrk" \
        "$ZAP_IMAGE" \
        zap-baseline.py \
        -t "http://localhost:${APP_PORT}" \
        -J "zap-vulnapp-run${i}.json" \
        -l WARN \
        -d || true

    END=$(date +%s)
    DURATION=$((END - START))

    # Stop vulnapp
    docker rm -f vulnapp-zap-target 2>/dev/null || true

    echo "  Run $i completed in ${DURATION}s"
    echo "vulnapp_zap_seconds=${DURATION}" >> "$TIMINGS_FILE"
done

echo ""
echo "============================================="
echo " All extra runs complete. Updated timings:"
echo "============================================="

# Compute updated mean and SD for vulnapp_zap
python3 - << 'PYEOF'
import math, re

timings = []
with open("results/multiapp/timings.txt") as f:
    for line in f:
        m = re.match(r"vulnapp_zap_seconds=(\d+)", line.strip())
        if m:
            timings.append(int(m.group(1)))

n    = len(timings)
mean = sum(timings) / n
var  = sum((x - mean)**2 for x in timings) / n
sd   = math.sqrt(var)
# 95% CI using t-distribution (t critical for n-1 df)
import statistics
try:
    ci95 = statistics.NormalDist().inv_cdf(0.975) * sd / math.sqrt(n)
except Exception:
    ci95 = 1.96 * sd / math.sqrt(n)

print(f"vulnapp_zap raw values (n={n}): {timings}")
print(f"Mean μ = {mean:.1f}s")
print(f"Std Dev σ = {sd:.1f}s")
print(f"95% CI = [{mean-ci95:.1f}s, {mean+ci95:.1f}s]")
print(f"Min = {min(timings)}s  Max = {max(timings)}s")
print()
print("UPDATE TABLE II: ZAP DAST: vulnapp")
print(f"  n={n}  μ={mean:.1f}s  σ={sd:.1f}s  95%CI=[{mean-ci95:.1f},{mean+ci95:.1f}]")
PYEOF
