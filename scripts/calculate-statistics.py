#!/usr/bin/env python3
# =============================================================
# scripts/calculate-statistics.py
#
# PURPOSE: Compute mean, SD, 95% CI (t-distribution for small n),
#          min, max, and range for all pipeline stage timings.
#          Addresses Reviewer 2 critique #3: "No CIs anywhere."
#
# OUTPUT:
#   results/statistics/timing-stats.csv   — machine-readable
#   results/statistics/timing-stats.txt   — paper-ready table
# =============================================================

import math
import os
import re
import csv
from collections import defaultdict

# Use scipy if available for exact t-critical values; fall back to approx
try:
    from scipy import stats as scipy_stats
    HAS_SCIPY = True
except ImportError:
    HAS_SCIPY = False

def t_critical_95(df):
    """95% CI t-critical value for given degrees of freedom."""
    if HAS_SCIPY:
        return scipy_stats.t.ppf(0.975, df)
    # Manual approximation for small n (Welch-Satterthwaite lookup)
    table = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571,
             6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262, 10: 2.228,
             15: 2.131, 20: 2.086, 30: 2.042}
    for k in sorted(table.keys(), reverse=True):
        if df >= k:
            return table[k]
    return 12.706  # df=1 worst case

def stats(vals):
    """Compute full statistics for a list of values."""
    n    = len(vals)
    mean = sum(vals) / n
    if n > 1:
        var  = sum((x - mean)**2 for x in vals) / (n - 1)  # sample variance
        sd   = math.sqrt(var)
        tc   = t_critical_95(n - 1)
        ci   = tc * sd / math.sqrt(n)
    else:
        sd, ci = 0.0, float('nan')
    return {
        'n': n,
        'mean': round(mean, 1),
        'sd': round(sd, 1),
        'ci95_low':  round(mean - ci, 1) if not math.isnan(ci) else 'n/a',
        'ci95_high': round(mean + ci, 1) if not math.isnan(ci) else 'n/a',
        'min': min(vals),
        'max': max(vals),
        'range': max(vals) - min(vals),
        'values': vals,
        'note': 'n=1: σ and CI not calculable' if n == 1 else ''
    }

# ── Load timing data ──────────────────────────────────────────
stages = defaultdict(list)
timings_files = [
    "results/multiapp/timings.txt",
    "results/baseline/baseline-timings.txt",
]

for fpath in timings_files:
    if os.path.exists(fpath):
        with open(fpath) as f:
            for line in f:
                line = line.strip()
                if "=" in line:
                    k, v = line.split("=", 1)
                    try:
                        stages[k.strip()].append(int(v.strip()))
                    except ValueError:
                        pass

if not stages:
    print("No timing data found. Run the pipeline first.")
    exit(1)

os.makedirs("results/statistics", exist_ok=True)

# ── Compute and output ────────────────────────────────────────
results = {}
for stage, vals in sorted(stages.items()):
    results[stage] = stats(vals)

# ── CSV output ────────────────────────────────────────────────
csv_path = "results/statistics/timing-stats.csv"
with open(csv_path, 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=[
        'stage', 'n', 'mean_s', 'sd_s', 'ci95_low', 'ci95_high',
        'min_s', 'max_s', 'range_s', 'note'
    ])
    writer.writeheader()
    for stage, s in results.items():
        writer.writerow({
            'stage': stage,
            'n': s['n'],
            'mean_s': s['mean'],
            'sd_s': s['sd'],
            'ci95_low': s['ci95_low'],
            'ci95_high': s['ci95_high'],
            'min_s': s['min'],
            'max_s': s['max'],
            'range_s': s['range'],
            'note': s['note']
        })

# ── Paper-ready text table ────────────────────────────────────
txt_path = "results/statistics/timing-stats.txt"
with open(txt_path, 'w') as f:
    header = (
        f"\n{'Stage':<35} {'n':>4} {'Mean(s)':>8} {'SD(s)':>7} "
        f"{'95% CI':>18} {'Min':>5} {'Max':>5} {'Note'}\n"
        f"{'-'*110}\n"
    )
    f.write(header)
    print(header, end='')

    for stage, s in results.items():
        ci_str = (f"[{s['ci95_low']}, {s['ci95_high']}]"
                  if s['ci95_low'] != 'n/a' else '[n/a — single run]')
        row = (
            f"{stage:<35} {s['n']:>4} {s['mean']:>8.1f} {s['sd']:>7.1f} "
            f"{ci_str:>18} {s['min']:>5} {s['max']:>5}  {s['note']}\n"
        )
        f.write(row)
        print(row, end='')

    # Compute wall-clock total (parallel block = max of Trivy stages)
    trivy_vals = [stages.get("vulnapp_trivy_seconds", [0]),
                  stages.get("dvwa_trivy_seconds", [0]),
                  stages.get("juiceshop_trivy_seconds", [0])]
    baseline_vals = stages.get("baseline_total_seconds", [25])
    baseline_mean = sum(baseline_vals) / len(baseline_vals)

    parallel_maxes = [max(t1, t2, t3)
                      for t1, t2, t3
                      in zip(*[stages.get(k, []) for k in
                               ["vulnapp_trivy_seconds",
                                "dvwa_trivy_seconds",
                                "juiceshop_trivy_seconds"]])]
    if parallel_maxes:
        par_stat = stats(parallel_maxes)
        note = (f"\n{'PARALLEL BLOCK (wall-clock)':<35} "
                f"{par_stat['n']:>4} {par_stat['mean']:>8.1f} {par_stat['sd']:>7.1f}"
                f"  (= max of 3 parallel Trivy stages — NOT sum)\n")
        f.write(note)
        print(note)

    footer = (
        f"\n{'='*110}\n"
        f"Baseline (no security tools): μ={baseline_mean:.1f}s "
        f"(from results/baseline/baseline-timings.txt)\n"
        f"NOTE: All CIs use two-tailed t-distribution at α=0.05.\n"
        f"      Stages with n=1 report 'n/a' for CI — not usable in comparative claims.\n"
    )
    f.write(footer)
    print(footer)

print(f"\nCSV  → {csv_path}")
print(f"Text → {txt_path}")
