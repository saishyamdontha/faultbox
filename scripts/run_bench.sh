#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p results
out=results/bench.csv
echo "rep,mode,metric,value" > "$out"
for rep in 1 2 3 4 5; do
  for m in none fork ipc mpk mpk_fast mpk_hard; do
    case $m in
      fork) calls=10000 ;;
      ipc)  calls=100000 ;;
      *)    calls=1000000 ;;
    esac
    taskset -c 2 ./build/bench "$m" "$calls" 1000 2>/dev/null | sed "s/^/$rep,/" | tee -a "$out"
  done
done
echo "--- mean over 5 reps ---"
awk -F, 'NR>1 { k=$2","$3; s[k]+=$4; n[k]++ } END { for (k in s) printf "%s,%.2f\n", k, s[k]/n[k] }' "$out" | sort
