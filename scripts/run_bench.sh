#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p results
out=results/bench.csv
echo "rep,mode,metric,value" > "$out"
for rep in 1 2 3 4 5; do
  for m in none fork ipc ipc_shm mpk mpk_fast mpk_hard; do
    cpus=2
    case $m in
      fork)    calls=10000 ;;
      ipc)     calls=100000 ;;
      ipc_shm) calls=1000000; cpus=2,4 ;;   # host and worker on separate cores
      *)       calls=1000000 ;;
    esac
    taskset -c "$cpus" ./build/bench "$m" "$calls" 1000 2>/dev/null | sed "s/^/$rep,/" | tee -a "$out"
  done
done
echo "--- mean over 5 reps ---"
awk -F, 'NR>1 { k=$2","$3; s[k]+=$4; n[k]++ } END { for (k in s) printf "%s,%.2f\n", k, s[k]/n[k] }' "$out" | sort
