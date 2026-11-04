#!/usr/bin/env bash
set -u
cd "$(dirname "$0")/.."
mkdir -p results
modes="${*:-none fork mpk mpk_fast}"
out=results/faults.csv
echo "mode,plugin,exit_code,outcome" > "$out"
for m in $modes; do
  for p in good nullderef oob_write; do
    ./build/host "$m" build/$p.so > /dev/null 2>&1
    code=$?
    case $code in
      0)   outcome=ok ;;
      3)   outcome=host_state_corrupted ;;
      4)   outcome=plugin_fault_contained ;;
      139) outcome=host_crashed_sigsegv ;;
      *)   outcome=other_$code ;;
    esac
    echo "$m,$p,$code,$outcome" | tee -a "$out"
  done
done
