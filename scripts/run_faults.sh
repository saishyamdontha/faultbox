#!/usr/bin/env bash
set -u
cd "$(dirname "$0")/.."
mkdir -p results
modes="${*:-none fork ipc mpk mpk_fast mpk_scan}"
plugins="good nullderef oob_write corrupt_unprotected divzero illegal abort_call stack_overflow exit_call wrpkru_attack"
out=results/faults.csv
echo "mode,plugin,exit_code,outcome" > "$out"
for m in $modes; do
  for p in $plugins; do
    ./build/host "$m" build/$p.so > /dev/null 2>&1
    code=$?
    case $code in
      0)  outcome=ok ;;
      3)  outcome=host_memory_corrupted ;;
      4)  outcome=plugin_fault_contained ;;
      5)  outcome=rejected_at_load ;;
      42) outcome=host_exited_by_plugin ;;
      *)  if [ "$code" -gt 128 ]; then
            outcome="host_crashed_SIG$(kill -l $((code - 128)))"
          else
            outcome="other_$code"
          fi ;;
    esac
    echo "$m,$p,$code,$outcome" | tee -a "$out"
  done
done
