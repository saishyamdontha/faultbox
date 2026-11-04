#!/usr/bin/env bash
set -u
cd "$(dirname "$0")/.."
out=results/baseline_none.csv
echo "mode,plugin,exit_code,outcome" > "$out"
for p in good nullderef oob_write; do
  ./build/host none build/$p.so > /dev/null 2>&1
  code=$?
  case $code in
    0)   outcome=ok ;;
    3)   outcome=host_state_corrupted ;;
    139) outcome=host_crashed_sigsegv ;;
    *)   outcome=other_$code ;;
  esac
  echo "none,$p,$code,$outcome" | tee -a "$out"
done
