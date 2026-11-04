#!/usr/bin/env bash
set -u
cd "$(dirname "$0")/.."
mkdir -p results
out=results/state.csv
echo "mode,recovery,first_call,fault,after_recovery,result" > "$out"
# "skip" is the negative control and is expected to FAIL
for spec in "mpk_fast skip" "mpk_fast reload" "mpk_fast snapshot" "mpk_hard snapshot"; do
  ./build/state_test $spec 2>/dev/null | tee -a "$out"
done
