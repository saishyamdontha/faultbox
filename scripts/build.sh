#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p build
# -O0 for plugins so the compiler keeps the faulty code as written
for p in good nullderef oob_write; do
  gcc -O0 -g -Wall -Isrc -shared -fPIC -o build/$p.so plugins/$p.c
done
gcc -O2 -g -Wall -Wextra -Isrc -rdynamic -o build/host src/host.c -ldl
echo "build ok"
