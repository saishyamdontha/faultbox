#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p build
for p in good nullderef oob_write; do
  gcc -O0 -g -Wall -Isrc -shared -fPIC -o build/$p.so plugins/$p.c
done
gcc -O2 -g -Wall -Wextra -Isrc -rdynamic -o build/host  src/host.c  src/isolation.c -ldl
gcc -O2 -g -Wall -Wextra -Isrc -rdynamic -o build/bench src/bench.c src/isolation.c -ldl
echo "build ok"
