#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p build
for src in plugins/*.c; do
  p=$(basename "$src" .c)
  gcc -O0 -g -Wall -Wno-infinite-recursion -Isrc -shared -fPIC -o build/$p.so "$src"
done
gcc -O2 -g -Wall -Wextra -Isrc -rdynamic -o build/host  src/host.c  src/isolation.c -ldl
gcc -O2 -g -Wall -Wextra -Isrc -rdynamic -o build/bench src/bench.c src/isolation.c -ldl
echo "build ok"
