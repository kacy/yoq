#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
build_dir=$(mktemp -d)
trap 'rm -rf "$build_dir"' EXIT

# host fixtures use low-address packet buffers for the 32-bit bpf context.
# ci runs them on linux x86_64; kernel tests cover actual bpf loading.
for source in "$repo_root"/tests/bpf/*_test.c; do
    test_name=$(basename -- "$source" .c)
    "${CC:-cc}" -std=gnu11 -O2 -Wall -Wextra -Werror \
        "$source" -o "$build_dir/$test_name"
    "$build_dir/$test_name"
done
