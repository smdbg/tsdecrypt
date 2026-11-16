#!/bin/sh
set -eu
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$test_dir/.." && pwd)
test_tmp=$(mktemp -d)
trap 'rm -rf "$test_tmp"' EXIT
"${CC:-cc}" -std=gnu11 -O2 -Wall -Wextra -Werror -I"$repo_dir" \
    "$test_dir/input-shift-test.c" "$repo_dir/input-shift.c" -o "$test_tmp/input-shift-test"
"$test_tmp/input-shift-test"
