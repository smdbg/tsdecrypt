#!/bin/sh
set -eu

test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$test_dir/.." && pwd)
case "${1:-}" in
    '') check_upstream=0 ;;
    --check-upstream) check_upstream=1 ;;
    *) printf 'Usage: %s [--check-upstream]\n' "$0" >&2; exit 2 ;;
esac
test_tmp=$(mktemp -d "$test_dir/.cs378x-test.XXXXXX")
trap 'rm -rf "$test_tmp"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

compile_test() {
    source_file=$1
    executable=$2
    # Unused send/client functions are discarded; receive code, framing,
    # AES, fdread, and logging are the real implementation and dependencies.
    "${CC:-cc}" -std=gnu11 -O2 -Wall -Wextra -Wno-deprecated-declarations \
        -ffunction-sections -fdata-sections -I"$repo_dir" \
        "-DCS378X_SOURCE=\"$source_file\"" \
        "$test_dir/cs378x-control-test.c" "$repo_dir/util.c" \
        "$repo_dir/libfuncs/io.c" "$repo_dir/libfuncs/log.c" \
        "$repo_dir/libfuncs/queue.c" \
        "$repo_dir/libtsfuncs/log.c" \
        -Wl,--gc-sections -lcrypto -lpthread -o "$executable"
}

compile_test "$repo_dir/camd-cs378x.c" "$test_tmp/current-test"
"$test_tmp/current-test"

if [ "$check_upstream" -eq 1 ]; then
    upstream=f4876e84cf1866645f84b93f830af67193c85f69
    git -C "$repo_dir" show "$upstream:camd-cs378x.c" > "$test_tmp/upstream.c"
    compile_test "$test_tmp/upstream.c" "$test_tmp/upstream-test"
    result=0
    "$test_tmp/upstream-test" > "$test_tmp/upstream.log" 2>&1 || result=$?
    if [ "$result" -ne 1 ] ||
       ! grep -q '^FAIL extended announcement: reply 1 returned 0' "$test_tmp/upstream.log"; then
        cat "$test_tmp/upstream.log" >&2
        printf 'FAIL: expected the upstream receiver to reject 0x50 before the CW\n' >&2
        exit 1
    fi
    printf 'PASS regression check: the unpatched upstream receiver fails this scenario\n'
fi
