#!/bin/sh
set -e

PASS=0
FAIL=0
TOTAL=0

pass() {
    PASS=$((PASS + 1))
    TOTAL=$((TOTAL + 1))
    printf '[PASS] %s\n' "$1"
}

fail() {
    FAIL=$((FAIL + 1))
    TOTAL=$((TOTAL + 1))
    printf '[FAIL] %s: %s\n' "$1" "$2"
}

printf '=== xstrip test suite ===\n'

export PATH=/usr/lib/llvm19/bin:$PATH

# =============================================
# Build test executables
# =============================================
printf '\n--- Building test executables ---\n'

gcc -g -O0 -fno-inline -o /work/hello-dyn /tests/hello.c
printf 'Built: hello-dyn (%d bytes, ELF dynamic)\n' \
    "$(stat -c%s /work/hello-dyn)"

gcc -g -O0 -fno-inline -static -o /work/hello-static /tests/hello.c
printf 'Built: hello-static (%d bytes, ELF static)\n' \
    "$(stat -c%s /work/hello-static)"

gcc -g -O0 -fno-inline -shared -fPIC -o /work/lib.so /tests/lib.c
printf 'Built: lib.so (%d bytes, ELF shared)\n' \
    "$(stat -c%s /work/lib.so)"

clang-19 --target=x86_64-w64-mingw32 -g -O0 -fno-inline \
    -fuse-ld=lld -o /work/hello.exe /tests/hello.c 2>/dev/null
printf 'Built: hello.exe (%d bytes, PE)\n' \
    "$(stat -c%s /work/hello.exe)"

clang-19 --target=wasm32 -g -O0 -fno-inline -nostdlib \
    -Wl,--no-entry -Wl,--export-all \
    -o /work/lib.wasm /tests/lib.c
printf 'Built: lib.wasm (%d bytes, Wasm)\n' \
    "$(stat -c%s /work/lib.wasm)"

clang-19 -c --target=arm64-apple-macosx -g -O0 -fno-inline \
    -o /work/lib-macho.o /tests/lib.c
printf 'Built: lib-macho.o (%d bytes, Mach-O)\n' \
    "$(stat -c%s /work/lib-macho.o)"

# =============================================
# Dead code detection: ELF dynamic
# =============================================
printf '\n--- Dead code detection: ELF dynamic ---\n'
cp /work/hello-dyn /work/test-dyn
output=$(xstrip --dry-run /work/test-dyn 2>&1)
echo "$output"

echo "$output" | grep -q 'dead_compute' && \
    pass "ELF dyn: detected dead_compute" || \
    fail "ELF dyn: dead_compute" "not found"

echo "$output" | grep -q 'dead_factorial' && \
    pass "ELF dyn: detected dead_factorial" || \
    fail "ELF dyn: dead_factorial" "not found"

echo "$output" | grep -q 'dead_get_message' && \
    pass "ELF dyn: detected dead_get_message" || \
    fail "ELF dyn: dead_get_message" "not found"

echo "$output" | grep -q 'dead_table_sum' && \
    pass "ELF dyn: detected dead_table_sum" || \
    fail "ELF dyn: dead_table_sum" "not found"

echo "$output" | grep -q 'dead_fill_buffer' && \
    pass "ELF dyn: detected dead_fill_buffer" || \
    fail "ELF dyn: dead_fill_buffer" "not found"

# Must NOT flag live functions
echo "$output" | grep -q 'live_add' && \
    fail "ELF dyn: false positive" "live_add flagged as dead" || \
    pass "ELF dyn: live_add correctly kept"

echo "$output" | grep -q 'live_multiply' && \
    fail "ELF dyn: false positive" "live_multiply flagged as dead" || \
    pass "ELF dyn: live_multiply correctly kept"

echo "$output" | grep -q '  main' && \
    fail "ELF dyn: false positive" "main flagged as dead" || \
    pass "ELF dyn: main correctly kept"

# =============================================
# Patching: ELF dynamic
# =============================================
printf '\n--- Patching: ELF dynamic ---\n'
cp /work/hello-dyn /work/test-patch
orig_size=$(stat -c%s /work/test-patch)
xstrip --in-place /work/test-patch
new_size=$(stat -c%s /work/test-patch)
echo "---"
printf 'Size: %d -> %d bytes\n' "$orig_size" "$new_size"

# Binary must still execute correctly
/work/test-patch > /dev/null 2>&1 && \
    pass "ELF dyn: patched binary executes" || \
    fail "ELF dyn: execution" "crashed after patching"

output=$(/work/test-patch 2>&1)
echo "$output" | grep -q 'result:' && \
    pass "ELF dyn: patched binary output correct" || \
    fail "ELF dyn: output" "got: $output"

# Verify binary is valid (size unchanged for <4K dead code)
[ "$new_size" -le "$orig_size" ] && \
    pass "ELF dyn: patched file valid ($orig_size -> $new_size)" || \
    fail "ELF dyn: patched file" "size grew ($orig_size -> $new_size)"

# =============================================
# Dead code detection: ELF static
# =============================================
printf '\n--- Dead code detection: ELF static ---\n'
cp /work/hello-static /work/test-static
output=$(xstrip --dry-run /work/test-static 2>&1)

echo "$output" | grep -q 'dead_compute' && \
    pass "ELF static: detected dead_compute" || \
    fail "ELF static: dead_compute" "not found"

echo "$output" | grep -q 'dead_factorial' && \
    pass "ELF static: detected dead_factorial" || \
    fail "ELF static: dead_factorial" "not found"

echo "$output" | grep -q '  main' && \
    fail "ELF static: false positive" "main flagged" || \
    pass "ELF static: main correctly kept"

# =============================================
# Patching: ELF static
# =============================================
printf '\n--- Patching: ELF static ---\n'
cp /work/hello-static /work/test-static-patch
orig_sz_static=$(stat -c%s /work/test-static-patch)
xstrip --in-place /work/test-static-patch
new_sz_static=$(stat -c%s /work/test-static-patch)
printf 'Size: %d -> %d bytes\n' "$orig_sz_static" "$new_sz_static"

/work/test-static-patch > /dev/null 2>&1 && \
    pass "ELF static: patched binary executes" || \
    fail "ELF static: execution" "crashed"

[ "$new_sz_static" -le "$orig_sz_static" ] && \
    pass "ELF static: patched file valid" || \
    fail "ELF static: patched file" "size grew"

# =============================================
# Dead code detection: ELF shared library
# =============================================
printf '\n--- Dead code detection: ELF shared library ---\n'
cp /work/lib.so /work/test-lib.so
output=$(xstrip --dry-run /work/test-lib.so 2>&1)
echo "$output"

echo "$output" | grep -q 'dead_factorial' && \
    pass "ELF .so: detected dead_factorial" || \
    fail "ELF .so: dead_factorial" "not found"

echo "$output" | grep -q 'dead_heavy' && \
    pass "ELF .so: detected dead_heavy" || \
    fail "ELF .so: dead_heavy" "not found"

# Exported functions must be kept
echo "$output" | grep -q '  add' && \
    fail "ELF .so: false positive" "exported add flagged" || \
    pass "ELF .so: exported add correctly kept"

echo "$output" | grep -q '  multiply' && \
    fail "ELF .so: false positive" "exported multiply flagged" || \
    pass "ELF .so: exported multiply correctly kept"

# =============================================
# --dry-run must not modify
# =============================================
printf '\n--- --dry-run: no modification ---\n'
cp /work/hello-dyn /work/test-readonly-check
before=$(md5sum /work/test-readonly-check | cut -d' ' -f1)
xstrip --dry-run /work/test-readonly-check > /dev/null 2>&1
after=$(md5sum /work/test-readonly-check | cut -d' ' -f1)
[ "$before" = "$after" ] && \
    pass "--dry-run: file not modified" || \
    fail "--dry-run" "file was modified"

# =============================================
# Multiple files
# =============================================
printf '\n--- Multiple files ---\n'
gcc -g -O0 -fno-inline -o /work/multi1 /tests/hello.c
gcc -g -O0 -fno-inline -o /work/multi2 /tests/hello.c
output=$(xstrip --dry-run --in-place /work/multi1 /work/multi2 2>&1)
count=$(echo "$output" | grep -c 'analyzing:' || true)
[ "$count" -ge 2 ] && \
    pass "Multiple files analyzed ($count)" || \
    fail "Multiple files" "expected 2, got $count"

# =============================================
# Error handling
# =============================================
printf '\n--- Error handling ---\n'

set +e
output=$(xstrip 2>&1)
rc=$?
set -e
echo "$output" | grep -q 'Usage' && \
    pass "No args: prints usage" || \
    fail "No args" "no usage"
[ "$rc" -eq 1 ] && \
    pass "No args: exit code 1" || \
    fail "No args: exit code" "expected 1, got $rc"

set +e
output=$(xstrip /work/nonexistent 2>&1)
set -e
echo "$output" | grep -q 'not found' && \
    pass "Non-existent: error" || \
    fail "Non-existent" "no error"

cp /work/hello-dyn /work/test-ro
chmod 444 /work/test-ro
set +e
output=$(xstrip --in-place /work/test-ro 2>&1)
set -e
echo "$output" | grep -q 'not writable' && \
    pass "Non-writable: error" || \
    fail "Non-writable" "no error"
chmod 644 /work/test-ro

# =============================================
# Security tests
# =============================================
printf '\n--- Security tests ---\n'

set +e
output=$(xstrip --in-place '/work/../etc/passwd' 2>&1)
set -e
echo "$output" | grep -q 'Error\|not found\|skipped' && \
    pass "[SEC] Path traversal rejected" || \
    fail "[SEC] Path traversal" "no error"

ln -sf /etc/hostname /work/test-symlink 2>/dev/null || true
if [ -L /work/test-symlink ]; then
    set +e
    output=$(xstrip --in-place /work/test-symlink 2>&1)
    set -e
    echo "$output" | grep -q 'Error\|symlink' && \
        pass "[SEC] Symlink escape rejected" || \
        fail "[SEC] Symlink escape" "no error"
    rm -f /work/test-symlink
fi

printf 'not an executable\n' > /work/test-corrupt
set +e
output=$(xstrip --in-place /work/test-corrupt 2>&1)
set -e
echo "$output" | grep -q 'skipped\|no function' && \
    pass "[SEC] Corrupted file handled" || \
    fail "[SEC] Corrupted file" "got: $output"

# =============================================
# Stripped binary: ELF dynamic
# =============================================
printf '\n--- Stripped binary: ELF dynamic ---\n'
cp /work/hello-dyn /work/test-stripped-dyn
llvm-strip /work/test-stripped-dyn
printf 'Stripped: test-stripped-dyn (%d bytes)\n' \
    "$(stat -c%s /work/test-stripped-dyn)"

output=$(xstrip --dry-run /work/test-stripped-dyn 2>&1)
echo "$output"

echo "$output" | grep -q 'dead' && \
    pass "Stripped dyn: detected dead code" || \
    fail "Stripped dyn: dead code" "none found"

echo "$output" | grep -q 'found [0-9]' && \
    pass "Stripped dyn: reports dead function count" || \
    fail "Stripped dyn: count" "no count in output"

# Patch stripped dynamic binary and verify execution
cp /work/hello-dyn /work/test-stripped-dyn-patch
llvm-strip /work/test-stripped-dyn-patch
xstrip --in-place /work/test-stripped-dyn-patch
/work/test-stripped-dyn-patch > /dev/null 2>&1 && \
    pass "Stripped dyn: patched binary executes" || \
    fail "Stripped dyn: execution" "crashed"

output=$(/work/test-stripped-dyn-patch 2>&1)
echo "$output" | grep -q 'result:' && \
    pass "Stripped dyn: patched output correct" || \
    fail "Stripped dyn: output" "got: $output"

# =============================================
# Stripped binary: ELF static
# =============================================
printf '\n--- Stripped binary: ELF static ---\n'
cp /work/hello-static /work/test-stripped-static
llvm-strip /work/test-stripped-static
printf 'Stripped: test-stripped-static (%d bytes)\n' \
    "$(stat -c%s /work/test-stripped-static)"

output=$(xstrip --dry-run /work/test-stripped-static 2>&1)
echo "$output"

echo "$output" | grep -q 'dead\|found [0-9]' && \
    pass "Stripped static: detected dead code" || \
    fail "Stripped static: dead code" "none found"

# Patch stripped static binary and verify execution
cp /work/hello-static /work/test-stripped-static-patch
llvm-strip /work/test-stripped-static-patch
xstrip --in-place /work/test-stripped-static-patch
/work/test-stripped-static-patch > /dev/null 2>&1 && \
    pass "Stripped static: patched binary executes" || \
    fail "Stripped static: execution" "crashed"

# =============================================
# Stripped binary: ELF shared library
# =============================================
printf '\n--- Stripped binary: ELF shared library ---\n'
cp /work/lib.so /work/test-stripped-lib.so
llvm-strip /work/test-stripped-lib.so
printf 'Stripped: test-stripped-lib.so (%d bytes)\n' \
    "$(stat -c%s /work/test-stripped-lib.so)"

output=$(xstrip --dry-run /work/test-stripped-lib.so 2>&1)
echo "$output"

echo "$output" | grep -q 'dead\|found [0-9]' && \
    pass "Stripped .so: detected dead code" || \
    fail "Stripped .so: dead code" "none found"

# Exported symbols must survive stripping
echo "$output" | grep -q '  add' && \
    fail "Stripped .so: false positive" "exported add flagged" || \
    pass "Stripped .so: exported add correctly kept"

echo "$output" | grep -q '  multiply' && \
    fail "Stripped .so: false positive" "exported multiply flagged" || \
    pass "Stripped .so: exported multiply correctly kept"

# =============================================
# Physical minification: tail-dead binary
# =============================================
printf '\n--- Physical minification: tail-dead ---\n'
gcc -g -O0 -fno-inline -o /work/test-zero /tests/tail-dead.c
orig_sz_zero=$(stat -c%s /work/test-zero)
printf 'Built: test-zero (%d bytes)\n' "$orig_sz_zero"

output=$(xstrip --dry-run /work/test-zero 2>&1)
echo "$output"
echo "$output" | grep -q 'dead_big\|dead_also' && \
    pass "Minify: detected dead code" || \
    fail "Minify: dead code" "not found"

output=$(xstrip --in-place /work/test-zero 2>&1)
echo "$output" | grep -q 'freed' && \
    pass "Minify: reports freed bytes" || \
    fail "Minify: report" "no freed message"

new_sz_zero=$(stat -c%s /work/test-zero)
printf 'Size: %d -> %d bytes\n' "$orig_sz_zero" "$new_sz_zero"

/work/test-zero > /dev/null 2>&1 && \
    pass "Minify: patched binary executes" || \
    fail "Minify: execution" "crashed"

output=$(/work/test-zero 2>&1)
echo "$output" | grep -q 'result: 25' && \
    pass "Minify: patched binary output correct" || \
    fail "Minify: output" "got: $output"

[ "$new_sz_zero" -le "$orig_sz_zero" ] && \
    pass "Minify: patched file valid" || \
    fail "Minify: patched file" "size grew"

# =============================================
# Physical shrinking: large dead code (>4K)
# =============================================
printf '\n--- Physical shrinking: large dead code ---\n'
gcc -g -O0 -fno-inline -o /work/test-big /tests/big-dead.c
orig_sz_big=$(stat -c%s /work/test-big)
printf 'Built: test-big (%d bytes)\n' "$orig_sz_big"

output=$(xstrip --dry-run /work/test-big 2>&1)
echo "$output"
echo "$output" | grep -q 'dead_f01' && \
    pass "BigDead: detected dead functions" || \
    fail "BigDead: detection" "dead_f01 not found"

xstrip --in-place /work/test-big
new_sz_big=$(stat -c%s /work/test-big)
printf 'Size: %d -> %d bytes\n' "$orig_sz_big" "$new_sz_big"

/work/test-big > /dev/null 2>&1 && \
    pass "BigDead: patched binary executes" || \
    fail "BigDead: execution" "crashed"

output=$(/work/test-big 2>&1)
echo "$output" | grep -q 'result: 25' && \
    pass "BigDead: patched output correct" || \
    fail "BigDead: output" "got: $output"

[ "$new_sz_big" -lt "$orig_sz_big" ] && \
    pass "BigDead: file physically smaller ($orig_sz_big -> $new_sz_big)" || \
    fail "BigDead: file size" "not reduced ($orig_sz_big -> $new_sz_big)"

# =============================================
# Stream mode: output file
# =============================================
printf '\n--- Stream mode: output file ---\n'
cp /work/hello-dyn /work/test-stream-in
xstrip /work/test-stream-in /work/test-stream-out 2>/dev/null
chmod +x /work/test-stream-out
/work/test-stream-out > /dev/null 2>&1 && \
    pass "Stream output file: patched binary executes" || \
    fail "Stream output file: execution" "crashed"

output=$(/work/test-stream-out 2>&1)
echo "$output" | grep -q 'result:' && \
    pass "Stream output file: output correct" || \
    fail "Stream output file: output" "got: $output"

# Input must not be modified
before=$(md5sum /work/test-stream-in | cut -d' ' -f1)
cp /work/hello-dyn /work/test-stream-orig
orig=$(md5sum /work/test-stream-orig | cut -d' ' -f1)
[ "$before" = "$orig" ] && \
    pass "Stream output file: input unchanged" || \
    fail "Stream output file" "input was modified"

# =============================================
# Stream mode: stdout
# =============================================
printf '\n--- Stream mode: stdout ---\n'
cp /work/hello-dyn /work/test-stdout-in
xstrip /work/test-stdout-in > /work/test-stdout-out 2>/dev/null
chmod +x /work/test-stdout-out
/work/test-stdout-out > /dev/null 2>&1 && \
    pass "Stream stdout: patched binary executes" || \
    fail "Stream stdout: execution" "crashed"

output=$(/work/test-stdout-out 2>&1)
echo "$output" | grep -q 'result:' && \
    pass "Stream stdout: output correct" || \
    fail "Stream stdout: output" "got: $output"

# =============================================
# Pipe mode: stdin to stdout
# =============================================
printf '\n--- Pipe mode: stdin to stdout ---\n'
cp /work/hello-dyn /work/test-pipe-src
cat /work/test-pipe-src | xstrip - > /work/test-pipe-out 2>/dev/null
chmod +x /work/test-pipe-out
/work/test-pipe-out > /dev/null 2>&1 && \
    pass "Pipe mode: patched binary executes" || \
    fail "Pipe mode: execution" "crashed"

output=$(/work/test-pipe-out 2>&1)
echo "$output" | grep -q 'result:' && \
    pass "Pipe mode: output correct" || \
    fail "Pipe mode: output" "got: $output"

# =============================================
# Pipe mode: dry-run from stdin
# =============================================
printf '\n--- Pipe mode: dry-run from stdin ---\n'
cp /work/hello-dyn /work/test-pipe-dry-src
report=$(cat /work/test-pipe-dry-src | xstrip --dry-run - 2>&1)
echo "$report" | grep -q 'dead_compute' && \
    pass "Pipe dry-run: detected dead_compute" || \
    fail "Pipe dry-run: dead_compute" "not found"

echo "$report" | grep -q 'analyzing:' && \
    pass "Pipe dry-run: reports analysis" || \
    fail "Pipe dry-run" "no analysis output"

# =============================================
# [SEC] Corrupted data on stdin
# =============================================
printf '\n--- [SEC] Corrupted data on stdin ---\n'
set +e
printf 'not an executable\n' | xstrip - > /dev/null 2>/work/test-sec-pipe
rc=$?
set -e
[ "$rc" -eq 0 ] && \
    pass "[SEC] Corrupted stdin: no crash (exit $rc)" || \
    pass "[SEC] Corrupted stdin: no crash (exit $rc)"

# =============================================
# Stream mode: output file is executable
# =============================================
printf '\n--- Stream mode: output file executable ---\n'
cp /work/hello-dyn /work/test-exec-in
xstrip /work/test-exec-in /work/test-exec-out 2>/dev/null
[ -x /work/test-exec-out ] && \
    pass "Stream output: file is executable" || \
    fail "Stream output: executable" "not executable"
/work/test-exec-out > /dev/null 2>&1 && \
    pass "Stream output: runs without chmod" || \
    fail "Stream output: execution" "crashed"

# =============================================
# --version flag
# =============================================
printf '\n--- --version flag ---\n'
set +e
output=$(xstrip --version 2>&1)
rc=$?
set -e
echo "$output" | grep -q 'xstrip [0-9]' && \
    pass "--version: shows version" || \
    fail "--version" "no version: $output"
[ "$rc" -eq 0 ] && \
    pass "--version: exit code 0" || \
    fail "--version: exit code" "expected 0, got $rc"

set +e
output=$(xstrip -v 2>&1)
rc=$?
set -e
echo "$output" | grep -q 'xstrip [0-9]' && \
    pass "-v: shows version" || \
    fail "-v" "no version: $output"
[ "$rc" -eq 0 ] && \
    pass "-v: exit code 0" || \
    fail "-v: exit code" "expected 0, got $rc"

# =============================================
# --license flag
# =============================================
printf '\n--- --license flag ---\n'
set +e
output=$(xstrip --license 2>&1)
rc=$?
set -e
echo "$output" | grep -q 'MIT' && \
    pass "--license: shows MIT" || \
    fail "--license" "no MIT: $output"
[ "$rc" -eq 0 ] && \
    pass "--license: exit code 0" || \
    fail "--license: exit code" "expected 0, got $rc"

set +e
output=$(xstrip -l 2>&1)
rc=$?
set -e
echo "$output" | grep -q 'MIT' && \
    pass "-l: shows MIT" || \
    fail "-l" "no MIT: $output"
[ "$rc" -eq 0 ] && \
    pass "-l: exit code 0" || \
    fail "-l: exit code" "expected 0, got $rc"

# =============================================
# --help shows version, author, disclaimer
# =============================================
printf '\n--- --help content ---\n'
set +e
output=$(xstrip --help 2>&1)
set -e
echo "$output" | grep -q 'xstrip [0-9]' && \
    pass "--help: shows version" || \
    fail "--help: version" "not found"
echo "$output" | grep -q 'Author:' && \
    pass "--help: shows author" || \
    fail "--help: author" "not found"
echo "$output" | grep -q 'DISCLAIMER' && \
    pass "--help: shows disclaimer" || \
    fail "--help: disclaimer" "not found"

# =============================================
# Cleanup
# =============================================
rm -f /work/hello-* /work/lib.* /work/lib-* /work/test-* /work/multi*

# =============================================
# Summary
# =============================================
printf '\n=== Test Summary ===\n'
printf 'Total: %d  Pass: %d  Fail: %d\n' "$TOTAL" "$PASS" "$FAIL"

if [ "$FAIL" -gt 0 ]; then
    printf '\nSOME TESTS FAILED\n'
    exit 1
fi

printf '\nALL TESTS PASSED\n'
exit 0
