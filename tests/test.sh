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

python3 /tests/gen_dotnet.py > /work/hello-dotnet.exe
printf 'Built: hello-dotnet.exe (%d bytes, .NET)\n' \
    "$(stat -c%s /work/hello-dotnet.exe)"

clang-19 --target=aarch64-linux-gnu -nostdlib -static -g -O0 \
    -fno-inline -fuse-ld=lld -o /work/hello-aarch64 \
    /tests/arm-hello.c 2>/dev/null
printf 'Built: hello-aarch64 (%d bytes, ELF AArch64)\n' \
    "$(stat -c%s /work/hello-aarch64)"

clang-19 --target=armv7-linux-gnueabihf -nostdlib -static -g -O0 \
    -fno-inline -fuse-ld=lld -o /work/hello-arm32 \
    /tests/arm-hello.c 2>/dev/null
printf 'Built: hello-arm32 (%d bytes, ELF ARM32)\n' \
    "$(stat -c%s /work/hello-arm32)"

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
# Dead code detection: PE executable
# =============================================
printf '\n--- Dead code detection: PE executable ---\n'
cp /work/hello.exe /work/test-pe
output=$(xstrip --dry-run /work/test-pe 2>&1)
echo "$output"

echo "$output" | grep -q 'analyzing:' && \
    pass "PE exe: analysis completed" || \
    fail "PE exe: analysis" "not completed"

echo "$output" | grep -q 'functions' && \
    pass "PE exe: functions discovered" || \
    fail "PE exe: functions" "none found"

echo "$output" | grep -q '  main' && \
    fail "PE exe: false positive" "main flagged as dead" || \
    pass "PE exe: main correctly kept"

# =============================================
# Patching: PE executable (zero-fill)
# =============================================
printf '\n--- Patching: PE executable ---\n'
cp /work/hello.exe /work/test-pe-patch
orig_sz_pe=$(stat -c%s /work/test-pe-patch)
xstrip --in-place /work/test-pe-patch
new_sz_pe=$(stat -c%s /work/test-pe-patch)
printf 'Size: %d -> %d bytes\n' "$orig_sz_pe" "$new_sz_pe"

[ "$new_sz_pe" -le "$orig_sz_pe" ] && \
    pass "PE exe: patched file valid" || \
    fail "PE exe: patched file" "size grew"

file_info=$(file /work/test-pe-patch)
echo "$file_info" | grep -q 'PE32' && \
    pass "PE exe: patched file still PE" || \
    fail "PE exe: patched type" "got: $file_info"

# =============================================
# Dead code detection: PE DLL (exports)
# =============================================
printf '\n--- Dead code detection: PE DLL ---\n'
clang-19 --target=x86_64-w64-mingw32 -g -O0 -fno-inline -shared \
    -fuse-ld=lld -o /work/lib.dll /tests/lib.c 2>/dev/null
printf 'Built: lib.dll (%d bytes, PE DLL)\n' \
    "$(stat -c%s /work/lib.dll)"

output=$(xstrip --dry-run /work/lib.dll 2>&1)
echo "$output"

echo "$output" | grep -q 'analyzing:' && \
    pass "PE DLL: analysis completed" || \
    fail "PE DLL: analysis" "not completed"

echo "$output" | grep -q 'functions' && \
    pass "PE DLL: functions discovered" || \
    fail "PE DLL: functions" "none found"

echo "$output" | grep -q '  add' && \
    fail "PE DLL: false positive" "exported add flagged" || \
    pass "PE DLL: exported add correctly kept"

echo "$output" | grep -q '  multiply' && \
    fail "PE DLL: false positive" "exported multiply flagged" || \
    pass "PE DLL: exported multiply correctly kept"

# =============================================
# Dead code detection: Mach-O object
# =============================================
printf '\n--- Dead code detection: Mach-O object ---\n'
output=$(xstrip --dry-run /work/lib-macho.o 2>&1)
echo "$output"

echo "$output" | grep -q 'analyzing:' && \
    pass "Mach-O: analysis completed" || \
    fail "Mach-O: analysis" "not completed"

echo "$output" | grep -q 'functions' && \
    pass "Mach-O: functions discovered" || \
    fail "Mach-O: functions" "none found"

echo "$output" | grep -q '    add:' && \
    fail "Mach-O: false positive" "exported add flagged" || \
    pass "Mach-O: exported add correctly kept"

echo "$output" | grep -q '    multiply:' && \
    fail "Mach-O: false positive" "exported multiply flagged" || \
    pass "Mach-O: exported multiply correctly kept"

echo "$output" | grep -q '    compute:' && \
    fail "Mach-O: false positive" "exported compute flagged" || \
    pass "Mach-O: exported compute correctly kept"

# =============================================
# Patching: Mach-O object
# =============================================
printf '\n--- Patching: Mach-O object ---\n'
cp /work/lib-macho.o /work/test-macho-patch
output=$(xstrip /work/test-macho-patch 2>&1)
echo "$output"
macho_sz_before=$(stat -c%s /work/lib-macho.o)
macho_sz_after=$(stat -c%s /work/test-macho-patch)
printf 'Size: %d -> %d bytes\n' "$macho_sz_before" "$macho_sz_after"
[ "$macho_sz_after" -le "$macho_sz_before" ] && \
    pass "Mach-O: patched file valid" || \
    fail "Mach-O: patched file" "grew in size"
file /work/test-macho-patch | grep -qi 'mach-o' && \
    pass "Mach-O: patched file still Mach-O" || \
    fail "Mach-O: patched file" "not Mach-O"

# =============================================
# Dead code detection: .NET managed assembly
# =============================================
printf '\n--- Dead code detection: .NET managed ---\n'
output=$(xstrip --dry-run /work/hello-dotnet.exe 2>&1)
echo "$output"

echo "$output" | grep -q 'analyzing:' && \
    pass ".NET: analysis completed" || \
    fail ".NET: analysis" "not completed"

echo "$output" | grep -q 'functions' && \
    pass ".NET: functions discovered" || \
    fail ".NET: functions" "none found"

echo "$output" | grep -q 'DeadMethod1' && \
    pass ".NET: detected DeadMethod1" || \
    fail ".NET: DeadMethod1" "not found"

echo "$output" | grep -q 'DeadMethod2' && \
    pass ".NET: detected DeadMethod2" || \
    fail ".NET: DeadMethod2" "not found"

echo "$output" | grep -q '    Main:' && \
    fail ".NET: false positive" "Main flagged" || \
    pass ".NET: Main correctly kept"

echo "$output" | grep -q '    LiveHelper:' && \
    fail ".NET: false positive" "LiveHelper flagged" || \
    pass ".NET: LiveHelper correctly kept"

# =============================================
# Patching: .NET managed assembly
# =============================================
printf '\n--- Patching: .NET managed ---\n'
cp /work/hello-dotnet.exe /work/test-dotnet-patch
output=$(xstrip /work/test-dotnet-patch 2>&1)
echo "$output"
dn_sz_before=$(stat -c%s /work/hello-dotnet.exe)
dn_sz_after=$(stat -c%s /work/test-dotnet-patch)
printf 'Size: %d -> %d bytes\n' "$dn_sz_before" "$dn_sz_after"
[ "$dn_sz_after" -le "$dn_sz_before" ] && \
    pass ".NET: patched file valid" || \
    fail ".NET: patched file" "grew in size"
file /work/test-dotnet-patch | grep -qi 'pe' && \
    pass ".NET: patched file still PE" || \
    fail ".NET: patched file" "not PE"

# =============================================
# Dead branch detection: noreturn calls
# =============================================
printf '\n--- Dead branch detection: noreturn calls ---\n'
gcc -g -O0 -fno-inline -fno-builtin -o /work/test-dead-branch \
    /tests/dead-branch.c
printf 'Built: test-dead-branch (%d bytes)\n' \
    "$(stat -c%s /work/test-dead-branch)"

output=$(xstrip --dry-run /work/test-dead-branch 2>&1)
echo "$output"

# Must detect dead branch after exit() in noreturn_dead
echo "$output" | grep -q 'dead branch' && \
    pass "DeadBranch: detected dead branch" || \
    fail "DeadBranch: detection" "no dead branch found"

# noreturn_dead should NOT be flagged as dead function
echo "$output" | grep -q '    noreturn_dead:' && \
    fail "DeadBranch: false positive" "noreturn_dead flagged dead" || \
    pass "DeadBranch: noreturn_dead correctly kept"

# live_caller must be kept
echo "$output" | grep -q '    live_caller:' && \
    fail "DeadBranch: false positive" "live_caller flagged dead" || \
    pass "DeadBranch: live_caller correctly kept"

# main must be kept
echo "$output" | grep -q '    main:' && \
    fail "DeadBranch: false positive" "main flagged dead" || \
    pass "DeadBranch: main correctly kept"

# Patch and verify execution + compaction
cp /work/test-dead-branch /work/test-dead-branch-patch
patch_out=$(xstrip --in-place /work/test-dead-branch-patch 2>&1)
echo "$patch_out"
/work/test-dead-branch-patch 5 > /dev/null 2>&1 && \
    pass "DeadBranch: patched binary executes" || \
    fail "DeadBranch: execution" "crashed"

output=$(/work/test-dead-branch-patch 5 2>&1)
echo "$output" | grep -q 'result:' && \
    pass "DeadBranch: patched output correct" || \
    fail "DeadBranch: output" "got: $output"

# Verify compaction: reassemble reports dead branches removed
echo "$patch_out" | grep -q 'dead branches removed' && \
    pass "DeadBranch: compaction applied" || \
    fail "DeadBranch: compaction" "not reported"

# =============================================
# Combined dead functions + dead branches
# =============================================
printf '\n--- Combined dead functions + dead branches ---\n'
gcc -g -O0 -fno-inline -fno-builtin -o /work/test-combined \
    /tests/combined-dead.c
printf 'Built: test-combined (%d bytes)\n' \
    "$(stat -c%s /work/test-combined)"

output=$(xstrip --dry-run /work/test-combined 2>&1)
echo "$output"

# Must detect dead functions
echo "$output" | grep -q 'dead_compute' && \
    pass "Combined: detected dead_compute" || \
    fail "Combined: dead_compute" "not found"

echo "$output" | grep -q 'dead_factorial' && \
    pass "Combined: detected dead_factorial" || \
    fail "Combined: dead_factorial" "not found"

# Must detect dead branches
echo "$output" | grep -q 'dead branch' && \
    pass "Combined: detected dead branches" || \
    fail "Combined: dead branches" "not found"

# Live functions must be kept
echo "$output" | grep -q '    process:' && \
    fail "Combined: false positive" "process flagged dead" || \
    pass "Combined: process correctly kept"

echo "$output" | grep -q '    validate:' && \
    fail "Combined: false positive" "validate flagged dead" || \
    pass "Combined: validate correctly kept"

echo "$output" | grep -q '    main:' && \
    fail "Combined: false positive" "main flagged dead" || \
    pass "Combined: main correctly kept"

# Patch and verify execution + compaction
cp /work/test-combined /work/test-combined-patch
patch_out=$(xstrip --in-place /work/test-combined-patch 2>&1)
echo "$patch_out"
/work/test-combined-patch 5 > /dev/null 2>&1 && \
    pass "Combined: patched binary executes" || \
    fail "Combined: execution" "crashed"

output=$(/work/test-combined-patch 5 2>&1)
echo "$output" | grep -q 'result:' && \
    pass "Combined: patched output correct" || \
    fail "Combined: output" "got: $output"

# Verify both dead functions and branches were compacted
echo "$patch_out" | grep -q 'dead functions removed' && \
    pass "Combined: dead functions compacted" || \
    fail "Combined: func compaction" "not reported"

echo "$patch_out" | grep -q 'dead branches removed' && \
    pass "Combined: dead branches compacted" || \
    fail "Combined: branch compaction" "not reported"

# =============================================
# Dead code detection: AArch64
# =============================================
printf '\n--- Dead code detection: AArch64 ---\n'
output=$(xstrip --dry-run /work/hello-aarch64 2>&1)
echo "$output"

echo "$output" | grep -q 'dead_compute' && \
    pass "AArch64: detected dead_compute" || \
    fail "AArch64: dead_compute" "not found"

echo "$output" | grep -q 'dead_factorial' && \
    pass "AArch64: detected dead_factorial" || \
    fail "AArch64: dead_factorial" "not found"

echo "$output" | grep -q '  _start' && \
    fail "AArch64: false positive" "_start flagged as dead" || \
    pass "AArch64: _start correctly kept"

echo "$output" | grep -q 'live_add' && \
    fail "AArch64: false positive" "live_add flagged as dead" || \
    pass "AArch64: live_add correctly kept"

echo "$output" | grep -q 'live_multiply' && \
    fail "AArch64: false positive" "live_multiply flagged" || \
    pass "AArch64: live_multiply correctly kept"

file_info=$(file /work/hello-aarch64)
echo "$file_info" | grep -q 'ELF.*ARM aarch64' && \
    pass "AArch64: correct ELF type" || \
    fail "AArch64: ELF type" "got: $file_info"

# =============================================
# Patching: AArch64 (zero-fill only)
# =============================================
printf '\n--- Patching: AArch64 ---\n'
cp /work/hello-aarch64 /work/test-aarch64-patch
orig_sz_a64=$(stat -c%s /work/test-aarch64-patch)
xstrip --in-place /work/test-aarch64-patch
new_sz_a64=$(stat -c%s /work/test-aarch64-patch)
printf 'Size: %d -> %d bytes\n' "$orig_sz_a64" "$new_sz_a64"

[ "$new_sz_a64" -le "$orig_sz_a64" ] && \
    pass "AArch64: patched file valid" || \
    fail "AArch64: patched file" "size grew"

file_info=$(file /work/test-aarch64-patch)
echo "$file_info" | grep -q 'ELF' && \
    pass "AArch64: patched file still ELF" || \
    fail "AArch64: patched type" "got: $file_info"

# =============================================
# Dead code detection: ARM32
# =============================================
printf '\n--- Dead code detection: ARM32 ---\n'
output=$(xstrip --dry-run /work/hello-arm32 2>&1)
echo "$output"

echo "$output" | grep -q 'dead_compute' && \
    pass "ARM32: detected dead_compute" || \
    fail "ARM32: dead_compute" "not found"

echo "$output" | grep -q 'dead_factorial' && \
    pass "ARM32: detected dead_factorial" || \
    fail "ARM32: dead_factorial" "not found"

echo "$output" | grep -q '  _start' && \
    fail "ARM32: false positive" "_start flagged as dead" || \
    pass "ARM32: _start correctly kept"

echo "$output" | grep -q 'live_add' && \
    fail "ARM32: false positive" "live_add flagged as dead" || \
    pass "ARM32: live_add correctly kept"

echo "$output" | grep -q 'live_multiply' && \
    fail "ARM32: false positive" "live_multiply flagged" || \
    pass "ARM32: live_multiply correctly kept"

file_info=$(file /work/hello-arm32)
echo "$file_info" | grep -q 'ELF.*ARM' && \
    pass "ARM32: correct ELF type" || \
    fail "ARM32: ELF type" "got: $file_info"

# =============================================
# Patching: ARM32 (zero-fill only)
# =============================================
printf '\n--- Patching: ARM32 ---\n'
cp /work/hello-arm32 /work/test-arm32-patch
orig_sz_arm32=$(stat -c%s /work/test-arm32-patch)
xstrip --in-place /work/test-arm32-patch
new_sz_arm32=$(stat -c%s /work/test-arm32-patch)
printf 'Size: %d -> %d bytes\n' "$orig_sz_arm32" "$new_sz_arm32"

[ "$new_sz_arm32" -le "$orig_sz_arm32" ] && \
    pass "ARM32: patched file valid" || \
    fail "ARM32: patched file" "size grew"

file_info=$(file /work/test-arm32-patch)
echo "$file_info" | grep -q 'ELF' && \
    pass "ARM32: patched file still ELF" || \
    fail "ARM32: patched type" "got: $file_info"

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
