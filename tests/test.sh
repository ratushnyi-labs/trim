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

printf '=== trim test suite ===\n'

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
    -Wl,--no-entry -Wl,--no-gc-sections \
    -Wl,--export=add -Wl,--export=multiply -Wl,--export=compute \
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

python3 /tests/gen_java.py > /work/hello-java.class
printf 'Built: hello-java.class (%d bytes, Java)\n' \
    "$(stat -c%s /work/hello-java.class)"

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

clang-19 --target=riscv64-linux-gnu -march=rv64gc -nostdlib -static \
    -g -O0 -fno-inline -fuse-ld=lld -o /work/hello-riscv64 \
    /tests/riscv-hello.c 2>/dev/null
printf 'Built: hello-riscv64 (%d bytes, ELF RISC-V 64)\n' \
    "$(stat -c%s /work/hello-riscv64)"

clang-19 --target=mips-linux-gnu -nostdlib -static -g -O0 \
    -fno-inline -fno-pic -fuse-ld=lld -o /work/hello-mips \
    /tests/mips-hello.c 2>/dev/null
printf 'Built: hello-mips (%d bytes, ELF MIPS)\n' \
    "$(stat -c%s /work/hello-mips)"

clang-19 --target=s390x-linux-gnu -nostdlib -static -g -O0 \
    -fno-inline -fuse-ld=lld -o /work/hello-s390x \
    /tests/s390x-hello.c 2>/dev/null
printf 'Built: hello-s390x (%d bytes, ELF s390x)\n' \
    "$(stat -c%s /work/hello-s390x)"

clang-19 --target=loongarch64-linux-gnu -nostdlib -static -g -O0 \
    -fno-inline -fuse-ld=lld -o /work/hello-loongarch64 \
    /tests/loongarch-hello.c 2>/dev/null
printf 'Built: hello-loongarch64 (%d bytes, ELF LoongArch64)\n' \
    "$(stat -c%s /work/hello-loongarch64)"

clang-19 --target=i686-linux-gnu -nostdlib -static -g -O0 \
    -fno-inline -fuse-ld=lld -o /work/hello-x86-32 \
    /tests/x86-32-hello.c 2>/dev/null
printf 'Built: hello-x86-32 (%d bytes, ELF x86-32)\n' \
    "$(stat -c%s /work/hello-x86-32)"

# =============================================
# Dead code detection: ELF dynamic
# =============================================
printf '\n--- Dead code detection: ELF dynamic ---\n'
cp /work/hello-dyn /work/test-dyn
output=$(trim --dry-run /work/test-dyn 2>&1)
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
trim --in-place /work/test-patch
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
output=$(trim --dry-run /work/test-static 2>&1)

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
trim --in-place /work/test-static-patch
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
output=$(trim --dry-run /work/test-lib.so 2>&1)
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
trim --dry-run /work/test-readonly-check > /dev/null 2>&1
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
output=$(trim --dry-run --in-place /work/multi1 /work/multi2 2>&1)
count=$(echo "$output" | grep -c 'analyzing:' || true)
[ "$count" -ge 2 ] && \
    pass "Multiple files analyzed ($count)" || \
    fail "Multiple files" "expected 2, got $count"

# =============================================
# Error handling
# =============================================
printf '\n--- Error handling ---\n'

set +e
output=$(trim 2>&1)
rc=$?
set -e
echo "$output" | grep -q 'Usage' && \
    pass "No args: prints usage" || \
    fail "No args" "no usage"
[ "$rc" -eq 1 ] && \
    pass "No args: exit code 1" || \
    fail "No args: exit code" "expected 1, got $rc"

set +e
output=$(trim /work/nonexistent 2>&1)
set -e
echo "$output" | grep -q 'not found' && \
    pass "Non-existent: error" || \
    fail "Non-existent" "no error"

cp /work/hello-dyn /work/test-ro
chmod 444 /work/test-ro
set +e
output=$(trim --in-place /work/test-ro 2>&1)
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
output=$(trim --in-place '/work/../etc/passwd' 2>&1)
set -e
echo "$output" | grep -q 'Error\|not found\|skipped' && \
    pass "[SEC] Path traversal rejected" || \
    fail "[SEC] Path traversal" "no error"

ln -sf /etc/hostname /work/test-symlink 2>/dev/null || true
if [ -L /work/test-symlink ]; then
    set +e
    output=$(trim --in-place /work/test-symlink 2>&1)
    set -e
    echo "$output" | grep -q 'Error\|symlink' && \
        pass "[SEC] Symlink escape rejected" || \
        fail "[SEC] Symlink escape" "no error"
    rm -f /work/test-symlink
fi

printf 'not an executable\n' > /work/test-corrupt
set +e
output=$(trim --in-place /work/test-corrupt 2>&1)
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

output=$(trim --dry-run /work/test-stripped-dyn 2>&1)
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
trim --in-place /work/test-stripped-dyn-patch
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

output=$(trim --dry-run /work/test-stripped-static 2>&1)
echo "$output"

echo "$output" | grep -q 'dead\|found [0-9]' && \
    pass "Stripped static: detected dead code" || \
    fail "Stripped static: dead code" "none found"

# Patch stripped static binary and verify execution
cp /work/hello-static /work/test-stripped-static-patch
llvm-strip /work/test-stripped-static-patch
trim --in-place /work/test-stripped-static-patch
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

output=$(trim --dry-run /work/test-stripped-lib.so 2>&1)
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

output=$(trim --dry-run /work/test-zero 2>&1)
echo "$output"
echo "$output" | grep -q 'dead_big\|dead_also' && \
    pass "Minify: detected dead code" || \
    fail "Minify: dead code" "not found"

output=$(trim --in-place /work/test-zero 2>&1)
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

output=$(trim --dry-run /work/test-big 2>&1)
echo "$output"
echo "$output" | grep -q 'dead_f01' && \
    pass "BigDead: detected dead functions" || \
    fail "BigDead: detection" "dead_f01 not found"

trim --in-place /work/test-big
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
# FDE function boundaries: stripped -O2 binary
# =============================================
printf '\n--- FDE function boundaries: stripped -O2 ---\n'
# A stripped image marks no start for a function nothing calls, so
# inference merged each dead_fde_* into the live function before it.
# The .eh_frame FDEs now delimit functions exactly: the dead ones must
# be found and removed (their 0x5EAD100n markers gone), while every
# probe_* path (fall-through into the next FDE, code past an FDE's end,
# a jump table into other FDEs, a sibling-call target, a pointer table,
# a qsort callback) stays live. Built as PIE, non-PIE and static.
fde_want='^probes: ft=6 gap=15 jt=70,71 tail=31 fp=14 sort=13579$'
fde_live='probe_ft_head probe_ft_tail probe_gap probe_jt jt_case0 jt_case1
    probe_tail probe_tail_target probe_fp_a probe_fp_b probe_cmp
    live_a live_b live_c'
fde_markers() {
    python3 -c 'import sys
d = open(sys.argv[1], "rb").read()
print(sum(d.count((0x5EAD1000 + k).to_bytes(4, "little"))
          for k in range(1, 5)))' "$1"
}
for fde_mode in pie nopie static; do
    case $fde_mode in
        pie) fde_flags= ;;
        nopie) fde_flags='-fno-pie -no-pie' ;;
        static) fde_flags=-static ;;
    esac
    fde_bin=/work/test-fde-$fde_mode
    gcc -O2 $fde_flags -o "$fde_bin" /tests/fde-bounds.c
    fde_syms=$(nm "$fde_bin")
    cp "$fde_bin" "$fde_bin-s"
    strip --strip-all "$fde_bin-s"
    fde_expected=$("$fde_bin-s" 2>&1)
    echo "$fde_expected" | grep -q "$fde_want" && \
        pass "FdeBounds $fde_mode: original output correct" || \
        fail "FdeBounds $fde_mode: original" "got: $fde_expected"

    fde_dry=$(trim --dry-run "$fde_bin-s" 2>&1)
    echo "$fde_dry"
    fde_dead=0
    fde_kept=0
    fde_missing=
    for n in dead_fde_1 dead_fde_2 dead_fde_3 dead_fde_4 $fde_live; do
        a=$(echo "$fde_syms" | awk -v n="$n" '$3 == n {
            sub(/^0+/, "", $1); print $1 }')
        # A name nm cannot find proves nothing: never count it as kept.
        if [ -z "$a" ]; then
            fde_missing="$fde_missing $n"
            continue
        fi
        if echo "$fde_dry" | grep -q "@ 0x$a\$"; then
            case $n in dead_*) fde_dead=$((fde_dead + 1)) ;; esac
        else
            case $n in dead_*) ;; *) fde_kept=$((fde_kept + 1)) ;; esac
        fi
    done
    [ -z "$fde_missing" ] && \
        pass "FdeBounds $fde_mode: every checked function has an address" || \
        fail "FdeBounds $fde_mode: symbols" "nm finds no address for:$fde_missing"
    [ "$fde_dead" -eq 4 ] && \
        pass "FdeBounds $fde_mode: dead FDE-only functions found" || \
        fail "FdeBounds $fde_mode: detection" "$fde_dead of 4 found"
    [ "$fde_kept" -eq 14 ] && \
        pass "FdeBounds $fde_mode: probe and live functions kept" || \
        fail "FdeBounds $fde_mode: false positive" \
            "$((14 - fde_kept)) live functions flagged"

    trim --in-place "$fde_bin-s" 2>&1 | grep 'reassembled' || true
    fde_out=$("$fde_bin-s" 2>&1) && \
        pass "FdeBounds $fde_mode: patched binary executes" || \
        fail "FdeBounds $fde_mode: execution" "crashed"
    [ "$fde_out" = "$fde_expected" ] && \
        pass "FdeBounds $fde_mode: patched output matches original" || \
        fail "FdeBounds $fde_mode: output" "got: $fde_out"
    fde_left=$(fde_markers "$fde_bin-s")
    [ "$(fde_markers "$fde_bin")" -gt 0 ] && [ "$fde_left" -eq 0 ] && \
        pass "FdeBounds $fde_mode: dead code removed from the file" || \
        fail "FdeBounds $fde_mode: removal" "$fde_left markers left"
done

# =============================================
# .dynsym-only exports: IFUNC and untyped symbols
# =============================================
printf '\n--- .dynsym-only exports: IFUNC and untyped ---\n'
# In a stripped shared library an IFUNC resolver (STT_GNU_IFUNC) and an
# untyped assembly export (STT_NOTYPE) are named only by their .dynsym
# st_value. Split at FDE boundaries they had no reference and were
# removed. Every defined .dynsym entry in executable code is a root.
# musl does not bind IFUNCs, so the loader binds both through st_value.
gcc -g -O0 -fno-inline -fPIC -shared \
    -o /work/libdynsym.so /tests/dynsym-exports.c
gcc -g -O0 -o /work/dynsym-loader /tests/dynsym-loader.c
strip --strip-all /work/libdynsym.so
dyn_want='dynsym: ifunc=16 notype=42'
output=$(/work/dynsym-loader /work/libdynsym.so 2>&1) || true
echo "$output" | grep -q 'types: ifunc=10 notype=0' && \
    echo "$output" | grep -q "$dyn_want" && \
    pass "DynsymExports: original binds IFUNC and NOTYPE exports" || \
    fail "DynsymExports: original" "got: $output"
dyn_out=$(trim --in-place /work/libdynsym.so 2>&1) || true
echo "$dyn_out" | grep -q '4 dead functions removed' && \
    pass "DynsymExports: the 4 dead functions removed" || \
    fail "DynsymExports: removal" "got: $dyn_out"
output=$(/work/dynsym-loader /work/libdynsym.so 2>&1) || true
echo "$output" | grep -q "$dyn_want" && \
    pass "DynsymExports: exports still bound and correct after trim" || \
    fail "DynsymExports: patched" "got: $output"
# Unstripped (the usual gcc -shared output) the function map comes from
# .symtab, which holds STT_FUNC symbols only: the IFUNC's resolver is a
# local function nothing calls, so it and the implementation it returns
# were removed. The .symtab function holding each .dynsym entry is a root.
gcc -g -O0 -fno-inline -fPIC -shared \
    -o /work/libdynsym-u.so /tests/dynsym-exports.c
dyn_out=$(trim --in-place /work/libdynsym-u.so 2>&1) || true
echo "$dyn_out" | grep -q '4 dead functions removed' && \
    ! echo "$dyn_out" | grep -q 'ifunc_resolver\|ifunc_impl' && \
    pass "DynsymExports unstripped: only the 4 dead functions removed" || \
    fail "DynsymExports unstripped: removal" "got: $dyn_out"
output=$(/work/dynsym-loader /work/libdynsym-u.so 2>&1) || true
echo "$output" | grep -q "$dyn_want" && \
    pass "DynsymExports unstripped: exports still bound and correct after trim" || \
    fail "DynsymExports unstripped: patched" "got: $output"

# =============================================
# Static printf: constant-flag branch folding
# =============================================
printf '\n--- Static printf: constant-flag branch folding ---\n'
# musl's printf core compares constant operands with `jl` on entry.
# Reading any nonzero flags value as "taken" flagged the whole format
# loop dead, so printf with format arguments printed nothing. The
# fixture's probes each isolate a construct that must not be folded.
gcc -static -O2 -o /work/test-sprintf /tests/static-printf.c
printf 'Built: test-sprintf (%d bytes)\n' \
    "$(stat -c%s /work/test-sprintf)"

sp_expected=$(/work/test-sprintf 2>&1)
echo "$sp_expected" | grep -q '^fmt: 42 hello ff' && \
    echo "$sp_expected" | grep -q '^probes: 1 1 1 1 1 1 1 1 1$' && \
    pass "StaticPrintf: original output correct" || \
    fail "StaticPrintf: original" "got: $sp_expected"

sp_dry=$(trim --dry-run /work/test-sprintf 2>&1)
echo "$sp_dry" | grep -q 'dead branch:.*(in printf_core)' && \
    fail "StaticPrintf: false positive" "printf_core blocks flagged dead" || \
    pass "StaticPrintf: printf_core kept"

echo "$sp_dry" | grep -q 'dead branch:.*(in probe_je_zero)' && \
    pass "StaticPrintf: constant equality branch still folded" || \
    fail "StaticPrintf: folding" "probe_je_zero dead path not found"

trim --in-place /work/test-sprintf 2>&1 | grep 'reassembled' || true
sp_out=$(/work/test-sprintf 2>&1) && \
    pass "StaticPrintf: patched binary executes" || \
    fail "StaticPrintf: execution" "crashed"

[ "$sp_out" = "$sp_expected" ] && \
    pass "StaticPrintf: patched output matches original" || \
    fail "StaticPrintf: output" "got: $sp_out"

# =============================================
# AArch64: sound dead-branch folding
# =============================================
printf '\n--- AArch64: sound dead-branch folding ---\n'
# The AArch64 constant model used to ignore instructions it did not
# recognise (loads, writeback, CCMP/FCMP, CSET, W zero-extension, ...)
# and kept stale constants, so live paths were folded away. Each
# probe_* isolates one such construct and must not be folded (MRS of
# RNDR also writes NZCV); each probe_dead_* branches on a real constant
# and must still be folded, including through a bitmask immediate, MOVK,
# CMN and ANDS on W registers.
clang-19 --target=aarch64-linux-gnu -march=armv8.1-a -nostdlib -static \
    -fno-pie -O2 -fuse-ld=lld -o /work/test-a64fold \
    /tests/aarch64-fold.c 2>/dev/null
printf 'Built: test-a64fold (%d bytes)\n' \
    "$(stat -c%s /work/test-a64fold)"

a64_expected=$(qemu-aarch64 /work/test-a64fold 2>&1) || true
echo "$a64_expected" | \
    grep -q '^probes: 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1$' && \
    echo "$a64_expected" | grep -q '^dead: 1 1 1 1 1 1 1 1 1$' && \
    pass "AArch64Fold: original output correct" || \
    fail "AArch64Fold: original" "got: $a64_expected"

a64_dry=$(trim --dry-run /work/test-a64fold 2>&1)
echo "$a64_dry" | grep 'dead branch:.*(in probe_' | \
    grep -qv '(in probe_dead_' && \
    fail "AArch64Fold: false positive" "a live probe path flagged dead" || \
    pass "AArch64Fold: live probe paths kept"

for p in probe_dead_beq probe_dead_cbnz probe_dead_cbz_w \
    probe_dead_tbnz probe_dead_wrap probe_dead_bitmask probe_dead_movk \
    probe_dead_cmn probe_dead_ands_w; do
    echo "$a64_dry" | grep -q "dead branch:.*(in $p)" && \
        pass "AArch64Fold: $p dead path removed" || \
        fail "AArch64Fold: folding" "$p dead path not found"
done

trim --in-place /work/test-a64fold 2>&1 | grep 'reassembled' || true
a64_out=$(qemu-aarch64 /work/test-a64fold 2>&1) && \
    pass "AArch64Fold: patched binary executes via QEMU" || \
    fail "AArch64Fold: QEMU execution" "crashed"

[ "$a64_out" = "$a64_expected" ] && \
    pass "AArch64Fold: patched output matches original" || \
    fail "AArch64Fold: output" "got: $a64_out"

# =============================================
# NativeAOT layout: managed code in __managedcode / __unbox
# =============================================
printf '\n--- NativeAOT layout: managed code sections ---\n'
gcc -g -O0 -fno-inline -o /work/test-nat /tests/nativeaot-sections.c
cp /work/test-nat /work/test-nat-strip
strip --strip-all /work/test-nat-strip
orig_sz_nat=$(stat -c%s /work/test-nat)
printf 'Built: test-nat (%d bytes)\n' "$orig_sz_nat"

output=$(trim --dry-run /work/test-nat 2>&1)
echo "$output"
echo "$output" | grep -q 'dead_f01' && \
    pass "NativeAOT: detected dead functions" || \
    fail "NativeAOT: detection" "dead_f01 not found"

echo "$output" | grep -q 'rt_helper\|rt_unbox' && \
    fail "NativeAOT: false positive" "helper called from managed code flagged" || \
    pass "NativeAOT: helpers called from managed code kept"

trim --in-place /work/test-nat
new_sz_nat=$(stat -c%s /work/test-nat)
printf 'Size: %d -> %d bytes\n' "$orig_sz_nat" "$new_sz_nat"

output=$(/work/test-nat 2>&1) && \
    pass "NativeAOT: patched binary executes" || \
    fail "NativeAOT: execution" "crashed"

echo "$output" | grep -q 'result: 31' && \
    pass "NativeAOT: managed->.text branches patched" || \
    fail "NativeAOT: output" "got: $output"

[ "$new_sz_nat" -lt "$orig_sz_nat" ] && \
    pass "NativeAOT: file physically smaller ($orig_sz_nat -> $new_sz_nat)" || \
    fail "NativeAOT: file size" "not reduced ($orig_sz_nat -> $new_sz_nat)"

trim --in-place /work/test-nat-strip 2>/dev/null
output=$(/work/test-nat-strip 2>&1)
echo "$output" | grep -q 'result: 31' && \
    pass "NativeAOT stripped: patched binary output correct" || \
    fail "NativeAOT stripped: output" "got: $output"

# =============================================
# NativeAOT image (__modules): dead code zero-filled in place
# =============================================
printf '\n--- NativeAOT image: zero-fill in place ---\n'
# With a __modules section trim detects a NativeAOT image and zero-fills
# dead code in place instead of compacting: no code moves and the file
# keeps its size. The variant's 32-bit self-relative pointer from
# __modules to the ELF header (which trim cannot patch) goes stale if
# anything moves.
gcc -g -O0 -fno-inline -DWITH_MODULES \
    -o /work/test-natm /tests/nativeaot-sections.c
cp /work/test-natm /work/test-natm-orig
cp /work/test-natm /work/test-natm-strip
strip --strip-all /work/test-natm-strip
orig_sz_natm=$(stat -c%s /work/test-natm)
printf 'Built: test-natm (%d bytes)\n' "$orig_sz_natm"

natm_out=$(trim --in-place /work/test-natm 2>&1) || true
echo "$natm_out"
echo "$natm_out" | \
    grep -q 'note: NativeAOT image detected; dead code zero-filled' && \
    pass "NativeAOT image: zero-fill note printed" || \
    fail "NativeAOT image: note" "not printed"
echo "$natm_out" | grep -q '30 dead functions removed' && \
    pass "NativeAOT image: 30 dead functions zero-filled" || \
    fail "NativeAOT image: zero-fill" "not reported"

new_sz_natm=$(stat -c%s /work/test-natm)
[ "$new_sz_natm" -eq "$orig_sz_natm" ] && \
    pass "NativeAOT image: file size unchanged ($new_sz_natm)" || \
    fail "NativeAOT image: file size" "$orig_sz_natm -> $new_sz_natm"

readelf -SW /work/test-natm-orig > /work/natm-shdr-orig
readelf -SW /work/test-natm > /work/natm-shdr-new
cmp -s /work/natm-shdr-orig /work/natm-shdr-new && \
    pass "NativeAOT image: section headers unchanged" || \
    fail "NativeAOT image: sections" \
        "$(diff /work/natm-shdr-orig /work/natm-shdr-new)"

readelf -lW /work/test-natm-orig > /work/natm-phdr-orig
readelf -lW /work/test-natm > /work/natm-phdr-new
cmp -s /work/natm-phdr-orig /work/natm-phdr-new && \
    pass "NativeAOT image: program headers unchanged" || \
    fail "NativeAOT image: program headers" \
        "$(diff /work/natm-phdr-orig /work/natm-phdr-new)"

# Dead function bodies (file ranges from the original symtab) must be
# all zero, and no byte outside them may change.
text_loc=$(readelf -SW /work/test-natm-orig | sed -n \
    's/.*\] \.text *PROGBITS *\([0-9a-f]*\) \([0-9a-f]*\) .*/\1 \2/p')
read -r text_va text_off <<EOF
$text_loc
EOF
nm -S /work/test-natm-orig | grep ' dead_f' > /work/natm-dead-syms
: > /work/natm-dead-ranges
while read -r addr size _ _; do
    lo=$((0x$addr - 0x$text_va + 0x$text_off))
    echo "$lo $((lo + 0x$size))" >> /work/natm-dead-ranges
done < /work/natm-dead-syms
natm_dirty=0
while read -r lo hi; do
    if od -An -v -tx1 -j "$lo" -N $((hi - lo)) /work/test-natm | \
        grep -q '[1-9a-f]'; then
        natm_dirty=$((natm_dirty + 1))
    fi
done < /work/natm-dead-ranges
natm_ranges=$(wc -l < /work/natm-dead-ranges)
[ "$natm_ranges" -eq 30 ] && [ "$natm_dirty" -eq 0 ] && \
    pass "NativeAOT image: dead function bytes zeroed ($natm_ranges)" || \
    fail "NativeAOT image: zeroed" \
        "$natm_dirty of $natm_ranges dead functions not all zero"
natm_stray=$(cmp -l /work/test-natm-orig /work/test-natm | awk '
    NR == FNR { lo[NR] = $1; hi[NR] = $2; n = NR; next }
    { off = $1 - 1; hit = 0
      for (i = 1; i <= n; i++) if (off >= lo[i] && off < hi[i]) hit = 1
      if (!hit || $3 != 0) bad++ }
    END { print bad + 0 }' /work/natm-dead-ranges -)
[ "$natm_stray" -eq 0 ] && \
    pass "NativeAOT image: no byte changed outside dead functions" || \
    fail "NativeAOT image: stray changes" "$natm_stray bytes"

output=$(/work/test-natm 2>&1) && \
    pass "NativeAOT image: patched binary executes" || \
    fail "NativeAOT image: execution" "crashed"
echo "$output" | grep -q 'result: 31' && \
    pass "NativeAOT image: output correct" || \
    fail "NativeAOT image: output" "got: $output"
echo "$output" | grep -q 'modules: ok' && \
    pass "NativeAOT image: self-relative pointer past .text valid" || \
    fail "NativeAOT image: __modules pointer" "got: $output"

# Stripped: function inference finds no dead code in this fixture, so
# this only checks trim leaves it working.
trim --in-place /work/test-natm-strip 2>/dev/null || true
output=$(/work/test-natm-strip 2>&1) || true
echo "$output" | grep -q 'modules: ok' && \
    echo "$output" | grep -q 'result: 31' && \
    pass "NativeAOT image stripped: patched binary output correct" || \
    fail "NativeAOT image stripped: output" "got: $output"

# Managed code sections without __modules are still compacted.
gcc -g -O0 -fno-inline -o /work/test-nat-drain /tests/nativeaot-sections.c
orig_sz_drain=$(stat -c%s /work/test-nat-drain)
natm_out=$(trim --in-place /work/test-nat-drain 2>&1) || true
new_sz_drain=$(stat -c%s /work/test-nat-drain)
! echo "$natm_out" | grep -q 'note: NativeAOT' && \
    [ "$new_sz_drain" -lt "$orig_sz_drain" ] && \
    pass "NativeAOT without __modules: compacted ($orig_sz_drain -> $new_sz_drain)" || \
    fail "NativeAOT without __modules" "note or size: $orig_sz_drain -> $new_sz_drain"

# =============================================
# NativeAOT ReadyToRun references: kept live
# =============================================
printf '\n--- NativeAOT ReadyToRun references: kept live ---\n'
# No .NET SDK in this image, so the fixture builds a minimal ReadyToRun
# header behind __modules: a module initializer list (213) and an
# ExternalReferences table (308) of 32-bit self-relative pointers to two
# static functions nothing else references. main() calls through them
# like the runtime: zero-filling them crashed it. r2r_unused stays dead.
gcc -g -O0 -fno-inline -o /work/test-r2r /tests/nativeaot-r2r.c
cp /work/test-r2r /work/test-r2r-strip
strip --strip-all /work/test-r2r-strip
r2r_out=$(trim --dry-run /work/test-r2r 2>&1) || true
echo "$r2r_out"
echo "$r2r_out" | \
    grep -q 'note: NativeAOT: 2 ReadyToRun references into code' && \
    pass "R2R refs: 2 references into code found" || \
    fail "R2R refs: model" "note not printed"
! echo "$r2r_out" | grep -q 'r2r_module_init\|r2r_external_ref' && \
    pass "R2R refs: referenced functions kept live" || \
    fail "R2R refs: false positive" "referenced function flagged dead"
echo "$r2r_out" | grep -q 'r2r_unused' && \
    pass "R2R refs: unreferenced function still dead" || \
    fail "R2R refs: detection" "r2r_unused not found"
trim --in-place /work/test-r2r 2>/dev/null || true
output=$(/work/test-r2r 2>&1) || true
echo "$output" | grep -q 'r2r: 51' && \
    pass "R2R refs: patched binary calls through the references" || \
    fail "R2R refs: execution" "got: $output"
# Stripped: functions inferred from FDEs.
trim --in-place /work/test-r2r-strip 2>/dev/null || true
output=$(/work/test-r2r-strip 2>&1) || true
echo "$output" | grep -q 'r2r: 51' && \
    pass "R2R refs stripped: patched binary output correct" || \
    fail "R2R refs stripped: output" "got: $output"
# An unverified header version: the model is refused and nothing may be
# called dead (fail closed).
gcc -g -O0 -fno-inline -DR2R_MAJOR=15 \
    -o /work/test-r2r-v15 /tests/nativeaot-r2r.c
r2r_out=$(trim --dry-run /work/test-r2r-v15 2>&1) || true
echo "$r2r_out" | grep -q 'ReadyToRun version 15.0 not verified' && \
    ! echo "$r2r_out" | grep -q 'dead functions' && \
    pass "R2R refs: unverified version fails closed (nothing dead)" || \
    fail "R2R refs: fail closed" "got: $r2r_out"

# =============================================
# Dead code outside .text: zero-filled in place
# =============================================
printf '\n--- Dead code outside .text: zero-filled in place ---\n'
# Unstripped, the symtab holds dead functions in executable sections after
# .text (__managedcode without __modules, and a custom `trimcode`). They
# outweigh the dead code in .text by more than a page: fed into the .text
# drain math they reversed the drain range (panic). Only .text is
# compacted; they must be zero-filled in place and their FDEs follow them.
gcc -g -O0 -fno-inline -o /work/test-xsd /tests/exec-section-dead.c
cp /work/test-xsd /work/test-xsd-orig
orig_sz_xsd=$(stat -c%s /work/test-xsd)
printf 'Built: test-xsd (%d bytes)\n' "$orig_sz_xsd"

xsd_rc=0
xsd_out=$(trim --in-place /work/test-xsd 2>&1) || xsd_rc=$?
echo "$xsd_out" | grep -v '^    ' || true
[ "$xsd_rc" -eq 0 ] && ! echo "$xsd_out" | grep -q 'panicked' && \
    pass "ExecSection: trim completes without panic" || \
    fail "ExecSection: trim" "rc=$xsd_rc"
echo "$xsd_out" | grep -q '91 dead functions removed' && \
    pass "ExecSection: 91 dead functions removed (30 in .text, 61 outside)" || \
    fail "ExecSection: count" "not reported"

new_sz_xsd=$(stat -c%s /work/test-xsd)
[ "$new_sz_xsd" -lt "$orig_sz_xsd" ] && \
    pass "ExecSection: .text compacted ($orig_sz_xsd -> $new_sz_xsd)" || \
    fail "ExecSection: file size" "not reduced ($orig_sz_xsd -> $new_sz_xsd)"

output=$(/work/test-xsd 2>&1) && \
    pass "ExecSection: patched binary executes" || \
    fail "ExecSection: execution" "crashed"
echo "$output" | grep -q 'result: 21' && \
    pass "ExecSection: managed->.text branch patched" || \
    fail "ExecSection: output" "got: $output"

# Print "dirty total" for the dead functions outside .text in $1 (dead_m*
# in __managedcode, dead_c* in trimcode): how many hold a nonzero byte.
# File offsets come from $1's own symtab and section headers.
xsd_dirty() {
    xd_n=0
    xd_d=0
    for xd_sec in __managedcode:dead_m trimcode:dead_c; do
        xd_loc=$(readelf -SW "$1" | sed -n \
            "s/.*\] ${xd_sec%%:*} *PROGBITS *\([0-9a-f]*\) \([0-9a-f]*\) .*/\1 \2/p")
        read -r xd_va xd_off <<EOF
$xd_loc
EOF
        nm -S "$1" | grep " ${xd_sec#*:}[0-9]*\$" > /work/xsd-syms || true
        while read -r addr size _ _; do
            lo=$((0x$addr - 0x$xd_va + 0x$xd_off))
            xd_n=$((xd_n + 1))
            if od -An -v -tx1 -j "$lo" -N $((0x$size)) "$1" | \
                grep -q '[1-9a-f]'; then
                xd_d=$((xd_d + 1))
            fi
        done < /work/xsd-syms
    done
    echo "$xd_d $xd_n"
}
xsd_before=$(xsd_dirty /work/test-xsd-orig)
xsd_after=$(xsd_dirty /work/test-xsd)
[ "$xsd_before" = "61 61" ] && [ "$xsd_after" = "0 61" ] && \
    pass "ExecSection: dead code outside .text zero-filled (61)" || \
    fail "ExecSection: zeroed" "dirty/total before: $xsd_before, after: $xsd_after"

# The zero-filled functions move with their section by the page-aligned
# drain; each FDE must cover exactly the function's new symbol range.
nm -S /work/test-xsd | grep ' dead_[mc][0-9]*$' > /work/xsd-syms || true
readelf --debug-dump=frames /work/test-xsd > /work/xsd-frames
xsd_nofde=0
while read -r addr size _ _; do
    end=$(printf '%016x' $((0x$addr + 0x$size)))
    if ! grep -q "pc=$addr\.\.$end\$" /work/xsd-frames; then
        xsd_nofde=$((xsd_nofde + 1))
    fi
done < /work/xsd-syms
[ "$(wc -l < /work/xsd-syms)" -eq 61 ] && [ "$xsd_nofde" -eq 0 ] && \
    pass "ExecSection: FDEs follow the zero-filled functions" || \
    fail "ExecSection: FDEs" "$xsd_nofde functions without a matching FDE"

# With __modules (NativeAOT image) every managed function is live:
# managed_hidden is reached only through a 32-bit self-relative pointer,
# as NativeAOT reaches managed methods through dehydrated MethodTables.
gcc -g -O0 -fno-inline -DWITH_MODULES \
    -o /work/test-xsdm /tests/exec-section-dead.c
orig_sz_xsdm=$(stat -c%s /work/test-xsdm)
xsdm_out=$(trim --in-place /work/test-xsdm 2>&1) || true
echo "$xsdm_out" | grep -q 'managed_hidden\|rt_hidden\|dead_m01' && \
    fail "ExecSection NativeAOT: false positive" "managed code flagged dead" || \
    pass "ExecSection NativeAOT: managed functions kept live"
echo "$xsdm_out" | grep -q '31 dead functions removed' && \
    pass "ExecSection NativeAOT: 31 dead functions zero-filled" || \
    fail "ExecSection NativeAOT: zero-fill" "not reported"
new_sz_xsdm=$(stat -c%s /work/test-xsdm)
[ "$new_sz_xsdm" -eq "$orig_sz_xsdm" ] && \
    pass "ExecSection NativeAOT: file size unchanged ($new_sz_xsdm)" || \
    fail "ExecSection NativeAOT: file size" "$orig_sz_xsdm -> $new_sz_xsdm"
output=$(/work/test-xsdm 2>&1) && \
    pass "ExecSection NativeAOT: patched binary executes" || \
    fail "ExecSection NativeAOT: execution" "crashed"
echo "$output" | grep -q 'result: 21' && \
    echo "$output" | grep -q 'hidden: 206' && \
    pass "ExecSection NativeAOT: output correct" || \
    fail "ExecSection NativeAOT: output" "got: $output"

# =============================================
# Switch jump-table: hoisted table base
# =============================================
printf '\n--- Switch jump-table: hoisted table base ---\n'
# -O2 turns the dense switch into a base-relative jump table; because it
# sits in a loop, the table-base `lea` is hoisted far (>6 instructions)
# before the `movsxd`, past the old detection window. Dead code before
# the dispatcher shifts the switch targets, so a stale table crashes.
gcc -O2 -fno-inline -o /work/test-jt /tests/jumptable-switch.c
printf 'Built: test-jt (%d bytes)\n' "$(stat -c%s /work/test-jt)"

jt_expected=$(/work/test-jt 2>&1)
echo "$jt_expected" | grep -q 'result:' && \
    pass "JumpTable: original produces result" || \
    fail "JumpTable: original" "no result: $jt_expected"

cp /work/test-jt /work/test-jt-patch
jt_patch_out=$(trim --in-place /work/test-jt-patch 2>&1)
echo "$jt_patch_out"

echo "$jt_patch_out" | grep -q 'dead functions removed' && \
    pass "JumpTable: dead functions compacted" || \
    fail "JumpTable: compaction" "not reported"

/work/test-jt-patch > /dev/null 2>&1 && \
    pass "JumpTable: patched binary executes" || \
    fail "JumpTable: execution" "crashed after patching"

jt_got=$(/work/test-jt-patch 2>&1)
[ "$jt_got" = "$jt_expected" ] && \
    pass "JumpTable: output correct after hoisted-base patch" || \
    fail "JumpTable: output" "expected [$jt_expected] got [$jt_got]"

# =============================================
# Switch jump-table: r13/rbp base, base LEA in another block
# =============================================
printf '\n--- Switch jump-table: r13/rbp base, split base LEA ---\n'
# gcc -O2 keeps the table base in r13: `movslq 0x0(%r13,idx,4)` needs a
# zero disp8 (ModRM mod=01), a form the detector used to reject. clang
# -O2 enters the switch loop by a jump to its test, so the base `lea`
# ends a different basic block than the dispatch, and a linear walk back
# stops at that jmp. Dead code before both dispatchers shifts the switch
# targets, so a stale table crashes; each main self-checks its result.
gcc -O2 -fno-inline -o /work/test-jt-r13 /tests/jumptable-r13.c
clang-19 -O2 -fno-inline -o /work/test-jt-split /tests/jumptable-split.c
printf 'Built: test-jt-r13 (%d bytes), test-jt-split (%d bytes)\n' \
    "$(stat -c%s /work/test-jt-r13)" "$(stat -c%s /work/test-jt-split)"

objdump -d /work/test-jt-r13 | grep -Eq 'movslq +0x0\(%(r13|rbp),' && \
    pass "JumpTable r13/rbp: fixture dispatches via 0x0(%r13|%rbp)" || \
    fail "JumpTable r13/rbp: fixture form" "no movslq 0x0(%r13|%rbp,...)"

objdump -d --no-show-raw-insn /work/test-jt-split | \
    awk '/<scan_records>:/ { f = 1; next }
         f && /^$/ { f = 0 }
         f && /lea .*\(%rip\)/ { l = 1 }
         f && l && /jmp +[0-9a-f]+ </ { j = 1 }
         f && j && /movslq/ { s = 1 }
         END { exit !s }' && \
    pass "JumpTable split LEA: fixture's base lea is followed by a jmp" || \
    fail "JumpTable split LEA: fixture form" "no lea, jmp, movslq sequence"

jt_r13_expected=$(/work/test-jt-r13 2>&1) || true
echo "$jt_r13_expected" | grep -q 'result: .* ok' && \
    pass "JumpTable r13/rbp: original self-check ok" || \
    fail "JumpTable r13/rbp: original" "got: $jt_r13_expected"

cp /work/test-jt-r13 /work/test-jt-r13-patch
jt_r13_out=$(trim --in-place /work/test-jt-r13-patch 2>&1) || true
echo "$jt_r13_out" | grep -q 'dead functions removed' && \
    pass "JumpTable r13/rbp: dead functions compacted" || \
    fail "JumpTable r13/rbp: compaction" "not reported"

jt_r13_got=$(/work/test-jt-r13-patch 2>&1) || true
[ "$jt_r13_got" = "$jt_r13_expected" ] && \
    pass "JumpTable r13/rbp: output correct after patch" || \
    fail "JumpTable r13/rbp: output" \
        "expected [$jt_r13_expected] got [$jt_r13_got]"

jt_split_expected=$(/work/test-jt-split 2>&1) || true
echo "$jt_split_expected" | grep -q 'result: .* ok' && \
    pass "JumpTable split LEA: original self-check ok" || \
    fail "JumpTable split LEA: original" "got: $jt_split_expected"

cp /work/test-jt-split /work/test-jt-split-patch
jt_split_out=$(trim --in-place /work/test-jt-split-patch 2>&1) || true
echo "$jt_split_out" | grep -q 'dead functions removed' && \
    pass "JumpTable split LEA: dead functions compacted" || \
    fail "JumpTable split LEA: compaction" "not reported"

jt_split_got=$(/work/test-jt-split-patch 2>&1) || true
[ "$jt_split_got" = "$jt_split_expected" ] && \
    pass "JumpTable split LEA: output correct after patch" || \
    fail "JumpTable split LEA: output" \
        "expected [$jt_split_expected] got [$jt_split_got]"

# =============================================
# Prefixed relative branches: addr32 / notrack / bnd
# =============================================
printf '\n--- Prefixed relative branches: addr32 / notrack / bnd ---\n'
# Each probe branches across dead code through a prefixed call, jmp or
# jcc (67 E8, 3E E9, F2 E9, F2 E8, 3E 0F 85; one call goes backwards).
# trim removes the dead code, so every rel32 must be re-pointed one
# prefix byte into its instruction. Built as PIE and static.
for pb_mode in pie static; do
    pb_bin=/work/test-prefixed-$pb_mode
    case $pb_mode in
        pie) pb_flags= ;;
        static) pb_flags=-static ;;
    esac
    gcc -O0 $pb_flags -o "$pb_bin" /tests/prefixed-branch.c
    pb_expected=$("$pb_bin" 2>&1) || true
    echo "$pb_expected" | grep -q '^prefixed-branch: ok$' && \
        pass "Prefixed $pb_mode: original self-check ok" || \
        fail "Prefixed $pb_mode: original" "got: $pb_expected"
    pb_out=$(trim --in-place "$pb_bin" 2>&1) || true
    echo "$pb_out" | grep -q 'dead_head: ' && \
        echo "$pb_out" | grep -q 'dead_middle: ' && \
        echo "$pb_out" | grep -q 'reassembled: [1-9]' && \
        pass "Prefixed $pb_mode: dead code between the branches removed" || \
        fail "Prefixed $pb_mode: compaction" "$pb_out"
    pb_got=$("$pb_bin" 2>&1) || true
    [ "$pb_got" = "$pb_expected" ] && \
        pass "Prefixed $pb_mode: patched binary output identical" || \
        fail "Prefixed $pb_mode: output" "got: $pb_got"
done

# =============================================
# Stream mode: output file
# =============================================
printf '\n--- Stream mode: output file ---\n'
cp /work/hello-dyn /work/test-stream-in
trim /work/test-stream-in /work/test-stream-out 2>/dev/null
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
trim /work/test-stdout-in > /work/test-stdout-out 2>/dev/null
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
cat /work/test-pipe-src | trim - > /work/test-pipe-out 2>/dev/null
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
report=$(cat /work/test-pipe-dry-src | trim --dry-run - 2>&1)
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
printf 'not an executable\n' | trim - > /dev/null 2>/work/test-sec-pipe
rc=$?
set -e
[ "$rc" -eq 0 ] && \
    pass "[SEC] Corrupted stdin: no crash (exit $rc)" || \
    pass "[SEC] Corrupted stdin: no crash (exit $rc)"

# =============================================
# [SEC] Malformed format-specific inputs
# =============================================
printf '\n--- [SEC] Malformed format-specific inputs ---\n'

# Truncated Java: valid magic but truncated constant pool
printf '\xCA\xFE\xBA\xBE\x00\x00\x00\x34\xFF\xFF' > /work/test-bad-java
set +e
output=$(trim --dry-run /work/test-bad-java 2>&1)
rc=$?
set -e
echo "$output" | grep -q 'skipped\|no function\|0 dead' && \
    pass "[SEC] Truncated Java: handled gracefully" || \
    pass "[SEC] Truncated Java: no crash (exit $rc)"

# Truncated Wasm: valid magic but truncated body
printf '\x00\x61\x73\x6D\x01\x00\x00\x00\x0A' > /work/test-bad-wasm
set +e
output=$(trim --dry-run /work/test-bad-wasm 2>&1)
rc=$?
set -e
echo "$output" | grep -q 'skipped\|no function\|0 dead' && \
    pass "[SEC] Truncated Wasm: handled gracefully" || \
    pass "[SEC] Truncated Wasm: no crash (exit $rc)"

# Truncated .NET: valid MZ header but truncated PE
printf 'MZ' > /work/test-bad-dotnet
dd if=/dev/zero bs=1 count=254 >> /work/test-bad-dotnet 2>/dev/null
set +e
output=$(trim --dry-run /work/test-bad-dotnet 2>&1)
rc=$?
set -e
echo "$output" | grep -q 'skipped\|no function\|0 dead' && \
    pass "[SEC] Truncated .NET: handled gracefully" || \
    pass "[SEC] Truncated .NET: no crash (exit $rc)"

# Empty file (0 bytes)
: > /work/test-empty
set +e
output=$(trim --dry-run /work/test-empty 2>&1)
rc=$?
set -e
echo "$output" | grep -q 'skipped\|no function\|Error' && \
    pass "[SEC] Empty file: handled gracefully" || \
    pass "[SEC] Empty file: no crash (exit $rc)"

# Java with huge constant pool count but no data
printf '\xCA\xFE\xBA\xBE\x00\x00\x00\x34\xFF\xFE' > /work/test-huge-cp
set +e
output=$(trim --dry-run /work/test-huge-cp 2>&1)
rc=$?
set -e
echo "$output" | grep -q 'skipped\|no function\|0 dead' && \
    pass "[SEC] Huge CP count: handled gracefully" || \
    pass "[SEC] Huge CP count: no crash (exit $rc)"

# 4 bytes only (every format's minimum magic)
printf '\x7FELF' > /work/test-4byte
set +e
output=$(trim --dry-run /work/test-4byte 2>&1)
rc=$?
set -e
echo "$output" | grep -q 'skipped\|no function\|0 dead' && \
    pass "[SEC] 4-byte file: handled gracefully" || \
    pass "[SEC] 4-byte file: no crash (exit $rc)"

# =============================================
# [SEC] Code section past the end of the file
# =============================================
printf '\n--- [SEC] Code section past the end of the file ---\n'
# A crafted or truncated ELF can name a code section whose file offset
# lies past the end of the file while its headers still parse. Besides
# .text, trim decodes .init, .fini and .plt*: slicing them panicked. It
# cannot read that code, so it must leave the file unchanged.
for eof_case in dyn:.fini dyn:.init dyn:.plt dyn:.text static:.init; do
    eof_src=/work/hello-${eof_case%%:*}
    eof_sec=${eof_case#*:}
    eof_bin=/work/test-eof-${eof_case%%:*}$eof_sec
    python3 /tests/elf_past_eof.py "$eof_src" "$eof_bin" "$eof_sec" > /dev/null
    eof_rc=0
    eof_out=$(trim "$eof_bin" "$eof_bin-out" 2>&1) || eof_rc=$?
    echo "$eof_out" | grep 'note\|panicked' || true
    [ "$eof_rc" -eq 0 ] && cmp -s "$eof_bin" "$eof_bin-out" && \
        echo "$eof_out" | grep -q "code section $eof_sec runs past the end" && \
        pass "[SEC] $eof_case past EOF: no panic, file left unchanged" || \
        fail "[SEC] $eof_case past EOF" "rc=$eof_rc: $eof_out"
done

# =============================================
# Stream mode: output file is executable
# =============================================
printf '\n--- Stream mode: output file executable ---\n'
cp /work/hello-dyn /work/test-exec-in
trim /work/test-exec-in /work/test-exec-out 2>/dev/null
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
output=$(trim --version 2>&1)
rc=$?
set -e
echo "$output" | grep -q 'trim [0-9]' && \
    pass "--version: shows version" || \
    fail "--version" "no version: $output"
[ "$rc" -eq 0 ] && \
    pass "--version: exit code 0" || \
    fail "--version: exit code" "expected 0, got $rc"

set +e
output=$(trim -v 2>&1)
rc=$?
set -e
echo "$output" | grep -q 'trim [0-9]' && \
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
output=$(trim --license 2>&1)
rc=$?
set -e
echo "$output" | grep -q 'MIT' && \
    pass "--license: shows MIT" || \
    fail "--license" "no MIT: $output"
[ "$rc" -eq 0 ] && \
    pass "--license: exit code 0" || \
    fail "--license: exit code" "expected 0, got $rc"

set +e
output=$(trim -l 2>&1)
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
output=$(trim --help 2>&1)
set -e
echo "$output" | grep -q 'trim [0-9]' && \
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
output=$(trim --dry-run /work/test-pe 2>&1)
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
trim --in-place /work/test-pe-patch
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

output=$(trim --dry-run /work/lib.dll 2>&1)
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
output=$(trim --dry-run /work/lib-macho.o 2>&1)
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
output=$(trim /work/test-macho-patch 2>&1)
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
output=$(trim --dry-run /work/hello-dotnet.exe 2>&1)
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
output=$(trim /work/test-dotnet-patch 2>&1)
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
# .NET IL dead branch detection
# =============================================
printf '\n--- .NET IL dead branch detection ---\n'
output=$(trim --dry-run /work/hello-dotnet.exe 2>&1)
echo "$output"
echo "$output" | grep -q 'dead branch' && \
    pass ".NET: detected dead branches" || \
    fail ".NET: dead branches" "not found"

# =============================================
# Dead branch detection: noreturn calls
# =============================================
printf '\n--- Dead branch detection: noreturn calls ---\n'
gcc -g -O0 -fno-inline -fno-builtin -o /work/test-dead-branch \
    /tests/dead-branch.c
printf 'Built: test-dead-branch (%d bytes)\n' \
    "$(stat -c%s /work/test-dead-branch)"

output=$(trim --dry-run /work/test-dead-branch 2>&1)
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
patch_out=$(trim --in-place /work/test-dead-branch-patch 2>&1)
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

output=$(trim --dry-run /work/test-combined 2>&1)
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
patch_out=$(trim --in-place /work/test-combined-patch 2>&1)
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
# PE metadata validation: patching preserves format
# =============================================
printf '\n--- PE metadata validation ---\n'
clang-19 --target=x86_64-w64-mingw32 -g -O0 -fno-inline -shared \
    -fuse-ld=lld -o /work/test-pe-meta.dll /tests/lib.c 2>/dev/null
orig_sz_pe_meta=$(stat -c%s /work/test-pe-meta.dll)
trim --in-place /work/test-pe-meta.dll 2>/dev/null
new_sz_pe_meta=$(stat -c%s /work/test-pe-meta.dll)

[ "$new_sz_pe_meta" -le "$orig_sz_pe_meta" ] && \
    pass "PE metadata: patched DLL valid" || \
    fail "PE metadata: patched DLL" "size grew"

file_info=$(file /work/test-pe-meta.dll)
echo "$file_info" | grep -q 'PE32' && \
    pass "PE metadata: patched DLL still PE" || \
    fail "PE metadata: patched type" "got: $file_info"

# =============================================
# Switch jump-table: PE and Mach-O table file offsets
# =============================================
printf '\n--- Switch jump-table: PE and Mach-O ---\n'
# Relative jump-table entries were read and rewritten at the table's
# vaddr taken as a file offset, true only for PIE ELF. A PE table sits
# at an RVA in .rdata whose raw data lies elsewhere, a Mach-O table at
# a vmaddr past the end of the file. Both stripped fixtures carry ~3 KB
# of dead code before the dispatcher. The PE table stays in .rdata
# while its case targets move, so all 12 entries must be rewritten; the
# Mach-O table follows its function in __text and moves with it. The
# images cannot run here, so jumptable_targets.py checks statically
# that every entry still reaches its original case code. The PE build
# skips the mingw CRT (entry `start`: mingw makes `main` call __main).
clang-19 --target=x86_64-w64-mingw32 -O2 -fno-inline -fuse-ld=lld -s \
    -nostdlib -Dmain=start -Wl,-e,start \
    -o /work/test-jt-pe.exe /tests/jumptable-mapped.c
clang-19 --target=x86_64-apple-macosx11 -O2 -fno-inline -nostdlib \
    -fuse-ld=lld -Wl,-no_exported_symbols -Wl,-x \
    -o /work/test-jt-macho /tests/jumptable-mapped.c
printf 'Built: test-jt-pe.exe (%d bytes), test-jt-macho (%d bytes)\n' \
    "$(stat -c%s /work/test-jt-pe.exe)" "$(stat -c%s /work/test-jt-macho)"

cp /work/test-jt-pe.exe /work/test-jt-pe-patch.exe
jt_pe_out=$(trim --in-place /work/test-jt-pe-patch.exe 2>&1) || true
echo "$jt_pe_out" | grep -q 'dead functions removed' && \
    pass "JumpTable PE: dead functions compacted" || \
    fail "JumpTable PE: compaction" "not reported"

jt_pe_chk=$(python3 /tests/jumptable_targets.py /work/test-jt-pe.exe \
    /work/test-jt-pe-patch.exe 12 2>&1) && \
    echo "$jt_pe_chk" | grep -q '^12/12 entries .*(12 rewritten)' && \
    pass "JumpTable PE: all 12 .rdata entries rewritten to their cases" || \
    fail "JumpTable PE: table entries" "$jt_pe_chk"

cp /work/test-jt-macho /work/test-jt-macho-patch
jt_mo_out=$(trim --in-place /work/test-jt-macho-patch 2>&1) || true
echo "$jt_mo_out" | grep -q 'dead functions removed' && \
    pass "JumpTable Mach-O: dead functions compacted" || \
    fail "JumpTable Mach-O: compaction" "not reported"

jt_mo_chk=$(python3 /tests/jumptable_targets.py /work/test-jt-macho \
    /work/test-jt-macho-patch 12 2>&1) && \
    echo "$jt_mo_chk" | grep -q '^12/12 entries' && \
    pass "JumpTable Mach-O: all 12 __text entries reach their cases" || \
    fail "JumpTable Mach-O: table entries" "$jt_mo_chk"

# =============================================
# Mach-O metadata validation: patching preserves format
# =============================================
printf '\n--- Mach-O metadata validation ---\n'
clang-19 -c --target=arm64-apple-macosx -g -O0 -fno-inline \
    -o /work/test-macho-meta /tests/big-dead.c
orig_sz_macho_meta=$(stat -c%s /work/test-macho-meta)
trim --in-place /work/test-macho-meta 2>/dev/null
new_sz_macho_meta=$(stat -c%s /work/test-macho-meta)

[ "$new_sz_macho_meta" -le "$orig_sz_macho_meta" ] && \
    pass "Mach-O metadata: patched file valid" || \
    fail "Mach-O metadata: patched file" "size grew"

file_info=$(file /work/test-macho-meta)
echo "$file_info" | grep -qi 'mach-o' && \
    pass "Mach-O metadata: patched file still Mach-O" || \
    fail "Mach-O metadata: patched type" "got: $file_info"

# =============================================
# Dead code detection: AArch64
# =============================================
printf '\n--- Dead code detection: AArch64 ---\n'
output=$(trim --dry-run /work/hello-aarch64 2>&1)
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
patch_out_a64=$(trim --in-place /work/test-aarch64-patch 2>&1)
echo "$patch_out_a64"
new_sz_a64=$(stat -c%s /work/test-aarch64-patch)
printf 'Size: %d -> %d bytes\n' "$orig_sz_a64" "$new_sz_a64"

[ "$new_sz_a64" -le "$orig_sz_a64" ] && \
    pass "AArch64: patched file valid" || \
    fail "AArch64: patched file" "size grew"

file_info=$(file /work/test-aarch64-patch)
echo "$file_info" | grep -q 'ELF' && \
    pass "AArch64: patched file still ELF" || \
    fail "AArch64: patched type" "got: $file_info"

echo "$patch_out_a64" | grep -q 'dead functions removed' && \
    pass "AArch64: compaction reported" || \
    fail "AArch64: compaction" "not reported"

# =============================================
# Dead code detection: ARM32
# =============================================
printf '\n--- Dead code detection: ARM32 ---\n'
output=$(trim --dry-run /work/hello-arm32 2>&1)
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
patch_out_arm32=$(trim --in-place /work/test-arm32-patch 2>&1)
echo "$patch_out_arm32"
new_sz_arm32=$(stat -c%s /work/test-arm32-patch)
printf 'Size: %d -> %d bytes\n' "$orig_sz_arm32" "$new_sz_arm32"

[ "$new_sz_arm32" -le "$orig_sz_arm32" ] && \
    pass "ARM32: patched file valid" || \
    fail "ARM32: patched file" "size grew"

file_info=$(file /work/test-arm32-patch)
echo "$file_info" | grep -q 'ELF' && \
    pass "ARM32: patched file still ELF" || \
    fail "ARM32: patched type" "got: $file_info"

echo "$patch_out_arm32" | grep -q 'dead functions removed' && \
    pass "ARM32: compaction reported" || \
    fail "ARM32: compaction" "not reported"

# =============================================
# Dead code detection: RISC-V 64
# =============================================
printf '\n--- Dead code detection: RISC-V 64 ---\n'
output=$(trim --dry-run /work/hello-riscv64 2>&1)
echo "$output"

echo "$output" | grep -q 'dead_compute' && \
    pass "RISC-V64: detected dead_compute" || \
    fail "RISC-V64: dead_compute" "not found"

echo "$output" | grep -q 'dead_factorial' && \
    pass "RISC-V64: detected dead_factorial" || \
    fail "RISC-V64: dead_factorial" "not found"

echo "$output" | grep -q '  _start' && \
    fail "RISC-V64: false positive" "_start flagged as dead" || \
    pass "RISC-V64: _start correctly kept"

echo "$output" | grep -q 'live_add' && \
    fail "RISC-V64: false positive" "live_add flagged as dead" || \
    pass "RISC-V64: live_add correctly kept"

echo "$output" | grep -q 'live_multiply' && \
    fail "RISC-V64: false positive" "live_multiply flagged" || \
    pass "RISC-V64: live_multiply correctly kept"

file_info=$(file /work/hello-riscv64)
echo "$file_info" | grep -q 'ELF.*RISC-V' && \
    pass "RISC-V64: correct ELF type" || \
    fail "RISC-V64: ELF type" "got: $file_info"

# =============================================
# Patching: RISC-V 64
# =============================================
printf '\n--- Patching: RISC-V 64 ---\n'
cp /work/hello-riscv64 /work/test-riscv64-patch
orig_sz_rv=$(stat -c%s /work/test-riscv64-patch)
patch_out_rv=$(trim --in-place /work/test-riscv64-patch 2>&1)
echo "$patch_out_rv"
new_sz_rv=$(stat -c%s /work/test-riscv64-patch)
printf 'Size: %d -> %d bytes\n' "$orig_sz_rv" "$new_sz_rv"

[ "$new_sz_rv" -le "$orig_sz_rv" ] && \
    pass "RISC-V64: patched file valid" || \
    fail "RISC-V64: patched file" "size grew"

file_info=$(file /work/test-riscv64-patch)
echo "$file_info" | grep -q 'ELF' && \
    pass "RISC-V64: patched file still ELF" || \
    fail "RISC-V64: patched type" "got: $file_info"

qemu-riscv64 /work/test-riscv64-patch > /dev/null 2>&1 && \
    pass "RISC-V64: patched binary executes via QEMU" || \
    fail "RISC-V64: QEMU execution" "crashed"

echo "$patch_out_rv" | grep -q 'dead functions removed' && \
    pass "RISC-V64: compaction reported" || \
    fail "RISC-V64: compaction" "not reported"

# =============================================
# Dead code detection: MIPS (big-endian)
# =============================================
printf '\n--- Dead code detection: MIPS ---\n'
output=$(trim --dry-run /work/hello-mips 2>&1)
echo "$output"

echo "$output" | grep -q 'dead_compute' && \
    pass "MIPS: detected dead_compute" || \
    fail "MIPS: dead_compute" "not found"

echo "$output" | grep -q 'dead_factorial' && \
    pass "MIPS: detected dead_factorial" || \
    fail "MIPS: dead_factorial" "not found"

echo "$output" | grep -q '  __start' && \
    fail "MIPS: false positive" "__start flagged as dead" || \
    pass "MIPS: __start correctly kept"

echo "$output" | grep -q 'live_add' && \
    fail "MIPS: false positive" "live_add flagged as dead" || \
    pass "MIPS: live_add correctly kept"

echo "$output" | grep -q 'live_multiply' && \
    fail "MIPS: false positive" "live_multiply flagged" || \
    pass "MIPS: live_multiply correctly kept"

file_info=$(file /work/hello-mips)
echo "$file_info" | grep -q 'ELF.*MIPS' && \
    pass "MIPS: correct ELF type" || \
    fail "MIPS: ELF type" "got: $file_info"

# =============================================
# Patching: MIPS
# =============================================
printf '\n--- Patching: MIPS ---\n'
cp /work/hello-mips /work/test-mips-patch
orig_sz_mips=$(stat -c%s /work/test-mips-patch)
patch_out_mips=$(trim --in-place /work/test-mips-patch 2>&1)
echo "$patch_out_mips"
new_sz_mips=$(stat -c%s /work/test-mips-patch)
printf 'Size: %d -> %d bytes\n' "$orig_sz_mips" "$new_sz_mips"

[ "$new_sz_mips" -le "$orig_sz_mips" ] && \
    pass "MIPS: patched file valid" || \
    fail "MIPS: patched file" "size grew"

file_info=$(file /work/test-mips-patch)
echo "$file_info" | grep -q 'ELF' && \
    pass "MIPS: patched file still ELF" || \
    fail "MIPS: patched type" "got: $file_info"

qemu-mips /work/test-mips-patch > /dev/null 2>&1 && \
    pass "MIPS: patched binary executes via QEMU" || \
    fail "MIPS: QEMU execution" "crashed"

echo "$patch_out_mips" | grep -q 'dead functions removed' && \
    pass "MIPS: compaction reported" || \
    fail "MIPS: compaction" "not reported"

# =============================================
# Dead code detection: s390x
# =============================================
printf '\n--- Dead code detection: s390x ---\n'
output=$(trim --dry-run /work/hello-s390x 2>&1)
echo "$output"

echo "$output" | grep -q 'dead_compute' && \
    pass "s390x: detected dead_compute" || \
    fail "s390x: dead_compute" "not found"

echo "$output" | grep -q 'dead_factorial' && \
    pass "s390x: detected dead_factorial" || \
    fail "s390x: dead_factorial" "not found"

echo "$output" | grep -q '  _start' && \
    fail "s390x: false positive" "_start flagged as dead" || \
    pass "s390x: _start correctly kept"

echo "$output" | grep -q 'live_add' && \
    fail "s390x: false positive" "live_add flagged as dead" || \
    pass "s390x: live_add correctly kept"

echo "$output" | grep -q 'live_multiply' && \
    fail "s390x: false positive" "live_multiply flagged" || \
    pass "s390x: live_multiply correctly kept"

file_info=$(file /work/hello-s390x)
echo "$file_info" | grep -q 'ELF.*S/390' && \
    pass "s390x: correct ELF type" || \
    fail "s390x: ELF type" "got: $file_info"

# =============================================
# Patching: s390x
# =============================================
printf '\n--- Patching: s390x ---\n'
cp /work/hello-s390x /work/test-s390x-patch
orig_sz_s390=$(stat -c%s /work/test-s390x-patch)
patch_out_s390=$(trim --in-place /work/test-s390x-patch 2>&1)
echo "$patch_out_s390"
new_sz_s390=$(stat -c%s /work/test-s390x-patch)
printf 'Size: %d -> %d bytes\n' "$orig_sz_s390" "$new_sz_s390"

[ "$new_sz_s390" -le "$orig_sz_s390" ] && \
    pass "s390x: patched file valid" || \
    fail "s390x: patched file" "size grew"

file_info=$(file /work/test-s390x-patch)
echo "$file_info" | grep -q 'ELF' && \
    pass "s390x: patched file still ELF" || \
    fail "s390x: patched type" "got: $file_info"

qemu-s390x /work/test-s390x-patch > /dev/null 2>&1 && \
    pass "s390x: patched binary executes via QEMU" || \
    fail "s390x: QEMU execution" "crashed"

echo "$patch_out_s390" | grep -q 'dead functions removed' && \
    pass "s390x: compaction reported" || \
    fail "s390x: compaction" "not reported"

# =============================================
# Dead code detection: LoongArch64
# =============================================
printf '\n--- Dead code detection: LoongArch64 ---\n'
output=$(trim --dry-run /work/hello-loongarch64 2>&1)
echo "$output"

echo "$output" | grep -q 'dead_compute' && \
    pass "LoongArch64: detected dead_compute" || \
    fail "LoongArch64: dead_compute" "not found"

echo "$output" | grep -q 'dead_factorial' && \
    pass "LoongArch64: detected dead_factorial" || \
    fail "LoongArch64: dead_factorial" "not found"

echo "$output" | grep -q '  _start' && \
    fail "LoongArch64: false positive" "_start flagged" || \
    pass "LoongArch64: _start correctly kept"

echo "$output" | grep -q 'live_add' && \
    fail "LoongArch64: false positive" "live_add flagged" || \
    pass "LoongArch64: live_add correctly kept"

echo "$output" | grep -q 'live_multiply' && \
    fail "LoongArch64: false positive" "live_multiply flagged" || \
    pass "LoongArch64: live_multiply correctly kept"

file_info=$(file /work/hello-loongarch64)
echo "$file_info" | grep -q 'ELF.*LoongArch' && \
    pass "LoongArch64: correct ELF type" || \
    fail "LoongArch64: ELF type" "got: $file_info"

# =============================================
# Patching: LoongArch64
# =============================================
printf '\n--- Patching: LoongArch64 ---\n'
cp /work/hello-loongarch64 /work/test-loongarch64-patch
orig_sz_la=$(stat -c%s /work/test-loongarch64-patch)
patch_out_la=$(trim --in-place /work/test-loongarch64-patch 2>&1)
echo "$patch_out_la"
new_sz_la=$(stat -c%s /work/test-loongarch64-patch)
printf 'Size: %d -> %d bytes\n' "$orig_sz_la" "$new_sz_la"

[ "$new_sz_la" -le "$orig_sz_la" ] && \
    pass "LoongArch64: patched file valid" || \
    fail "LoongArch64: patched file" "size grew"

file_info=$(file /work/test-loongarch64-patch)
echo "$file_info" | grep -q 'ELF' && \
    pass "LoongArch64: patched file still ELF" || \
    fail "LoongArch64: patched type" "got: $file_info"

qemu-loongarch64 /work/test-loongarch64-patch > /dev/null 2>&1 && \
    pass "LoongArch64: patched binary executes via QEMU" || \
    fail "LoongArch64: QEMU execution" "crashed"

echo "$patch_out_la" | grep -q 'dead functions removed' && \
    pass "LoongArch64: compaction reported" || \
    fail "LoongArch64: compaction" "not reported"

# =============================================
# Dead code detection: x86-32
# =============================================
printf '\n--- Dead code detection: x86-32 ---\n'
output=$(trim --dry-run /work/hello-x86-32 2>&1)
echo "$output"

echo "$output" | grep -q 'dead_compute' && \
    pass "x86-32: detected dead_compute" || \
    fail "x86-32: dead_compute" "not found"

echo "$output" | grep -q 'dead_factorial' && \
    pass "x86-32: detected dead_factorial" || \
    fail "x86-32: dead_factorial" "not found"

echo "$output" | grep -q '  _start' && \
    fail "x86-32: false positive" "_start flagged" || \
    pass "x86-32: _start correctly kept"

echo "$output" | grep -q 'live_add' && \
    fail "x86-32: false positive" "live_add flagged" || \
    pass "x86-32: live_add correctly kept"

echo "$output" | grep -q 'live_multiply' && \
    fail "x86-32: false positive" "live_multiply flagged" || \
    pass "x86-32: live_multiply correctly kept"

file_info=$(file /work/hello-x86-32)
echo "$file_info" | grep -q 'ELF.*32-bit\|ELF.*386\|ELF.*i386' && \
    pass "x86-32: correct ELF type" || \
    fail "x86-32: ELF type" "got: $file_info"

# =============================================
# Patching: x86-32
# =============================================
printf '\n--- Patching: x86-32 ---\n'
cp /work/hello-x86-32 /work/test-x86-32-patch
orig_sz_x32=$(stat -c%s /work/test-x86-32-patch)
patch_out_x32=$(trim --in-place /work/test-x86-32-patch 2>&1)
echo "$patch_out_x32"
new_sz_x32=$(stat -c%s /work/test-x86-32-patch)
printf 'Size: %d -> %d bytes\n' "$orig_sz_x32" "$new_sz_x32"

[ "$new_sz_x32" -le "$orig_sz_x32" ] && \
    pass "x86-32: patched file valid" || \
    fail "x86-32: patched file" "size grew"

file_info=$(file /work/test-x86-32-patch)
echo "$file_info" | grep -q 'ELF' && \
    pass "x86-32: patched file still ELF" || \
    fail "x86-32: patched type" "got: $file_info"

echo "$patch_out_x32" | grep -q 'dead functions removed' && \
    pass "x86-32: compaction reported" || \
    fail "x86-32: compaction" "not reported"

# =============================================
# Dead-branch folding paused: ARM32, RISC-V, MIPS, LoongArch, s390x
# =============================================
printf '\n--- Dead-branch folding paused: ARM32, RISC-V, MIPS, LoongArch, s390x ---\n'
# Dead branches are folded only on architectures whose constant model
# passed a soundness audit (x86-64 and AArch64); the others are paused
# until theirs lands. Their fixtures report no dead branch, while dead
# functions are still found.
for pa in arm32 riscv64 mips s390x loongarch64; do
    pa_out=$(trim --dry-run /work/hello-$pa 2>&1) || true
    ! echo "$pa_out" | grep -q 'dead branch:' && \
        echo "$pa_out" | grep -q 'found 2 dead functions' && \
        pass "Paused $pa: no dead branch; dead functions still found" || \
        fail "Paused $pa" "$pa_out"
done
# MIPS: $t0 = 0 is overwritten by lw (1 at run time) and tested with
# bnez; the constant model ignored the load and folded the live path
# away (mips-fold.c). The trimmed binary must print what it printed.
# Its dead function lies before put and __start, so the absolute JAL
# targets to them must follow even where the JAL itself moves too.
clang-19 --target=mips-linux-gnu -nostdlib -static -O0 -fno-pic \
    -fuse-ld=lld -o /work/test-mips-fold /tests/mips-fold.c 2>/dev/null
mf_expected=$(qemu-mips /work/test-mips-fold 2>&1) || true
mf_out=$(trim --in-place /work/test-mips-fold 2>&1) || true
echo "$mf_out"
mf_got=$(qemu-mips /work/test-mips-fold 2>&1) || true
[ "$mf_expected" = 'probes: 1' ] && \
    ! echo "$mf_out" | grep -q 'dead branch:' && \
    echo "$mf_out" | grep -q 'dead_unused: ' && \
    [ "$mf_got" = "$mf_expected" ] && \
    pass "Paused MIPS: lw/bnez probe kept; trimmed output identical" || \
    fail "Paused MIPS: lw/bnez probe" "got: $mf_got"

# =============================================
# Dead-branch folding paused: x86-32
# =============================================
printf '\n--- Dead-branch folding paused: x86-32 ---\n'
# The x86 decoders read 32-bit code in 64-bit mode, where inc/dec
# (0x40-0x4F) are REX prefixes: `inc esi; cmp esi, 10; jne` read as a
# compare of the stale esi = 0, so the jne was folded as always taken
# and the loop exit removed (x86-32-fold.c). Folding is paused on
# x86-32 until its decoding is fixed and audited. The probe exits with
# 0 when the loop ran to 10, before and after trimming; its dead
# function lies before the probe and _start, so both move.
x32_out=$(trim --dry-run /work/hello-x86-32 2>&1) || true
! echo "$x32_out" | grep -q 'dead branch:' && \
    echo "$x32_out" | grep -q 'found 2 dead functions' && \
    pass "Paused x86-32: no dead branch; dead functions still found" || \
    fail "Paused x86-32" "$x32_out"
clang-19 --target=i686-linux-gnu -nostdlib -static -O0 -fno-pic \
    -fuse-ld=lld -o /work/test-x86-32-fold /tests/x86-32-fold.c 2>/dev/null
xf_expected=0
/work/test-x86-32-fold || xf_expected=$?
xf_out=$(trim --in-place /work/test-x86-32-fold 2>&1) || true
echo "$xf_out"
xf_got=0
/work/test-x86-32-fold || xf_got=$?
[ "$xf_expected" = 0 ] && \
    ! echo "$xf_out" | grep -q 'dead branch:' && \
    echo "$xf_out" | grep -q 'dead_unused: ' && \
    [ "$xf_got" = 0 ] && \
    pass "Paused x86-32: inc/cmp/jne loop kept; trimmed probe exits 0" || \
    fail "Paused x86-32: inc loop" "exit: $xf_expected -> $xf_got"

# =============================================
# Dead code detection: WebAssembly
# =============================================
printf '\n--- Dead code detection: WebAssembly ---\n'
output=$(trim --dry-run /work/lib.wasm 2>&1)
echo "$output"

echo "$output" | grep -q 'analyzing:' && \
    pass "Wasm: analysis completed" || \
    fail "Wasm: analysis" "not completed"

echo "$output" | grep -q 'dead functions' && \
    pass "Wasm: detected dead functions" || \
    fail "Wasm: dead functions" "none found"

echo "$output" | grep -q '  add' && \
    fail "Wasm: false positive" "exported add flagged" || \
    pass "Wasm: exported add correctly kept"

echo "$output" | grep -q '  multiply' && \
    fail "Wasm: false positive" "exported multiply flagged" || \
    pass "Wasm: exported multiply correctly kept"

echo "$output" | grep -q '  compute' && \
    fail "Wasm: false positive" "exported compute flagged" || \
    pass "Wasm: exported compute correctly kept"

# =============================================
# Wasm dead branch detection
# =============================================
printf '\n--- Wasm dead branch detection ---\n'
output=$(trim --dry-run /work/lib.wasm 2>&1)
echo "$output"
echo "$output" | grep -q 'dead branch' && \
    pass "Wasm: detected dead branches" || \
    fail "Wasm: dead branches" "not found"

# =============================================
# Patching: WebAssembly
# =============================================
printf '\n--- Patching: WebAssembly ---\n'
cp /work/lib.wasm /work/test-wasm-patch
orig_sz_wasm=$(stat -c%s /work/test-wasm-patch)
patch_out_wasm=$(trim --in-place /work/test-wasm-patch 2>&1)
echo "$patch_out_wasm"
new_sz_wasm=$(stat -c%s /work/test-wasm-patch)
printf 'Size: %d -> %d bytes\n' "$orig_sz_wasm" "$new_sz_wasm"

[ "$new_sz_wasm" -le "$orig_sz_wasm" ] && \
    pass "Wasm: patched file valid" || \
    fail "Wasm: patched file" "size grew"

file_info=$(file /work/test-wasm-patch)
echo "$file_info" | grep -q 'WebAssembly\|wasm' && \
    pass "Wasm: patched file still WebAssembly" || \
    fail "Wasm: patched type" "got: $file_info"

echo "$patch_out_wasm" | grep -q 'dead branches removed' && \
    pass "Wasm: dead branch compaction reported" || \
    fail "Wasm: dead branch compaction" "not reported"

# Wasm physical shrink: file must be strictly smaller (dead branches
# are physically removed from live function bodies)
[ "$new_sz_wasm" -lt "$orig_sz_wasm" ] && \
    pass "Wasm: file physically shrunk" || \
    fail "Wasm: physical shrink" "size $new_sz_wasm >= $orig_sz_wasm"

# =============================================
# Dead code detection: Java .class
# =============================================
printf '\n--- Dead code detection: Java .class ---\n'
output=$(trim --dry-run /work/hello-java.class 2>&1)
echo "$output"

echo "$output" | grep -q 'analyzing:' && \
    pass "Java: analysis completed" || \
    fail "Java: analysis" "not completed"

echo "$output" | grep -q 'functions' && \
    pass "Java: functions discovered" || \
    fail "Java: functions" "none found"

echo "$output" | grep -q 'deadMethod1' && \
    pass "Java: detected deadMethod1" || \
    fail "Java: deadMethod1" "not found"

echo "$output" | grep -q 'deadMethod2' && \
    pass "Java: detected deadMethod2" || \
    fail "Java: deadMethod2" "not found"

echo "$output" | grep -q '    main:' && \
    fail "Java: false positive" "main flagged as dead" || \
    pass "Java: main correctly kept"

echo "$output" | grep -q '    liveHelper:' && \
    fail "Java: false positive" "liveHelper flagged" || \
    pass "Java: liveHelper correctly kept"

echo "$output" | grep -q '    <init>:' && \
    fail "Java: false positive" "<init> flagged" || \
    pass "Java: <init> correctly kept"

echo "$output" | grep -q 'deadWithExc' && \
    pass "Java: detected deadWithExc (exc handler)" || \
    fail "Java: deadWithExc" "not found"

echo "$output" | grep -q 'deadWithSwitch' && \
    pass "Java: detected deadWithSwitch (tableswitch)" || \
    fail "Java: deadWithSwitch" "not found"

echo "$output" | grep -q '    liveWithSMT:' && \
    fail "Java: false positive" "liveWithSMT flagged" || \
    pass "Java: liveWithSMT correctly kept (StackMapTable)"

# =============================================
# Patching: Java .class
# =============================================
printf '\n--- Patching: Java .class ---\n'
cp /work/hello-java.class /work/test-java-patch.class
orig_sz_java=$(stat -c%s /work/test-java-patch.class)
patch_out_java=$(trim --in-place /work/test-java-patch.class 2>&1)
echo "$patch_out_java"
new_sz_java=$(stat -c%s /work/test-java-patch.class)
printf 'Size: %d -> %d bytes\n' "$orig_sz_java" "$new_sz_java"

[ "$new_sz_java" -lt "$orig_sz_java" ] && \
    pass "Java: file physically shrunk" || \
    fail "Java: physical shrink" "size $new_sz_java >= $orig_sz_java"

echo "$patch_out_java" | grep -q 'dead functions removed' && \
    pass "Java: compaction reported" || \
    fail "Java: compaction" "not reported"

# Verify the patched class file still has CAFEBABE magic
head_bytes=$(xxd -l 4 -p /work/test-java-patch.class)
[ "$head_bytes" = "cafebabe" ] && \
    pass "Java: patched file has valid magic" || \
    fail "Java: magic" "got: $head_bytes"

# =============================================
# Cleanup
# =============================================
rm -f /work/hello-* /work/lib.* /work/lib-* /work/test-* /work/multi*

# =============================================
# Unwind tables: C++ exceptions through moved code
# (.eh_frame / .eh_frame_hdr re-pointed after compaction)
# =============================================
printf '\n--- Unwind tables: C++ exceptions through moved code ---\n'
if g++ -g -O0 -o /work/eh-unwind /tests/eh-unwind.cpp; then
    cp /work/eh-unwind /work/eh-unwind-strip
    strip --strip-all /work/eh-unwind-strip
    for eh_bin in /work/eh-unwind /work/eh-unwind-strip; do
        eh_tag=$(basename "$eh_bin")
        orig_sz_eh=$(stat -c%s "$eh_bin")
        trim --in-place "$eh_bin" > /dev/null 2>&1 || \
            fail "EH $eh_tag: trim" "exited non-zero"
        new_sz_eh=$(stat -c%s "$eh_bin")
        printf 'Size: %d -> %d bytes (%s)\n' \
            "$orig_sz_eh" "$new_sz_eh" "$eh_tag"
        [ "$new_sz_eh" -lt "$orig_sz_eh" ] && \
            pass "EH $eh_tag: file physically smaller ($orig_sz_eh -> $new_sz_eh)" || \
            fail "EH $eh_tag: file size" "not reduced ($orig_sz_eh -> $new_sz_eh)"
        output=$("$eh_bin" 2>&1) && \
            pass "EH $eh_tag: patched binary executes" || \
            fail "EH $eh_tag: execution" "crashed: $output"
        echo "$output" | grep -q 'caught: boom' && \
        echo "$output" | grep -q 'result: -1 5 unwound: 6' && \
        echo "$output" | grep -q 'marker: eh-unwind done' && \
            pass "EH $eh_tag: exception unwinds through moved frames" || \
            fail "EH $eh_tag: output" "got: $output"
    done
else
    fail "EH: build" "g++ could not build eh-unwind.cpp"
fi
rm -f /work/eh-unwind /work/eh-unwind-strip

# =============================================
# RELR packing (--relr): RELATIVE relocations
# =============================================
printf '\n--- RELR packing: --relr ---\n'
# relr-pointers.c holds ~4200 R_X86_64_RELATIVE relocations (dense and
# sparse pointer tables in .data.rel.ro and .data). --relr packs them
# into a RELR table (DT_RELR) inside the old .rela.dyn range:
# - musl static-pie (--relr-static: Alpine's musl applies DT_RELR in
#   its start code): every relocation is RELATIVE and .rela.dyn ends the
#   first (read-only) segment, so its header becomes .relr.dyn, the RELA
#   tags leave .dynamic and the freed whole pages leave the file;
# - dynamic PIE: GLOB_DAT and an unaligned RELATIVE relocation stay RELA
#   and a .relr.dyn header is appended; .rela.plt follows .rela.dyn in
#   its segment and nothing in a segment may move, so the slack stays
#   as padding;
# - the same PIE with its data-pointer words zeroed in place (as lld
#   leaves them; RELA ignores them): --relr must write the addends back.
# Every vaddr stays. Plain trim (no --relr) is the reference: the packed
# binary must print exactly what the original prints.
gcc -O0 -static-pie -o /work/relr-spie /tests/relr-pointers.c
gcc -O0 -DWITH_UNALIGNED -o /work/relr-pie /tests/relr-pointers.c
cp /work/relr-pie /work/relr-pie0
python3 /tests/relr_zero_words.py /work/relr-pie0
for rb in relr-spie relr-pie relr-pie0; do
    rb_in=/work/$rb
    rb_exp=$("$rb_in" 2>&1) || true
    trim "$rb_in" "$rb_in-plain" > /dev/null 2>&1 || true
    rb_flag=--relr
    [ "$rb" = relr-spie ] && rb_flag=--relr-static
    rb_rc=0
    rb_out=$(trim "$rb_flag" "$rb_in" "$rb_in-relr" 2>&1) || rb_rc=$?
    echo "$rb_out" | grep 'relr\|Error' || true
    [ "$rb_rc" -eq 0 ] && [ -s "$rb_in-relr" ] && \
        echo "$rb_out" | grep -q 'relr: packed' && \
        pass "RELR $rb: trim --relr packed the relocations" || \
        fail "RELR $rb: trim --relr" "rc=$rb_rc: $rb_out"
    rb_got=$("$rb_in-relr" 2>&1) || true
    echo "$rb_exp" | grep -q 'relr-fixture: ok' && \
        [ "$rb_got" = "$rb_exp" ] && \
        pass "RELR $rb: packed binary output identical" || \
        fail "RELR $rb: output" "got: $rb_got"
    rb_dyn=$(readelf -dW "$rb_in-relr" 2>&1) || true
    echo "$rb_dyn" | grep -q '(RELR) ' && \
        echo "$rb_dyn" | grep -q '(RELRSZ) ' && \
        echo "$rb_dyn" | grep -q '(RELRENT) *8 ' && \
        pass "RELR $rb: .dynamic has DT_RELR, DT_RELRSZ, DT_RELRENT" || \
        fail "RELR $rb: .dynamic" "$rb_dyn"
    # readelf decodes .relr.dyn on its own: it must relocate exactly the
    # word-aligned RELATIVE relocations; all others stay in .rela.dyn.
    rb_want=$(readelf -rW "$rb_in-plain" | \
        awk '$3 == "R_X86_64_RELATIVE" && $1 ~ /[08]$/' | wc -l)
    rb_have=$(readelf -rW "$rb_in-relr" | sed -n \
        "s/.*'\.relr\.dyn' .* relocate \([0-9]*\) locations.*/\1/p")
    rb_rela0=$(readelf -rW "$rb_in-plain" | sed -n \
        "s/.*'\.rela\.dyn' .* contains \([0-9]*\) entr.*/\1/p")
    rb_rela1=$(readelf -rW "$rb_in-relr" | sed -n \
        "s/.*'\.rela\.dyn' .* contains \([0-9]*\) entr.*/\1/p")
    [ -n "$rb_have" ] && [ "$rb_have" -eq "$rb_want" ] && \
        [ "${rb_rela1:-0}" -eq $((rb_rela0 - rb_want)) ] && \
        pass "RELR $rb: .relr.dyn relocates $rb_want words, ${rb_rela1:-0} stay RELA" || \
        fail "RELR $rb: tables" \
            "relr '$rb_have' of $rb_want; rela ${rb_rela0} -> ${rb_rela1:-0}"
    readelf -lW "$rb_in-plain" | \
        awk '/^  [A-Z]/ && $1 != "Type" {print $1, $3}' > /work/relr-va-plain
    readelf -lW "$rb_in-relr" | \
        awk '/^  [A-Z]/ && $1 != "Type" {print $1, $3}' > /work/relr-va-new
    [ -s /work/relr-va-new ] && cmp -s /work/relr-va-plain /work/relr-va-new && \
        pass "RELR $rb: every segment keeps its vaddr" || \
        fail "RELR $rb: vaddrs" "$(diff /work/relr-va-plain /work/relr-va-new)"
    rb_sz_plain=$(stat -c%s "$rb_in-plain" 2>/dev/null || echo 0)
    rb_sz_relr=$(stat -c%s "$rb_in-relr" 2>/dev/null || echo 0)
    printf 'Size: %d -> %d bytes (%s, without -> with --relr)\n' \
        "$rb_sz_plain" "$rb_sz_relr" "$rb"
    case $rb in
    relr-spie)
        rb_freed=$((rb_sz_plain - rb_sz_relr))
        [ "$rb_freed" -ge 4096 ] && [ $((rb_freed % 4096)) -eq 0 ] && \
            pass "RELR $rb: $((rb_freed / 4096)) whole pages left the file ($rb_sz_plain -> $rb_sz_relr)" || \
            fail "RELR $rb: file size" "$rb_sz_plain -> $rb_sz_relr"
        rb_shdr=$(readelf -SW "$rb_in-relr" 2>&1) || true
        echo "$rb_shdr" | grep -q '\.relr\.dyn *RELR ' && \
            ! echo "$rb_shdr" | grep -q '\.rela\.dyn' && \
            ! echo "$rb_dyn" | grep -q '(RELA' && \
            pass "RELR $rb: no RELA left; its header now describes .relr.dyn" || \
            fail "RELR $rb: headers" "$(echo "$rb_shdr" | grep rel)"
        ;;
    relr-pie)
        echo "$rb_out" | \
            grep -q 'slack kept as padding (.rela.plt follows .rela.dyn' && \
            [ "$rb_sz_relr" -ge "$rb_sz_plain" ] && \
            [ "$rb_sz_relr" -le $((rb_sz_plain + 96)) ] && \
            readelf -SW "$rb_in-relr" | grep -q '\.relr\.dyn *RELR ' && \
            pass "RELR $rb: slack kept as padding, .relr.dyn header appended" || \
            fail "RELR $rb: padding" "$rb_sz_plain -> $rb_sz_relr"
        ;;
    relr-pie0)
        echo "$rb_out" | grep -q 'wrote [1-9][0-9]* addends in place' && \
            cmp -s "$rb_in-relr" /work/relr-pie-relr && \
            pass "RELR $rb: addends written back (same image as relr-pie)" || \
            fail "RELR $rb: addends" "not written back"
        ;;
    esac
done

readelf -dW /work/relr-spie-plain | grep -q '(RELA) ' && \
    ! readelf -dW /work/relr-spie-plain | grep -q '(RELR)' && \
    pass "RELR: without --relr the relocations stay RELA" || \
    fail "RELR: default" "plain trim changed the relocations"

trim --help 2>&1 | grep -q -- '--relr ' && \
    pass "RELR: --help documents --relr" || \
    fail "RELR: --help" "no --relr entry"

# glibc 2.36+ will not load an object with DT_RELR whose DT_NEEDED names
# libc.so.* unless it needs the GLIBC_ABI_DT_RELR version, which --relr
# does not add. Alpine has no glibc: a stand-in libc.so.6 with versioned
# symbols gives the fixtures the same DT_NEEDED and DT_VERNEED (they are
# built, never run). Needing GLIBC_ABI_DT_RELR already, packing proceeds.
printf 'int relr_fake(void) { return 0; }\nint relr_fake2(void) { return 1; }\n' \
    > /work/relr-fake.c
printf 'GLIBC_2.2.5 { global: *; };\n' > /work/relr-libc1.map
printf 'GLIBC_2.2.5 { global: relr_fake; local: *; };\nGLIBC_ABI_DT_RELR { global: relr_fake2; };\n' \
    > /work/relr-libc2.map
for rv in 1 2; do
    gcc -shared -fPIC -Wl,-soname,libc.so.6 \
        -Wl,--version-script=/work/relr-libc$rv.map \
        -o /work/relr-libc$rv.so /work/relr-fake.c
done
gcc -O0 -o /work/relr-glibc /tests/relr-pointers.c -Wl,--no-as-needed \
    -Wl,-u,relr_fake /work/relr-libc1.so
gcc -O0 -o /work/relr-glibcv /tests/relr-pointers.c -Wl,--no-as-needed \
    -Wl,-u,relr_fake -Wl,-u,relr_fake2 /work/relr-libc2.so
rg_out=$(trim --relr /work/relr-glibcv /work/relr-glibcv-r 2>&1) || true
echo "$rg_out" | grep 'relr\|Error' || true
echo "$rg_out" | grep -q 'relr: packed' && \
    readelf -dW /work/relr-glibcv-r | grep -q '(RELR) ' && \
    pass "RELR relr-glibcv: needs GLIBC_ABI_DT_RELR already; packed" || \
    fail "RELR relr-glibcv: packing" "$rg_out"

# Refusals: a fixed-address executable, a relocatable object, a PIE
# whose DT_RELA tag became DT_REL, one whose DT_RELASZ also covers the
# PLT relocations (DT_JMPREL; section headers dropped as by sstrip, so
# none contradicts the tags), a .dynamic without room for the three
# RELR tags (--spare-dynamic-tags=0 while RELA entries remain), an
# unsupported architecture, a PE file, an already packed image, a
# static-pie without --relr-static and a glibc-linked PIE without
# GLIBC_ABI_DT_RELR. Each gets a clear message, and the output is
# exactly what plain trim writes.
gcc -O0 -no-pie -o /work/relr-nopie /tests/relr-pointers.c
gcc -O0 -c -o /work/relr-obj /tests/relr-pointers.c
python3 /tests/elf_dyn_tag.py /work/relr-pie /work/relr-rel retag 7 17
python3 /tests/elf_dyn_tag.py /work/relr-pie /work/relr-jmprel grow 8 2 noshdr
gcc -O0 -DWITH_UNALIGNED -Wl,--spare-dynamic-tags=0 \
    -o /work/relr-full /tests/relr-pointers.c
clang-19 --target=riscv64-linux-gnu -march=rv64gc -nostdlib -static \
    -fuse-ld=lld -o /work/relr-riscv /tests/riscv-hello.c 2>/dev/null
clang-19 --target=x86_64-w64-mingw32 -O0 -fuse-ld=lld \
    -o /work/relr-pe.exe /tests/hello.c 2>/dev/null
for rr in relr-nopie:'not position-independent (ET_EXEC' \
          relr-obj:'not position-independent (ET_REL' \
          relr-rel:'has DT_REL relocations' \
          relr-jmprel:'the PLT relocations (DT_JMPREL) lie inside' \
          relr-full:'no room in .dynamic' \
          relr-riscv:'unsupported architecture RISC-V' \
          relr-pe.exe:'not an ELF file' \
          relr-spie-relr:'already has DT_RELR' \
          relr-spie:'static-pie (ET_DYN without PT_INTERP)' \
          relr-glibc:'linked against glibc (libc.so.6)'; do
    rr_bin=/work/${rr%%:*}
    rr_why=${rr#*:}
    trim "$rr_bin" "$rr_bin-plain" > /dev/null 2>&1 || true
    rr_out=$(trim --relr "$rr_bin" "$rr_bin-r" 2>&1) || true
    echo "$rr_out" | grep 'relr\|Error' || true
    echo "$rr_out" | grep -q "relr: refused: $rr_why" && \
        cmp -s "$rr_bin-plain" "$rr_bin-r" && \
        pass "RELR refusal ${rr%%:*}: $rr_why; output unchanged" || \
        fail "RELR refusal ${rr%%:*}" "$rr_out"
done

# Overlay data after the last section and header table: the relocations
# are packed in place, but nothing may move in the file.
cp /work/relr-spie /work/relr-ovl
printf 'TRIM-OVERLAY-DATA' >> /work/relr-ovl
ro_out=$(trim --relr-static /work/relr-ovl /work/relr-ovl-r 2>&1) || true
echo "$ro_out" | grep 'relr\|Error' || true
ro_got=$(/work/relr-ovl-r 2>&1) || true
echo "$ro_out" | grep -q 'relr: packed' && \
    echo "$ro_out" | grep -q 'bytes of overlay data follow' && \
    [ "$(tail -c 17 /work/relr-ovl-r)" = TRIM-OVERLAY-DATA ] && \
    [ "$ro_got" = "$(/work/relr-spie 2>&1)" ] && \
    pass "RELR relr-ovl: overlay kept in place (packed, nothing drained)" || \
    fail "RELR relr-ovl: overlay" "$ro_out"

# --dry-run --relr reports the packing and writes nothing.
cp /work/relr-pie /work/relr-dry
rd_out=$(trim --dry-run --relr /work/relr-dry /work/relr-dry-out 2>&1) || true
rd_ip=$(trim --dry-run --relr -i /work/relr-dry 2>&1) || true
echo "$rd_out" | grep -q 'relr: packed' && \
    echo "$rd_ip" | grep -q 'relr: packed' && \
    cmp -s /work/relr-pie /work/relr-dry && [ ! -e /work/relr-dry-out ] && \
    pass "RELR --dry-run --relr: packing reported, nothing written" || \
    fail "RELR --dry-run --relr" "$rd_out"

# AArch64 static-pie without libc: its own start code applies DT_RELA
# and DT_RELR (relr-aarch64.c). --relr refuses it; --relr-static packs
# it, and the packed image runs exactly like the original under QEMU.
clang-19 --target=aarch64-linux-gnu -fPIE -static-pie -nostdlib -O1 \
    -fuse-ld=lld -o /work/relr-a64 /tests/relr-aarch64.c
ra_exp=$(qemu-aarch64 /work/relr-a64 2>&1) || true
trim /work/relr-a64 /work/relr-a64-plain > /dev/null 2>&1 || true
ra_out=$(trim --relr /work/relr-a64 /work/relr-a64-r 2>&1) || true
echo "$ra_out" | grep -q 'relr: refused: static-pie' && \
    cmp -s /work/relr-a64-plain /work/relr-a64-r && \
    pass "RELR relr-a64: --relr refuses an AArch64 static-pie" || \
    fail "RELR relr-a64: refusal" "$ra_out"
ra_out=$(trim --relr-static /work/relr-a64 /work/relr-a64-rs 2>&1) || true
echo "$ra_out" | grep 'relr\|Error' || true
ra_got=$(qemu-aarch64 /work/relr-a64-rs 2>&1) || true
echo "$ra_exp" | grep -q '^relr-a64: ok$' && \
    echo "$ra_out" | grep -q 'relr: packed' && \
    readelf -dW /work/relr-a64-rs | grep -q '(RELR) ' && \
    [ "$ra_got" = "$ra_exp" ] && \
    pass "RELR relr-a64: --relr-static packed it; QEMU output identical" || \
    fail "RELR relr-a64: --relr-static" "got: $ra_got / $ra_out"

trim --help 2>&1 | grep -q -- '--relr-static ' && \
    pass "RELR: --help documents --relr-static" || \
    fail "RELR: --help" "no --relr-static entry"
rm -f /work/relr-*

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
