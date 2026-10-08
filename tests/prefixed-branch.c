/* Regression fixture: relative branches behind legacy prefixes (x86-64).
 * Build: gcc -O0 (PIE or static).
 *
 * Linkers relax `call *f@GOTPCREL(%rip)` into `addr32 call f` (67 E8),
 * CET code marks branches `notrack` (3E) and MPX code `bnd` (F2). The
 * prefix leaves the rel32 displacement in place, one byte further in.
 *
 * Layout (one asm block, so the order is fixed): dead_head, the
 * probes, dead_middle, the targets. trim removes both dead functions,
 * so every probe moves and every target moves further: each forward
 * displacement must shrink by the size of dead_middle, and the one
 * backward call (from after dead_middle to before it) must grow. A
 * displacement left stale lands in the wrong place: the program prints
 * a wrong value or crashes. */
#include <stdio.h>

int probe_addr32_call(void);
int probe_notrack_jmp(void);
int probe_bnd_jmp(void);
int probe_bnd_call(void);
int probe_hint_jcc(int taken);
int probe_back_call(void);

/* Dead filler: 100 three-byte adds, never referenced (local: global
 * functions are roots). */
#define DEAD_BODY ".rept 100\n\taddl $1, %eax\n\t.endr\n\tret\n"

/* A branch spelled as bytes: assemblers drop `addr32` on `call` and no
 * longer accept `bnd`, so the opcode bytes are given and the rel32 is
 * computed against a local target in the same section. */
#define REL32(bytes, target) \
    ".byte " bytes "\n\t.long " target " - . - 4\n\t"

/* A global function symbol for trim's function map. */
#define GLOBAL_FN(name, body) \
    ".globl " name "\n" LOCAL_FN(name, body)

/* A local function symbol for trim's function map. */
#define LOCAL_FN(name, body) \
    ".type " name ", @function\n" name ":\n\t" body \
    ".size " name ", .-" name "\n"

__asm__(
    ".text\n"
    LOCAL_FN("dead_head", DEAD_BODY)

    /* 67 E8: returns target_a() + 1 = 42. */
    GLOBAL_FN("probe_addr32_call",
        REL32("0x67, 0xe8", "target_a")
        "addl $1, %eax\n\tret\n")

    /* 3E E9: tail jump to target_b (7). */
    GLOBAL_FN("probe_notrack_jmp",
        "xorl %eax, %eax\n\t"
        REL32("0x3e, 0xe9", "target_b") "\n")

    /* F2 E9: tail jump to target_c (9). */
    GLOBAL_FN("probe_bnd_jmp", REL32("0xf2, 0xe9", "target_c") "\n")

    /* F2 E8: returns target_e() * 2 = 26. */
    GLOBAL_FN("probe_bnd_call",
        REL32("0xf2, 0xe8", "target_e")
        "addl %eax, %eax\n\tret\n")

    /* 3E 0F 85: jne (hint taken) to target_d (11) when taken != 0. */
    GLOBAL_FN("probe_hint_jcc",
        "cmpl $0, %edi\n\t"
        REL32("0x3e, 0x0f, 0x85", "target_d")
        "movl $-1, %eax\n\tret\n")

    /* Target of the backward call from probe_back_call: 5. */
    LOCAL_FN("back_target", "movl $5, %eax\n\tret\n")

    LOCAL_FN("dead_middle", DEAD_BODY)

    LOCAL_FN("target_a", "movl $41, %eax\n\tret\n")
    LOCAL_FN("target_b", "movl $7, %eax\n\tret\n")
    LOCAL_FN("target_c", "movl $9, %eax\n\tret\n")
    LOCAL_FN("target_d", "movl $11, %eax\n\tret\n")
    LOCAL_FN("target_e", "movl $13, %eax\n\tret\n")

    /* 67 E8 backward: returns back_target() + 100 = 105. */
    GLOBAL_FN("probe_back_call",
        REL32("0x67, 0xe8", "back_target")
        "addl $100, %eax\n\tret\n")
);

/* Run every probe and compare with the expected values. */
int main(void)
{
    int got[6] = {
        probe_addr32_call(), probe_notrack_jmp(), probe_bnd_jmp(),
        probe_bnd_call(), probe_hint_jcc(1), probe_back_call(),
    };
    static const int want[6] = { 42, 7, 9, 26, 11, 105 };
    int bad = 0;
    for (int i = 0; i < 6; i++)
        bad += got[i] != want[i];
    printf("prefixed: %d %d %d %d %d %d\n",
           got[0], got[1], got[2], got[3], got[4], got[5]);
    printf("prefixed-branch: %s\n", bad ? "FAIL" : "ok");
    return bad != 0;
}
