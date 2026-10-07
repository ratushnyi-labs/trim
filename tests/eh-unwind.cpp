/* C++ exception unwinding through code moved by compaction.
 * More than 4K of dead code sits BEFORE the live throw/catch chain, so
 * every live function moves by the per-interval shift while .eh_frame,
 * .eh_frame_hdr and .gcc_except_table move by the page-aligned shrink.
 * Unless each FDE's pc_begin and the .eh_frame_hdr search table are
 * re-pointed, the unwinder cannot find the frames and std::terminate()
 * aborts the program. Some dead functions carry their own try/catch so
 * their FDEs (with LSDA pointers) must be neutralised, not left aliasing
 * the live code that slides into their place. Every dead function calls
 * itself, which gives it a function start even in a stripped binary
 * (call-target inference) while keeping it unreachable. */
#include <cstdio>
#include <stdexcept>

#define DEAD(name, c1, c2, c3) \
static int name(int a, int b) { \
    int r = a * c1 + b; \
    r = r * c2 - a * c3; \
    r = (r ^ (r >> 3)) + c1 * b; \
    r = r * a - b * c2 + c3; \
    r = (r ^ (r >> 5)) + c1 * c2; \
    r = r + a * c3 - b * c1; \
    r = (r ^ (r >> 7)) * c2 + c3; \
    r = r * b - a * c3 + c1; \
    r = (r ^ (r >> 2)) + a * b; \
    r = r + b * c2 - a * c1 + c3; \
    if (r == c3) \
        return name(b, a); \
    return r; \
}

/* Dead function with its own landing pad (FDE with an LSDA pointer). */
#define DEAD_EH(name, c1, c2) \
static int name(int a) { \
    try { \
        if (a * c1 > c2) throw std::runtime_error("dead"); \
        return a > c2 ? name(a - 1) : a * c2 - c1; \
    } catch (const std::exception &) { \
        return -c1; \
    } \
}

DEAD(dead_f01, 7, 13, 31)
DEAD_EH(dead_eh01, 3, 97)
DEAD(dead_f02, 11, 17, 37)
DEAD(dead_f03, 3, 19, 41)
DEAD(dead_f04, 23, 29, 43)
DEAD_EH(dead_eh02, 5, 89)
DEAD(dead_f05, 5, 31, 47)
DEAD(dead_f06, 37, 41, 53)
DEAD(dead_f07, 43, 47, 59)
DEAD(dead_f08, 53, 59, 61)
DEAD_EH(dead_eh03, 7, 83)
DEAD(dead_f09, 67, 71, 73)
DEAD(dead_f10, 79, 83, 89)
DEAD(dead_f11, 97, 101, 103)
DEAD(dead_f12, 107, 109, 113)
DEAD(dead_f13, 127, 131, 137)
DEAD(dead_f14, 139, 149, 151)
DEAD(dead_f15, 157, 163, 167)
DEAD(dead_f16, 173, 179, 181)
DEAD(dead_f17, 191, 193, 197)
DEAD(dead_f18, 199, 211, 223)
DEAD(dead_f19, 227, 229, 233)
DEAD(dead_f20, 239, 241, 251)
DEAD(dead_f21, 257, 263, 269)
DEAD(dead_f22, 271, 277, 281)
DEAD(dead_f23, 283, 293, 307)
DEAD(dead_f24, 311, 313, 317)
DEAD(dead_f25, 331, 337, 347)
DEAD(dead_f26, 349, 353, 359)
DEAD(dead_f27, 367, 373, 379)
DEAD(dead_f28, 383, 389, 397)
DEAD(dead_f29, 401, 409, 419)
DEAD(dead_f30, 421, 431, 433)

/* Live code: an exception thrown three frames deep, with a destructor
 * (cleanup landing pad) to run in every frame it unwinds through. */
static int unwound = 0;

struct Guard {
    ~Guard() { ++unwound; }
};

__attribute__((noinline)) static int live_level3(int x) {
    Guard g;
    if (x > 2)
        throw std::runtime_error("boom");
    return x;
}

__attribute__((noinline)) static int live_level2(int x) {
    Guard g;
    return live_level3(x + 1) * 2;
}

__attribute__((noinline)) static int live_level1(int x) {
    Guard g;
    return live_level2(x + 1) + 1;
}

__attribute__((noinline)) static int live_run(int x) {
    try {
        return live_level1(x);
    } catch (const std::runtime_error &e) {
        std::printf("caught: %s\n", e.what());
        return -1;
    }
}

int main() {
    int thrown = live_run(1);
    int normal = live_run(0);
    std::printf("result: %d %d unwound: %d\n", thrown, normal, unwound);
    std::printf("marker: eh-unwind done\n");
    return 0;
}
