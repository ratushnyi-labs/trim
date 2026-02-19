/* Library with exported functions + dead internal code.
 * Used for testing .so, .dll, .wasm, and Mach-O stripping. */

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

/* ============================================================
 * DEAD CODE: internal functions never called by anyone.
 * ============================================================ */

static int dead_factorial(int n) {
    if (n <= 1) return 1;
    return n * dead_factorial(n - 1);
}

static const int dead_table[64] = {
     0,  1,  2,  3,  4,  5,  6,  7,
     8,  9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23,
    24, 25, 26, 27, 28, 29, 30, 31,
    32, 33, 34, 35, 36, 37, 38, 39,
    40, 41, 42, 43, 44, 45, 46, 47,
    48, 49, 50, 51, 52, 53, 54, 55,
    56, 57, 58, 59, 60, 61, 62, 63,
};

static int dead_heavy(int a, int b) {
    int sum = 0;
    for (int i = 0; i < a; i++) {
        sum += dead_table[i & 63] * b;
    }
    return sum;
}

static int dead_unused_entirely(int x) {
    return x * x * x + dead_factorial(x);
}

/* ============================================================
 * LIVE CODE: exported API functions.
 * ============================================================ */

EXPORT int add(int a, int b) {
    return a + b;
}

EXPORT int multiply(int a, int b) {
    return a * b;
}

EXPORT int compute(int mode, int a, int b) {
    if (mode == 0) return add(a, b);
    if (mode == 1) return multiply(a, b);
    return 0;
}
