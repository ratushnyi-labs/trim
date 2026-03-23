#include <stdio.h>
#include <string.h>

/* ============================================================
 * DEAD CODE: these functions are never called from anywhere.
 * trim should detect and patch them out.
 * ============================================================ */

static int dead_compute(int a, int b) {
    int result = 0;
    for (int i = 0; i < a; i++) {
        result += b * i;
    }
    return result;
}

static const char dead_banner[] =
    "This is a dead string constant that should be identified "
    "as unreachable dead data associated with dead_get_message.";

static const char *dead_get_message(void) {
    return dead_banner;
}

static int dead_factorial(int n) {
    if (n <= 1) return 1;
    return n * dead_factorial(n - 1);
}

static const int dead_lookup[64] = {
     0,  1,  2,  3,  4,  5,  6,  7,
     8,  9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23,
    24, 25, 26, 27, 28, 29, 30, 31,
    32, 33, 34, 35, 36, 37, 38, 39,
    40, 41, 42, 43, 44, 45, 46, 47,
    48, 49, 50, 51, 52, 53, 54, 55,
    56, 57, 58, 59, 60, 61, 62, 63,
};

static int dead_table_sum(void) {
    int sum = 0;
    for (int i = 0; i < 64; i++) {
        sum += dead_lookup[i];
    }
    return sum;
}

static void dead_fill_buffer(char *buf, int len) {
    memset(buf, 'X', len);
    buf[len - 1] = '\0';
}

/* ============================================================
 * LIVE CODE: called directly or indirectly from main.
 * trim must NOT touch these.
 * ============================================================ */

static int live_add(int a, int b) {
    return a + b;
}

static int live_multiply(int a, int b) {
    return a * b;
}

int main(int argc, char *argv[]) {
    int x = live_add(argc, 2);
    int y = live_multiply(x, 3);
    printf("result: %d\n", y);
    for (int i = 1; i < argc; i++) {
        printf("arg[%d]: %s\n", i, argv[i]);
    }
    return 0;
}
