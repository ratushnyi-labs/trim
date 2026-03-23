/* Test binary with dead functions at the end of .text.
 * Used to verify trim can truncate trailing dead code. */
#include <stdio.h>

int live_add(int a, int b) { return a + b; }
int live_mul(int a, int b) { return a * b; }

int main(void) {
    printf("result: %d\n", live_add(2, 3) + live_mul(4, 5));
    return 0;
}

/* Dead functions placed last in source — compiler emits them at the
 * end of .text (after main), so they can be truncated. */
static int dead_big(int n) {
    int s = 0;
    for (int i = 0; i < n; i++) {
        s += i * i;
    }
    return s;
}

static int dead_also(int x) {
    return x * x * x + dead_big(x);
}
