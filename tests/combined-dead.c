/* Combined test: both dead functions AND dead branches.
   No standard headers — declare everything manually
   so the compiler does not know exit() is noreturn. */
extern int printf(const char *format, ...);
extern void exit(int);

/* Dead function: never called from main or live code */
static int dead_compute(int a, int b) {
    int result = 0;
    for (int i = 0; i < a; i++) {
        result += b * i;
    }
    return result;
}

/* Dead function: also never called */
static int dead_factorial(int n) {
    if (n <= 1) return 1;
    return n * dead_factorial(n - 1);
}

/* Live function with dead branch after exit() */
int process(int x) {
    if (x < 0) {
        printf("negative\n");
        exit(1);
        /* Dead branch: unreachable after exit() */
        printf("this never runs\n");
        printf("this also never runs\n");
        return -999;
    }
    return x * 2;
}

/* Another live function with dead branch */
int validate(int x) {
    if (x > 1000) {
        printf("overflow\n");
        exit(2);
        /* Dead branch: unreachable */
        printf("unreachable validation\n");
        return -1;
    }
    return x + 1;
}

int main(int argc, char *argv[]) {
    int a = process(argc);
    int b = validate(a);
    printf("result: %d\n", b);
    return 0;
}
