/* No standard headers — declare everything manually
   so the compiler does not know exit() is noreturn. */
extern int printf(const char *format, ...);
extern void exit(int);

/* Function with dead code after exit() call.
   Compiler does not know exit is noreturn because we
   declared it without the attribute. */
int noreturn_dead(int x) {
    if (x < 0) {
        printf("negative\n");
        exit(1);
        /* Dead: code after exit() is unreachable */
        printf("this never runs\n");
        return -1;
    }
    return x * 2;
}

/* Live function that calls noreturn_dead */
int live_caller(int a, int b) {
    int r = noreturn_dead(a);
    return r + b;
}

int main(int argc, char *argv[]) {
    int x = live_caller(argc, 2);
    printf("result: %d\n", x);
    return 0;
}
