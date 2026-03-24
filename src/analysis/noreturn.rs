//! Noreturn function detection for dead-code-after-call analysis.
//!
//! Maintains a static set of function names known to never return
//! to their caller (e.g., `exit`, `abort`, `longjmp`). When a call
//! to one of these is detected, all subsequent code until the next
//! branch target is marked as dead.

use std::collections::HashSet;
use std::sync::LazyLock;

/// Functions known to never return to their caller.
pub static NORETURN_FUNCS: LazyLock<HashSet<&'static str>> =
    LazyLock::new(|| {
        [
            "exit",
            "_exit",
            "_Exit",
            "abort",
            "__stack_chk_fail",
            "__assert_fail",
            "__assert_rtn",
            "longjmp",
            "_longjmp",
            "siglongjmp",
            "__cxa_throw",
            "__cxa_rethrow",
            "pthread_exit",
            "thrd_exit",
            "ExitProcess",
            "TerminateProcess",
            "RaiseException",
            "__fortify_fail",
            "__libc_fatal",
            "__builtin_unreachable",
            "__ubsan_handle_builtin_unreachable",
            "rust_begin_unwind",
            "__assert2",
        ]
        .into_iter()
        .collect()
    });
