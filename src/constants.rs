//! Compile-time constants for the dead-code analysis pipeline.
//!
//! Contains the set of runtime/startup function names that must
//! always be kept alive regardless of reachability analysis.
//! These include C runtime entry points, linker-generated symbols,
//! and platform-specific initializers for Linux, musl, Windows PE,
//! MIPS, and ARM.

use std::collections::HashSet;
use std::sync::LazyLock;

/// Set of function names that must always be treated as live roots.
/// These are runtime/startup symbols that the linker or OS loader
/// calls directly, bypassing normal call-graph edges.
pub static RUNTIME_KEEP: LazyLock<HashSet<&'static str>> =
    LazyLock::new(|| {
        [
            "_start",
            "main",
            "_init",
            "_fini",
            "__libc_start_main",
            "__libc_csu_init",
            "__libc_csu_fini",
            "__libc_start_call_main",
            "_dl_relocate_static_pie",
            "frame_dummy",
            "register_tm_clones",
            "deregister_tm_clones",
            "__do_global_dtors_aux",
            "__do_global_ctors_aux",
            "__init_libc",
            "__init_tls",
            "__copy_tls",
            "atexit",
            "__cxa_atexit",
            "__cxa_finalize",
            "exit",
            "_exit",
            "__stack_chk_fail",
            "__stack_chk_guard",
            "_start_c",
            "__funcs_on_exit",
            "__stdio_exit",
            "__libc_exit_fini",
            "__dls3",
            "__dls2b",
            "DllMain",
            "DllMainCRTStartup",
            "WinMainCRTStartup",
            "mainCRTStartup",
            "_mainCRTStartup",
            "wmainCRTStartup",
            "__main",
            "__security_init_cookie",
            // MIPS entry point
            "__start",
            // ARM runtime symbols
            "__aeabi_unwind_cpp_pr0",
            "__aeabi_unwind_cpp_pr1",
            "__aeabi_unwind_cpp_pr2",
            "__aeabi_memcpy",
            "__aeabi_memset",
            "__aeabi_memclr",
            "__arm_personality_routine",
            "__gnu_unwind_frame",
            // PE additional symbols
            "_CRT_INIT",
            "__security_check_cookie",
            "_guard_check_icall",
        ]
        .into_iter()
        .collect()
    });
