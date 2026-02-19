use std::collections::HashSet;
use std::sync::LazyLock;

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
        ]
        .into_iter()
        .collect()
    });
