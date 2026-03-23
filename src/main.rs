use std::io::{self, Read, Write};
use std::process;

const VERSION: &str = match option_env!("TRIM_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};

const LICENSE: &str = include_str!("../LICENSE");

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let parsed = match parse_args(&args[1..]) {
        Ok(a) => a,
        Err(msg) => {
            eprintln!("Error: {}", msg);
            process::exit(1);
        }
    };
    match parsed {
        Action::Help => {
            eprint_usage();
            process::exit(0);
        }
        Action::Version => {
            println!("trim {}", VERSION);
            process::exit(0);
        }
        Action::License => {
            println!("{}", LICENSE);
            process::exit(0);
        }
        Action::InPlace { dry_run, files, max_sccp } => {
            process::exit(run_in_place(&files, dry_run, max_sccp));
        }
        Action::Stream { dry_run, input, output, max_sccp } => {
            process::exit(run_stream(
                &input, output.as_deref(), dry_run, max_sccp,
            ));
        }
    }
}

enum Action {
    Help,
    Version,
    License,
    InPlace { dry_run: bool, files: Vec<String>, max_sccp: usize },
    Stream { dry_run: bool, input: String, output: Option<String>, max_sccp: usize },
}

fn parse_args(args: &[String]) -> Result<Action, String> {
    if args.is_empty() {
        eprint_usage();
        return Err("no arguments provided".to_string());
    }
    let mut in_place = false;
    let mut dry_run = false;
    let mut max_sccp = trim::analysis::sccp::DEFAULT_MAX_INSTRS;
    let mut positional = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => return Ok(Action::Help),
            "--version" | "-v" => return Ok(Action::Version),
            "--license" | "-l" => return Ok(Action::License),
            "--in-place" | "-i" => in_place = true,
            "--dry-run" => dry_run = true,
            "--max-sccp-instrs" => {
                i += 1;
                max_sccp = parse_max_sccp(&args, i)?;
            }
            s if s.starts_with("--max-sccp-instrs=") => {
                let val = &s["--max-sccp-instrs=".len()..];
                max_sccp = val.parse::<usize>().map_err(|_| {
                    format!("invalid --max-sccp-instrs value: {}", val)
                })?;
            }
            s if s.starts_with('-') && s != "-" => {
                return Err(format!("unknown option: {}", s));
            }
            _ => positional.push(args[i].clone()),
        }
        i += 1;
    }
    if in_place {
        if positional.is_empty() {
            return Err("--in-place requires at least one file".into());
        }
        return Ok(Action::InPlace { dry_run, files: positional, max_sccp });
    }
    if positional.is_empty() {
        eprint_usage();
        return Err("no input specified".to_string());
    }
    if positional.len() > 2 {
        return Err("too many arguments (use --in-place for multiple files)".into());
    }
    let input = positional[0].clone();
    let output = positional.get(1).cloned();
    Ok(Action::Stream { dry_run, input, output, max_sccp })
}

fn parse_max_sccp(
    args: &[String],
    i: usize,
) -> Result<usize, String> {
    if i >= args.len() {
        return Err("--max-sccp-instrs requires a value".into());
    }
    args[i].parse::<usize>().map_err(|_| {
        format!("invalid --max-sccp-instrs value: {}", args[i])
    })
}

fn run_in_place(
    files: &[String],
    dry_run: bool,
    max_sccp: usize,
) -> i32 {
    let mut rc = 0;
    for path in files {
        match trim::process_file(path, dry_run, max_sccp) {
            Ok(result) => {
                if result != 0 {
                    rc = result;
                }
            }
            Err(e) => {
                eprintln!("Error: {}", e);
                rc = 1;
            }
        }
    }
    rc
}

fn read_input(input: &str) -> Result<Vec<u8>, i32> {
    if input == "-" {
        read_stdin().map_err(|e| {
            eprintln!("Error: {}", e);
            1
        })
    } else {
        std::fs::read(input).map_err(|e| {
            eprintln!("Error: '{}' not found: {}", input, e);
            1
        })
    }
}

fn write_output(path: &str, data: &[u8]) -> i32 {
    if let Err(e) = std::fs::write(path, data) {
        eprintln!("Error: cannot write '{}': {}", path, e);
        return 1;
    }
    set_executable(path);
    0
}

fn run_stream(
    input: &str,
    output: Option<&str>,
    dry_run: bool,
    max_sccp: usize,
) -> i32 {
    let data = match read_input(input) {
        Ok(d) => d,
        Err(rc) => return rc,
    };
    let label = if input == "-" { "<stdin>" } else { input };
    let result = match trim::process_bytes(
        &data, label, dry_run, max_sccp,
    ) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error: {}", e);
            return 1;
        }
    };
    if dry_run {
        return 0;
    }
    let out_data = match result {
        Some(patched) => patched,
        None => data,
    };
    if let Some(path) = output {
        return write_output(path, &out_data);
    }
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    if let Err(e) = handle.write_all(&out_data) {
        eprintln!("Error: {}", e);
        return 1;
    }
    0
}

#[cfg(unix)]
fn set_executable(path: &str) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_mode(perms.mode() | 0o111);
        let _ = std::fs::set_permissions(path, perms);
    }
}

#[cfg(not(unix))]
fn set_executable(_path: &str) {}

fn read_stdin() -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    io::stdin().lock().read_to_end(&mut buf)?;
    Ok(buf)
}

fn eprint_usage() {
    eprintln!(
        "trim {VERSION}\n\
         Author: Pavlo Ratushnyi\n\
         \n\
         Usage: trim [OPTIONS] <INPUT> [OUTPUT]\n\
         \n\
         Find and remove dead code from executables.\n\
         Supports: ELF, PE/COFF, Mach-O, .NET\n\
         \n\
         Modes:\n\
         \x20 trim INPUT OUTPUT       Write patched binary to OUTPUT\n\
         \x20 trim INPUT              Write patched binary to stdout\n\
         \x20 trim -                  Read stdin, write to stdout\n\
         \x20 trim -i FILE [FILE...]  Modify files in-place\n\
         \x20 trim --dry-run INPUT    Analyze only, report to stderr\n\
         \n\
         Options:\n\
         \x20 --in-place, -i          Modify files in-place\n\
         \x20 --dry-run               Report dead code without producing output\n\
         \x20 --max-sccp-instrs N     Max instructions per function for SCCP\n\
         \x20                         analysis (default: 10000)\n\
         \x20 --version, -v           Show version\n\
         \x20 --license, -l           Show license\n\
         \x20 --help, -h              Show this help message\n\
         \n\
         DISCLAIMER: This software performs disassembly and binary\n\
         modification of executable files. Processing software you do\n\
         not own or lack authorization to modify may violate applicable\n\
         license agreements, terms of service, or laws. The user assumes\n\
         all responsibility for ensuring lawful use."
    );
}
