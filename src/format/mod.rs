//! Binary format detection and dispatch.
//!
//! Identifies the binary format of an input file by inspecting magic bytes,
//! then delegates to the appropriate format-specific module for analysis
//! and compaction (ELF, PE/COFF, Mach-O, .NET, Wasm, Java).

pub mod dotnet;
pub mod elf;
pub mod java;
pub mod macho;
pub mod pe;
pub mod wasm;

/// Detected binary format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Linux/Unix ELF binary.
    Elf,
    /// Windows PE/COFF binary.
    Pe,
    /// macOS/iOS Mach-O binary.
    MachO,
    /// .NET (CLI) assembly.
    Dotnet,
    /// WebAssembly module.
    Wasm,
    /// Java .class file.
    Java,
}

/// Detect binary format from the first few magic bytes of `data`.
///
/// Returns `None` if the format is unrecognized.
pub fn detect_format(data: &[u8]) -> Option<Format> {
    if data.len() >= 4 && data[..4] == *b"\x7fELF" {
        return Some(Format::Elf);
    }
    if data.len() >= 2 && data[..2] == *b"MZ" {
        if dotnet::metadata::has_cli_header(data) {
            return Some(Format::Dotnet);
        }
        return Some(Format::Pe);
    }
    if data.len() >= 4 && is_macho_magic(data) {
        return Some(Format::MachO);
    }
    if data.len() >= 4 && is_wasm_magic(data) {
        return Some(Format::Wasm);
    }
    if data.len() >= 4 && is_java_magic(data) {
        return Some(Format::Java);
    }
    None
}

/// Check for Java class file magic (0xCAFEBABE).
fn is_java_magic(data: &[u8]) -> bool {
    data[0] == 0xCA
        && data[1] == 0xFE
        && data[2] == 0xBA
        && data[3] == 0xBE
}

/// Check for Mach-O magic (32-bit, 64-bit, or byte-swapped).
fn is_macho_magic(data: &[u8]) -> bool {
    let m = u32::from_le_bytes(
        data[..4].try_into().unwrap_or([0; 4]),
    );
    matches!(m, 0xFEED_FACE | 0xFEED_FACF | 0xCEFA_EDFE | 0xCFFA_EDFE)
}

/// Check for WebAssembly module magic (`\0asm`).
fn is_wasm_magic(data: &[u8]) -> bool {
    data[0] == 0x00
        && data[1] == 0x61
        && data[2] == 0x73
        && data[3] == 0x6D
}
