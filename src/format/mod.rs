pub mod dotnet;
pub mod elf;
pub mod macho;
pub mod pe;
pub mod wasm;

/// Detected binary format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Elf,
    Pe,
    MachO,
    Dotnet,
    Wasm,
}

/// Detect binary format from magic bytes.
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
    None
}

fn is_macho_magic(data: &[u8]) -> bool {
    let m = u32::from_le_bytes(
        data[..4].try_into().unwrap_or([0; 4]),
    );
    matches!(m, 0xFEED_FACE | 0xFEED_FACF | 0xCEFA_EDFE | 0xCFFA_EDFE)
}

fn is_wasm_magic(data: &[u8]) -> bool {
    data[0] == 0x00
        && data[1] == 0x61
        && data[2] == 0x73
        && data[3] == 0x6D
}
