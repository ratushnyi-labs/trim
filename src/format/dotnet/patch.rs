//! .NET MethodDef RVA and CLI header patching after physical compaction.
//!
//! After dead method bodies are removed and the `.text` section is
//! compacted, all RVA-based references must be shifted downward to
//! account for the removed bytes. This module handles:
//!
//! - **MethodDef RVA patching** -- iterates every row in the MethodDef
//!   metadata table and subtracts the cumulative shift for each RVA that
//!   falls within the compacted range.
//! - **CLI header RVA patching** -- adjusts the seven RVA fields in the
//!   CLI header (metadata, resources, strong-name, code-manager, vtable,
//!   export-address, native-header).
//! - **Dead method zeroing** -- replaces method IL bodies with a single
//!   `ret` opcode (0x2A) followed by zero-fill before physical compaction.

use crate::format::dotnet::metadata::read_u32;
use crate::patch::relocs::total_shift;

/// Write a little-endian `u32` into `data` at `off`. No-op if OOB.
fn write_u32(data: &mut [u8], off: usize, val: u32) {
    if off + 4 <= data.len() {
        data[off..off + 4]
            .copy_from_slice(&val.to_le_bytes());
    }
}

/// Shift MethodDef RVAs to account for compacted dead intervals.
pub fn patch_method_rvas(
    data: &mut [u8],
    table_off: usize,
    row_size: usize,
    count: usize,
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
) {
    for i in 0..count {
        let off = table_off + i * row_size;
        if off + 4 > data.len() {
            break;
        }
        let rva = read_u32(data, off);
        if rva == 0 {
            continue;
        }
        let shift =
            total_shift(rva as u64, intervals, ts, te);
        if shift > 0 {
            write_u32(
                data,
                off,
                (rva as u64 - shift) as u32,
            );
        }
    }
}

/// Shift CLI header RVA fields after compaction.
pub fn patch_cli_rvas(
    data: &mut [u8],
    cli_offset: usize,
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
) {
    // CLI header RVA fields: metadata(+8), resources(+24),
    // strong_name(+32), code_manager(+40), vtable(+48),
    // export_addr(+56), native_header(+64)
    let rva_fields = [8, 24, 32, 40, 48, 56, 64];
    for &field_off in &rva_fields {
        let off = cli_offset + field_off;
        if off + 4 > data.len() {
            break;
        }
        let rva = read_u32(data, off);
        if rva == 0 {
            continue;
        }
        let shift =
            total_shift(rva as u64, intervals, ts, te);
        if shift > 0 {
            write_u32(
                data,
                off,
                (rva as u64 - shift) as u32,
            );
        }
    }
}

/// Zero dead IL method bodies, replacing with `ret`.
/// Returns (count_patched, bytes_saved).
pub fn zero_dead_methods(
    data: &mut Vec<u8>,
    dead_rvas: &[(u32, String)],
    rva_to_offset: &dyn Fn(u32) -> Option<usize>,
) -> (usize, u64) {
    let mut count = 0usize;
    let mut saved = 0u64;
    for (rva, _name) in dead_rvas {
        if let Some(off) = rva_to_offset(*rva) {
            let freed = zero_method_body(data, off);
            if freed > 0 {
                count += 1;
                saved += freed;
            }
        }
    }
    (count, saved)
}

/// Zero a single IL method body: write `ret` (0x2A) at the first code
/// byte and fill the remainder with zeros. Returns bytes freed.
fn zero_method_body(
    data: &mut Vec<u8>,
    offset: usize,
) -> u64 {
    if offset >= data.len() {
        return 0;
    }
    let header = data[offset];
    let (code_off, code_size) = if header & 0x03 == 0x02 {
        let sz = (header >> 2) as usize;
        (offset + 1, sz)
    } else if header & 0x03 == 0x03 {
        parse_fat_size(data, offset)
    } else {
        return 0;
    };
    if code_size <= 1 || code_off + code_size > data.len()
    {
        return 0;
    }
    data[code_off] = 0x2A;
    for i in 1..code_size {
        data[code_off + i] = 0x00;
    }
    (code_size - 1) as u64
}

/// Parse a fat method header to extract `(code_offset, code_size)`.
fn parse_fat_size(
    data: &[u8],
    offset: usize,
) -> (usize, usize) {
    if offset + 12 > data.len() {
        return (0, 0);
    }
    let flags_size = data[offset] as u16
        | ((data[offset + 1] as u16) << 8);
    let hdr_size = ((flags_size >> 12) & 0x0F) * 4;
    let code_size = read_u32(data, offset + 4) as usize;
    (offset + hdr_size as usize, code_size)
}
