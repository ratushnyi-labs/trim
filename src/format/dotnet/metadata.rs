//! .NET metadata root and stream parsing.
//!
//! Reads the PE/COFF headers to locate the CLI header
//! (DataDirectory entry 14), then parses the CLI header to find the
//! metadata root (`BSJB` signature). From the metadata root it enumerates
//! stream headers (`#~` or `#-` for tables, `#Strings`, `#Blob`) and
//! records their file offsets and sizes.
//!
//! Key types:
//! - `CliHeader` -- parsed CLI header (metadata RVA, entry-point token,
//!   flags).
//! - `MetadataRoot` -- absolute file offsets for the `#~`, `#Strings`,
//!   and `#Blob` streams.
//!
//! The parser returns `None` on any malformed or truncated input rather
//! than panicking.

use std::collections::HashMap;

/// CLI header parsed from PE DataDirectory[14].
pub struct CliHeader {
    pub metadata_rva: u32,
    pub metadata_size: u32,
    pub entry_point_token: u32,
    pub flags: u32,
}

/// Metadata root with stream offsets.
pub struct MetadataRoot {
    pub tables_offset: usize,
    pub tables_size: usize,
    pub strings_offset: usize,
    pub strings_size: usize,
    pub blob_offset: usize,
    pub blob_size: usize,
}

/// Parse CLI header from PE data at given file offset.
pub fn parse_cli_header(
    data: &[u8],
    offset: usize,
) -> Option<CliHeader> {
    if offset + 72 > data.len() {
        return None;
    }
    let cb = read_u32(data, offset);
    if cb < 72 {
        return None;
    }
    Some(CliHeader {
        metadata_rva: read_u32(data, offset + 8),
        metadata_size: read_u32(data, offset + 12),
        flags: read_u32(data, offset + 16),
        entry_point_token: read_u32(data, offset + 20),
    })
}

/// Parse metadata root header and locate streams.
pub fn parse_metadata_root(
    data: &[u8],
    offset: usize,
) -> Option<MetadataRoot> {
    if offset + 16 > data.len() {
        return None;
    }
    let sig = read_u32(data, offset);
    if sig != 0x424A_5342 {
        return None;
    }
    let len = read_u32(data, offset + 12) as usize;
    let streams_start = offset + 16 + round_up_4(len);
    if streams_start + 2 > data.len() {
        return None;
    }
    let num_streams =
        read_u16(data, streams_start) as usize;
    parse_streams(data, offset, streams_start + 2, num_streams)
}

/// Walk the stream headers after the metadata root, building a map of
/// stream name to `(absolute_offset, size)` and returning a `MetadataRoot`.
fn parse_streams(
    data: &[u8],
    base: usize,
    mut pos: usize,
    count: usize,
) -> Option<MetadataRoot> {
    let mut streams: HashMap<String, (usize, usize)> =
        HashMap::new();
    for _ in 0..count {
        if pos + 8 > data.len() {
            return None;
        }
        let off = read_u32(data, pos) as usize;
        let sz = read_u32(data, pos + 4) as usize;
        pos += 8;
        let name = read_cstr(data, pos)?;
        let name_len = name.len() + 1;
        pos += round_up_4(name_len);
        streams.insert(name, (base + off, sz));
    }
    let (to, ts) = streams.get("#~").copied()
        .or_else(|| streams.get("#-").copied())?;
    let (so, ss) =
        streams.get("#Strings").copied().unwrap_or((0, 0));
    let (bo, bs) =
        streams.get("#Blob").copied().unwrap_or((0, 0));
    Some(MetadataRoot {
        tables_offset: to,
        tables_size: ts,
        strings_offset: so,
        strings_size: ss,
        blob_offset: bo,
        blob_size: bs,
    })
}

/// Check if a PE has a CLI header (is .NET managed).
pub fn has_cli_header(data: &[u8]) -> bool {
    cli_header_offset(data).is_some()
}

/// Get file offset of CLI header from PE data.
pub fn cli_header_offset(data: &[u8]) -> Option<usize> {
    let (coff_off, opt_off, opt_size) =
        parse_pe_offsets(data)?;
    let rva = read_com_descriptor_rva(
        data, opt_off, opt_size,
    )?;
    rva_to_offset(data, 0, coff_off, rva)
}

/// Extract COFF header offset, optional header offset, and optional header
/// size from a PE binary. Validates the MZ and PE signatures.
fn parse_pe_offsets(
    data: &[u8],
) -> Option<(usize, usize, usize)> {
    if data.len() < 0x3C + 4 || data[..2] != *b"MZ" {
        return None;
    }
    let pe_off = read_u32(data, 0x3C) as usize;
    if pe_off + 4 > data.len() {
        return None;
    }
    if data[pe_off..pe_off + 4] != *b"PE\0\0" {
        return None;
    }
    let coff_off = pe_off + 4;
    if coff_off + 20 > data.len() {
        return None;
    }
    let opt_size =
        read_u16(data, coff_off + 16) as usize;
    let opt_off = coff_off + 20;
    if opt_off + opt_size > data.len() {
        return None;
    }
    Some((coff_off, opt_off, opt_size))
}

/// Read the COM descriptor (CLI header) RVA from PE DataDirectory entry 14.
/// Handles both PE32 (magic 0x10B) and PE32+ (magic 0x20B) layouts.
fn read_com_descriptor_rva(
    data: &[u8],
    opt_off: usize,
    opt_size: usize,
) -> Option<u32> {
    let magic = read_u16(data, opt_off);
    let dd_offset = match magic {
        0x10B => opt_off + 96,
        0x20B => opt_off + 112,
        _ => return None,
    };
    let entry_off = dd_offset + 14 * 8;
    if entry_off + 8 > opt_off + opt_size {
        return None;
    }
    let rva = read_u32(data, entry_off);
    let size = read_u32(data, entry_off + 4);
    if rva == 0 || size == 0 { None } else { Some(rva) }
}

/// Convert an RVA to a raw file offset by iterating PE section headers.
fn rva_to_offset(
    data: &[u8],
    _pe_off: usize,
    coff_off: usize,
    rva: u32,
) -> Option<usize> {
    let num_secs =
        read_u16(data, coff_off + 2) as usize;
    let opt_size =
        read_u16(data, coff_off + 16) as usize;
    let sec_off = coff_off + 20 + opt_size;
    for i in 0..num_secs {
        let s = sec_off + i * 40;
        if s + 40 > data.len() {
            return None;
        }
        let vsize = read_u32(data, s + 8);
        let vaddr = read_u32(data, s + 12);
        let raw_off = read_u32(data, s + 20);
        if rva >= vaddr && rva < vaddr + vsize {
            return Some(
                (rva - vaddr + raw_off) as usize,
            );
        }
    }
    None
}

/// Read a little-endian `u32` from `data` at `off`. Returns 0 on OOB.
pub fn read_u32(data: &[u8], off: usize) -> u32 {
    if off + 4 > data.len() { return 0; }
    u32::from_le_bytes(
        data[off..off + 4].try_into().unwrap_or([0; 4]),
    )
}

/// Read a little-endian `u16` from `data` at `off`. Returns 0 on OOB.
pub fn read_u16(data: &[u8], off: usize) -> u16 {
    if off + 2 > data.len() { return 0; }
    u16::from_le_bytes(
        data[off..off + 2].try_into().unwrap_or([0; 2]),
    )
}

/// Read a null-terminated ASCII string from `data` at `off`.
fn read_cstr(data: &[u8], off: usize) -> Option<String> {
    if off >= data.len() { return None; }
    let end = data[off..].iter().position(|&b| b == 0)?;
    if off + end > data.len() { return None; }
    String::from_utf8(data[off..off + end].to_vec()).ok()
}

/// Round `n` up to the next multiple of 4 (metadata alignment).
fn round_up_4(n: usize) -> usize {
    (n + 3) & !3
}
