//! .NET metadata table parsing (MethodDef, TypeDef, and supporting tables).
//!
//! Reads the `#~` (or `#-`) table stream header to determine heap-size
//! flags and per-table row counts, then walks tables in ECMA-335 order
//! to compute row offsets. Currently extracts two tables in detail:
//!
//! - **MethodDef** (table 0x06) -- RVA, flags, and `#Strings` name index
//!   for every method in the assembly.
//! - **TypeDef** (table 0x02) -- flags, name index, and `method_list`
//!   (first owned MethodDef row) for every type.
//!
//! Row sizes are computed dynamically based on heap-size flags and coded-
//! index widths so the parser handles both small (2-byte) and wide
//! (4-byte) indices.
//!
//! Key types:
//! - `TableStream` -- parsed table stream header with row counts.
//! - `MethodDef` -- single row from the MethodDef table.
//! - `TypeDef` -- single row from the TypeDef table.

use crate::format::dotnet::metadata::{
    read_u16, read_u32, MetadataRoot,
};

/// Table IDs in ECMA-335 metadata.
const TID_TYPEDEF: usize = 0x02;
const TID_METHODDEF: usize = 0x06;
const TID_MEMBERREF: usize = 0x0A;

/// Parsed MethodDef row from ECMA-335 table 0x06.
pub struct MethodDef {
    pub rva: u32,
    pub flags: u16,
    pub name_idx: u32,
}

/// Parsed TypeDef row from ECMA-335 table 0x02.
pub struct TypeDef {
    pub flags: u32,
    pub name_idx: u32,
    pub method_list: u32,
}

/// Parsed `#~` table stream header: heap-size flags, per-table row
/// counts, and the file offset where actual row data begins.
pub struct TableStream {
    pub heap_sizes: u8,
    pub row_counts: [u32; 64],
    pub rows_start: usize,
}

/// Parse the #~ table stream header.
pub fn parse_table_stream(
    data: &[u8],
    root: &MetadataRoot,
) -> Option<TableStream> {
    let off = root.tables_offset;
    if off + 24 > data.len() {
        return None;
    }
    let heap_sizes = data[off + 6];
    let valid = read_u64(data, off + 8);
    let mut pos = off + 24;
    let mut row_counts = [0u32; 64];
    for i in 0..64 {
        if valid & (1u64 << i) != 0 {
            if pos + 4 > data.len() {
                return None;
            }
            row_counts[i] = read_u32(data, pos);
            pos += 4;
        }
    }
    Some(TableStream {
        heap_sizes,
        row_counts,
        rows_start: pos,
    })
}

/// Read all MethodDef rows.
pub fn read_method_defs(
    data: &[u8],
    ts: &TableStream,
) -> Vec<MethodDef> {
    let count = ts.row_counts[TID_METHODDEF] as usize;
    if count == 0 {
        return Vec::new();
    }
    let sw = (ts.heap_sizes & 0x01) != 0;
    let bw = (ts.heap_sizes & 0x04) != 0;
    let pw = ts.row_counts[0x08] > 0xFFFF;
    let rsz = method_def_row_size(sw, bw, pw);
    let off = table_offset(data, ts, TID_METHODDEF);
    let mut methods = Vec::with_capacity(count);
    for i in 0..count {
        let r = off + i * rsz;
        if r + rsz > data.len() {
            break;
        }
        methods.push(parse_method_row(data, r, sw));
    }
    methods
}

/// Parse a single MethodDef row at file offset `r`.
fn parse_method_row(
    data: &[u8],
    r: usize,
    str_wide: bool,
) -> MethodDef {
    MethodDef {
        rva: read_u32(data, r),
        flags: read_u16(data, r + 6),
        name_idx: read_heap_idx(data, r + 8, str_wide),
    }
}

/// Read all TypeDef rows.
pub fn read_type_defs(
    data: &[u8],
    ts: &TableStream,
) -> Vec<TypeDef> {
    let count = ts.row_counts[TID_TYPEDEF] as usize;
    if count == 0 {
        return Vec::new();
    }
    let widths = typedef_widths(ts);
    let rsz = typedef_row_size(
        widths.0, widths.1, widths.2, widths.3,
    );
    let off = table_offset(data, ts, TID_TYPEDEF);
    let mut types = Vec::with_capacity(count);
    for i in 0..count {
        let r = off + i * rsz;
        if r + rsz > data.len() {
            break;
        }
        types.push(parse_typedef_row(data, r, &widths));
    }
    types
}

/// Determine column widths for TypeDef rows based on heap sizes and
/// coded-index thresholds.
fn typedef_widths(
    ts: &TableStream,
) -> (bool, bool, bool, bool) {
    let sw = (ts.heap_sizes & 0x01) != 0;
    let ew = coded_idx_wide(
        &[TID_TYPEDEF, 0x01, 0x1B],
        &ts.row_counts,
    );
    let fw = ts.row_counts[0x04] > 0xFFFF;
    let mw = ts.row_counts[TID_METHODDEF] > 0xFFFF;
    (sw, ew, fw, mw)
}

/// Parse a single TypeDef row at file offset `r`.
fn parse_typedef_row(
    data: &[u8],
    r: usize,
    widths: &(bool, bool, bool, bool),
) -> TypeDef {
    let (sw, ew, fw, mw) = *widths;
    let flags = read_u32(data, r);
    let mut p = r + 4;
    let name_idx = read_heap_idx(data, p, sw);
    p += hs(sw) + hs(sw) + hs(ew) + hs(fw);
    let method_list = read_heap_idx(data, p, mw);
    TypeDef { flags, name_idx, method_list }
}

/// Read a string from the #Strings heap.
pub fn get_string(
    data: &[u8],
    root: &MetadataRoot,
    idx: u32,
) -> String {
    let off = root.strings_offset + idx as usize;
    if off >= data.len() {
        return String::new();
    }
    let end = data[off..]
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(0);
    if off + end > data.len() {
        return String::new();
    }
    String::from_utf8_lossy(&data[off..off + end])
        .to_string()
}

/// Calculate file offset for a table's first row.
fn table_offset(
    _data: &[u8],
    ts: &TableStream,
    table_id: usize,
) -> usize {
    let mut off = ts.rows_start;
    for i in 0..table_id {
        let count = ts.row_counts[i] as usize;
        if count > 0 {
            let sz = row_size_for_table(i, ts);
            off = off.saturating_add(
                count.saturating_mul(sz),
            );
        }
    }
    off
}

/// Determine if coded index needs 4 bytes.
fn coded_idx_wide(
    tables: &[usize],
    counts: &[u32; 64],
) -> bool {
    let bits = coded_tag_bits(tables.len());
    let max = tables
        .iter()
        .map(|&t| counts[t])
        .max()
        .unwrap_or(0);
    max >= (1u32 << (16 - bits))
}

/// Number of tag bits needed for a coded index over `n` candidate tables.
fn coded_tag_bits(n: usize) -> u32 {
    match n {
        0..=2 => 1,
        3..=4 => 2,
        5..=8 => 3,
        9..=16 => 4,
        _ => 5,
    }
}

/// Read a heap index (2 or 4 bytes) depending on the `wide` flag.
fn read_heap_idx(
    data: &[u8],
    off: usize,
    wide: bool,
) -> u32 {
    if wide {
        read_u32(data, off)
    } else {
        read_u16(data, off) as u32
    }
}

/// Compute MethodDef row size: 4 (RVA) + 2 (ImplFlags) + 2 (Flags)
/// + string_idx + blob_idx + param_idx.
fn method_def_row_size(
    str_wide: bool,
    blob_wide: bool,
    param_wide: bool,
) -> usize {
    4 + 2 + 2
        + if str_wide { 4 } else { 2 }
        + if blob_wide { 4 } else { 2 }
        + if param_wide { 4 } else { 2 }
}

/// Compute TypeDef row size: 4 (Flags) + name + namespace + extends +
/// field_list + method_list.
fn typedef_row_size(
    str_wide: bool,
    extends_wide: bool,
    field_wide: bool,
    method_wide: bool,
) -> usize {
    4 + if str_wide { 4 } else { 2 }
        + if str_wide { 4 } else { 2 }
        + if extends_wide { 4 } else { 2 }
        + if field_wide { 4 } else { 2 }
        + if method_wide { 4 } else { 2 }
}

/// Row size for any table (simplified).
fn row_size_for_table(
    tid: usize,
    ts: &TableStream,
) -> usize {
    let sw = (ts.heap_sizes & 0x01) != 0;
    let bw = (ts.heap_sizes & 0x04) != 0;
    let gw = (ts.heap_sizes & 0x02) != 0;
    match tid {
        0x00 => 4 + hs(sw) + hs(gw) + hs(bw) + hs(sw),
        0x01 => coded_sz(2) + hs(sw) + hs(sw),
        TID_TYPEDEF => {
            let w = typedef_widths(ts);
            typedef_row_size(w.0, w.1, w.2, w.3)
        }
        0x04 => 2 + hs(sw) + hs(bw),
        TID_METHODDEF => method_def_row_size(
            sw, bw, ts.row_counts[0x08] > 0xFFFF,
        ),
        0x08..=0x09 => row_size_misc(tid, sw),
        _ => row_size_upper(tid, sw, bw, ts),
    }
}

/// Row size for tables 0x08 (Param) and 0x09 (InterfaceImpl).
fn row_size_misc(tid: usize, sw: bool) -> usize {
    match tid {
        0x08 => 2 + hs(sw),
        0x09 => 2 + hs(sw) + hs(sw),
        _ => 0,
    }
}

/// Row size for tables 0x0A and above (MemberRef, Constant, etc.).
fn row_size_upper(
    tid: usize,
    sw: bool,
    bw: bool,
    ts: &TableStream,
) -> usize {
    match tid {
        TID_MEMBERREF => {
            member_ref_parent_sz(&ts.row_counts)
                + hs(sw) + hs(bw)
        }
        0x0E => hs(bw),
        0x11 => coded_sz(2) + hs(bw),
        0x14 => 2 + hs(bw),
        0x17 => 4 + hs(sw) + hs(sw) + hs(bw),
        0x1A => hs(sw),
        0x1B => 4 + hs(sw) + hs(sw),
        0x20 | 0x27 => 8,
        0x23 => 2 + hs(bw) + hs(sw),
        0x28 => 6,
        0x29 | 0x2A => coded_sz(2) + coded_sz(2),
        0x2B => coded_sz(2) + hs(bw),
        0x2C => coded_sz(3),
        _ => 0,
    }
}

/// Heap/simple index size: 4 if wide, 2 otherwise.
fn hs(wide: bool) -> usize {
    if wide { 4 } else { 2 }
}

/// Coded-index column size: 2 bytes if tag bits fit, 4 otherwise.
fn coded_sz(tag_bits: usize) -> usize {
    if tag_bits <= 2 { 2 } else { 4 }
}

/// Column size for the MemberRefParent coded index.
fn member_ref_parent_sz(counts: &[u32; 64]) -> usize {
    let tables = [TID_TYPEDEF, 0x01, TID_METHODDEF, 0x1A, 0x1B];
    if coded_idx_wide(&tables, counts) { 4 } else { 2 }
}

/// Return (first_row_file_offset, row_size, count) for MethodDef.
pub fn method_def_table_info(
    data: &[u8],
    ts: &TableStream,
) -> (usize, usize, usize) {
    let count = ts.row_counts[TID_METHODDEF] as usize;
    let sw = (ts.heap_sizes & 0x01) != 0;
    let bw = (ts.heap_sizes & 0x04) != 0;
    let pw = ts.row_counts[0x08] > 0xFFFF;
    let rsz = method_def_row_size(sw, bw, pw);
    let off = table_offset(data, ts, TID_METHODDEF);
    (off, rsz, count)
}

/// Read a little-endian `u64` from `data` at `off`.
fn read_u64(data: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(
        data[off..off + 8].try_into().unwrap_or([0; 8]),
    )
}
