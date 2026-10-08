//! Function boundary inference for stripped binaries.
//!
//! When symbol tables are unavailable (stripped binaries), infers function
//! start addresses from three sources:
//! 1. Call targets — addresses targeted by call instructions
//! 2. PC-relative references — addresses loaded via LEA/ADRP patterns
//! 3. Data section pointers — addresses found in .got, .init_array, etc.
//!
//! Each inferred function extends from its start address to the next
//! function's start (or the end of .text). Known dynamic symbols and
//! the entry point anchor the initial set.
//!
//! When `.eh_frame` describes the code (x86-64 ELF, see
//! `infer_functions_fde`), its FDEs are exact boundaries: every FDE is
//! one function spanning exactly its range, and inference only
//! partitions the code no FDE covers. A
//! function found only through its FDE has no caller in .text, so its
//! liveness comes from the reference graph and roots alone; to keep that
//! sound, fall-through between adjacent functions and relative jump-table
//! entries become explicit references, and code addresses held in data,
//! relocations, personality pointers and (fixed-address images)
//! instruction immediates make the function holding them a root.

use crate::types::{
    DecodedInstr, Endian, FlowType, FuncInfo, FuncMap, Section,
};
use std::collections::{BTreeMap, HashMap, HashSet};

/// Inferred function starts: address -> (name, is_global).
type Starts = BTreeMap<u64, (String, bool)>;

/// Most 32-bit entries read from one candidate relative jump table.
const MAX_TABLE_ENTRIES: usize = 4096;

/// What an image says about exact code boundaries and address-taken
/// code, for `infer_functions_fde`.
pub struct FdeHints {
    /// FDE code ranges `(pc_begin, pc_range)` from `.eh_frame`.
    pub fdes: Vec<(u64, u64)>,
    /// Personality routines named by the CIEs.
    pub personalities: Vec<u64>,
    /// Allocated, file-backed, non-executable sections other than the
    /// unwind tables: where relative jump tables are read.
    pub data_secs: Vec<Section>,
    /// The data sections that can hold absolute code addresses: all of
    /// them in a fixed-address image; in a position-independent one only
    /// those dynamic relocations write and the relocation tables
    /// (addends). Scanned for pointer-aligned code addresses.
    pub ptr_secs: Vec<Section>,
    /// Allocated executable sections: scanned for absolute code
    /// addresses held in instructions when `fixed` is set.
    pub code_secs: Vec<Section>,
    /// Fixed-address image (ET_EXEC): code may hold absolute 32-bit
    /// addresses and data 32-bit pointers, without relocations.
    pub fixed: bool,
}

/// One function of the FDE-refined map.
struct Piece {
    start: u64,
    end: u64,
    name: String,
    global: bool,
}

/// How x86 alignment padding behaves when execution reaches it.
enum Pad {
    /// NOP of any length: execution runs through.
    Nop,
    /// INT3: execution traps.
    Trap,
}

/// Infer function boundaries for stripped binaries.
pub fn infer_functions(
    entry: u64,
    dynsyms: &FuncMap,
    data: &[u8],
    sections: &[Section],
    instrs: &[DecodedInstr],
    text_start: u64,
    text_end: u64,
    is64: bool,
) -> FuncMap {
    let starts = infer_starts(
        entry, dynsyms, data, sections, instrs, text_start, text_end,
        is64,
    );
    build_func_map(&starts, text_end)
}

/// Infer functions of a stripped x86-64 image whose FDEs give exact
/// boundaries: every FDE inside .text is one function spanning exactly
/// its range; the code no FDE covers keeps the inferred boundaries,
/// clipped at the FDEs. Returns the function map and the references the
/// reference graph must add (fall-through, relative jump tables) as
/// synthetic instructions carrying only an address and targets.
pub fn infer_functions_fde(
    entry: u64,
    dynsyms: &FuncMap,
    data: &[u8],
    sections: &[Section],
    instrs: &[DecodedInstr],
    text_start: u64,
    text_end: u64,
    hints: &FdeHints,
) -> (FuncMap, Vec<DecodedInstr>) {
    let starts = infer_starts(
        entry, dynsyms, data, sections, instrs, text_start, text_end,
        true,
    );
    let fdes = fde_spans(&hints.fdes, text_start, text_end);
    if fdes.is_empty() {
        return (build_func_map(&starts, text_end), Vec::new());
    }
    let mut pieces =
        partition(&starts, &fdes, instrs, text_start, text_end);
    mark_taken(&mut pieces, data, hints, text_start, text_end);
    let mut links = fallthrough_links(&pieces, &fdes, instrs);
    links.extend(table_links(
        data, instrs, &hints.data_secs, text_start, text_end,
    ));
    (pieces_to_map(pieces), links)
}

/// Collect inferred function starts with their names and root flags.
fn infer_starts(
    entry: u64,
    dynsyms: &FuncMap,
    data: &[u8],
    sections: &[Section],
    instrs: &[DecodedInstr],
    text_start: u64,
    text_end: u64,
    is64: bool,
) -> Starts {
    let data_refs = scan_data_code_refs(
        data, sections, text_start, text_end, is64,
    );
    let call_targets = collect_call_targets(instrs);
    let ref_targets = collect_ref_targets(instrs);
    let mut starts = Starts::new();
    for (name, fi) in dynsyms {
        if text_start <= fi.addr && fi.addr < text_end {
            starts.insert(fi.addr, (name.clone(), fi.is_global));
        }
    }
    if text_start <= entry && entry < text_end {
        starts
            .entry(entry)
            .or_insert(("_start".to_string(), true));
    }
    insert_targets(
        &mut starts, &call_targets, text_start, text_end,
    );
    insert_targets(
        &mut starts, &ref_targets, text_start, text_end,
    );
    for addr in &data_refs {
        starts
            .entry(*addr)
            .or_insert((format!("sub_{:x}", addr), true));
    }
    starts
}

/// Insert call/ref targets into the function start map if within .text bounds.
fn insert_targets(
    starts: &mut Starts,
    targets: &[u64],
    text_start: u64,
    text_end: u64,
) {
    for tgt in targets {
        if text_start <= *tgt && *tgt < text_end {
            starts
                .entry(*tgt)
                .or_insert((format!("sub_{:x}", tgt), false));
        }
    }
}

/// Extract all target addresses from call instructions.
fn collect_call_targets(
    instrs: &[DecodedInstr],
) -> Vec<u64> {
    instrs
        .iter()
        .filter(|i| i.is_call)
        .flat_map(|i| i.targets.iter().copied())
        .collect()
}

/// Extract all PC-relative reference targets (LEA/ADRP patterns).
fn collect_ref_targets(
    instrs: &[DecodedInstr],
) -> Vec<u64> {
    instrs
        .iter()
        .filter_map(|i| i.pc_rel_target)
        .collect()
}

/// Scan data sections (.got, .init_array, etc.) for pointers into .text.
fn scan_data_code_refs(
    data: &[u8],
    sections: &[Section],
    text_start: u64,
    text_end: u64,
    is64: bool,
) -> Vec<u64> {
    let scan_names: &[&str] = &[
        ".data",
        ".data.rel.ro",
        ".got",
        ".got.plt",
        ".init_array",
        ".fini_array",
        ".ctors",
        ".dtors",
        ".rdata",
    ];
    let ptr_size: usize = if is64 { 8 } else { 4 };
    let endian = Endian::Little;
    let mut refs = Vec::new();
    for sec in sections {
        if !scan_names.contains(&sec.name.as_str()) {
            continue;
        }
        let end = (sec.offset as usize + sec.size as usize)
            .min(data.len());
        let mut i = sec.offset as usize;
        while i + ptr_size <= end {
            let val =
                crate::types::read_ptr(data, i, is64, endian);
            if text_start <= val && val < text_end {
                refs.push(val);
            }
            i += ptr_size;
        }
    }
    refs
}

/// Build the final FuncMap from sorted start addresses.
/// Each function's size extends to the next function or to text_end.
fn build_func_map(
    starts: &Starts,
    text_end: u64,
) -> FuncMap {
    let addrs: Vec<u64> = starts.keys().copied().collect();
    let mut funcs = FuncMap::new();
    for (i, &addr) in addrs.iter().enumerate() {
        let (ref name, is_global) = starts[&addr];
        let size = if i + 1 < addrs.len() {
            addrs[i + 1] - addr
        } else {
            text_end - addr
        };
        if size > 0 {
            funcs.insert(
                name.clone(),
                FuncInfo {
                    addr,
                    size,
                    is_global,
                },
            );
        }
    }
    funcs
}

// ---- FDE partitioning ---------------------------------------------------

/// FDE ranges as `[begin, end)` spans starting inside .text, clipped to
/// its end, sorted; overlapping spans merge into one (conservative: the
/// merged function is live as a whole).
fn fde_spans(fdes: &[(u64, u64)], ts: u64, te: u64) -> Vec<(u64, u64)> {
    let mut v: Vec<(u64, u64)> = fdes
        .iter()
        .filter_map(|&(b, len)| {
            let e = b.checked_add(len)?.min(te);
            (ts <= b && b < e).then_some((b, e))
        })
        .collect();
    v.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(v.len());
    for (b, e) in v {
        match merged.last_mut() {
            Some(last) if b < last.1 => last.1 = last.1.max(e),
            _ => merged.push((b, e)),
        }
    }
    merged
}

/// Split .text into functions: one per FDE span, and in each region no
/// FDE covers, the inferred functions plus any code past an FDE's end.
fn partition(
    starts: &Starts,
    fdes: &[(u64, u64)],
    instrs: &[DecodedInstr],
    ts: u64,
    te: u64,
) -> Vec<Piece> {
    let mut pieces = Vec::new();
    let mut lo = ts;
    for &(b, e) in fdes {
        uncovered(&mut pieces, starts, instrs, lo, b, lo != ts);
        pieces.push(fde_piece(starts, b, e));
        lo = e;
    }
    uncovered(&mut pieces, starts, instrs, lo, te, lo != ts);
    pieces
}

/// The function of FDE span `[b, e)`: named after an inferred start at
/// `b` (else `sub_<b>`), and a root if any inferred start inside it is
/// one. Other inferred starts inside the span are dropped: references to
/// them resolve to this function by range.
fn fde_piece(starts: &Starts, b: u64, e: u64) -> Piece {
    let name = match starts.get(&b) {
        Some((n, _)) => n.clone(),
        None => format!("sub_{:x}", b),
    };
    let global = starts.range(b..e).any(|(_, s)| s.1);
    Piece { start: b, end: e, name, global }
}

/// Functions of `[lo, hi)`, a region no FDE covers: each inferred start
/// runs to the next one or to `hi`, as without FDEs. When the region
/// follows an FDE (`after_fde`), code before its first inferred start
/// becomes a function `sub_<addr>` from its first non-padding
/// instruction; padding alone stays outside every function.
fn uncovered(
    pieces: &mut Vec<Piece>,
    starts: &Starts,
    instrs: &[DecodedInstr],
    lo: u64,
    hi: u64,
    after_fde: bool,
) {
    if lo >= hi {
        return;
    }
    let inner: Vec<(u64, &(String, bool))> =
        starts.range(lo..hi).map(|(a, s)| (*a, s)).collect();
    let first = inner.first().map_or(hi, |s| s.0);
    if after_fde {
        if let Some(a) = first_code(instrs, lo, first) {
            let name = format!("sub_{:x}", a);
            pieces.push(Piece { start: a, end: first, name, global: false });
        }
    }
    for (i, &(a, (name, global))) in inner.iter().enumerate() {
        let end = inner.get(i + 1).map_or(hi, |s| s.0);
        let name = name.clone();
        pieces.push(Piece { start: a, end, name, global: *global });
    }
}

/// Address of the first decoded instruction in `[lo, hi)` that is not
/// alignment padding.
fn first_code(instrs: &[DecodedInstr], lo: u64, hi: u64) -> Option<u64> {
    let i = instrs.partition_point(|x| x.addr < lo);
    instrs[i..]
        .iter()
        .take_while(|x| x.addr < hi)
        .find(|x| pad_kind(&x.raw).is_none())
        .map(|x| x.addr)
}

/// Convert the pieces into a function map.
fn pieces_to_map(pieces: Vec<Piece>) -> FuncMap {
    pieces
        .into_iter()
        .filter(|p| p.end > p.start)
        .map(|p| {
            let fi = FuncInfo {
                addr: p.start,
                size: p.end - p.start,
                is_global: p.global,
            };
            (p.name, fi)
        })
        .collect()
}

// ---- Address-taken code -------------------------------------------------

/// Make roots of the functions whose code the image takes outside the
/// decoded instruction stream: holding a pointer-aligned value from a
/// pointer section (in-place pointers and relocation addends alike;
/// 32-bit values too in a fixed-address image) or a personality routine;
/// in a fixed-address image also starting at a 32-bit instruction
/// immediate.
fn mark_taken(
    pieces: &mut [Piece],
    data: &[u8],
    hints: &FdeHints,
    ts: u64,
    te: u64,
) {
    let mut inside = data_code_values(data, hints, ts, te);
    inside.extend(hints.personalities.iter().copied());
    inside.sort_unstable();
    inside.dedup();
    let exact = if hints.fixed {
        code_immediates(data, &hints.code_secs, pieces)
    } else {
        HashSet::new()
    };
    for p in pieces.iter_mut() {
        let i = inside.partition_point(|&a| a < p.start);
        let held = inside.get(i).is_some_and(|&a| a < p.end);
        p.global |= held || exact.contains(&p.start);
    }
}

/// Values in `[ts, te)` read at pointer alignment from the pointer
/// sections (8 bytes; also 4 bytes in a fixed-address image).
fn data_code_values(
    data: &[u8],
    hints: &FdeHints,
    ts: u64,
    te: u64,
) -> Vec<u64> {
    let mut widths = vec![8];
    if hints.fixed {
        widths.push(4);
    }
    let mut out = Vec::new();
    for sec in &hints.ptr_secs {
        for &w in &widths {
            out.extend(
                aligned_values(data, sec, w)
                    .filter(|v| (ts..te).contains(v)),
            );
        }
    }
    out
}

/// Little-endian `width`-byte values at `width`-aligned vaddrs of `sec`.
fn aligned_values<'a>(
    data: &'a [u8],
    sec: &Section,
    width: usize,
) -> impl Iterator<Item = u64> + 'a {
    let skip = sec.vaddr.wrapping_neg() as usize % width;
    let lo = (sec.offset as usize).saturating_add(skip);
    let hi = (sec.offset as usize)
        .saturating_add(sec.size as usize)
        .min(data.len());
    data.get(lo..hi.max(lo))
        .unwrap_or(&[])
        .chunks_exact(width)
        .map(read_le)
}

/// Function starts named by a 32-bit little-endian window anywhere in
/// the code sections: absolute addresses in `mov`/`push` immediates and
/// displacements of a fixed-address image.
fn code_immediates(
    data: &[u8],
    code_secs: &[Section],
    pieces: &[Piece],
) -> HashSet<u64> {
    let starts: HashSet<u64> = pieces.iter().map(|p| p.start).collect();
    let mut out = HashSet::new();
    for sec in code_secs {
        let lo = sec.offset as usize;
        let hi = lo.saturating_add(sec.size as usize).min(data.len());
        for w in data.get(lo..hi.max(lo)).unwrap_or(&[]).windows(4) {
            let v = read_le(w);
            if starts.contains(&v) {
                out.insert(v);
            }
        }
    }
    out
}

/// Read up to 8 bytes as a little-endian unsigned value.
fn read_le(b: &[u8]) -> u64 {
    b.iter().rev().fold(0u64, |v, &x| (v << 8) | x as u64)
}

// ---- Synthetic references ---------------------------------------------

/// A synthetic instruction at `src` that only references `targets`.
fn link(src: u64, targets: Vec<u64>) -> DecodedInstr {
    DecodedInstr {
        addr: src,
        raw: Vec::new(),
        len: 0,
        targets,
        pc_rel_target: None,
        is_call: false,
        flow: FlowType::Normal,
    }
}

/// Fall-through references: the instruction that can continue into a
/// function's first byte references it, so splitting code at FDE
/// boundaries never strands code entered only by falling through (an
/// FDE ending early, assembly with several entries, code past an FDE's
/// end). The reference comes from whatever function holds that
/// instruction, or is an orphan (a root) if none does.
fn fallthrough_links(
    pieces: &[Piece],
    fdes: &[(u64, u64)],
    instrs: &[DecodedInstr],
) -> Vec<DecodedInstr> {
    let fde_ends: HashSet<u64> = fdes.iter().map(|s| s.1).collect();
    pieces
        .iter()
        .filter_map(|p| {
            falls_into(instrs, p.start, &fde_ends)
                .map(|src| link(src, vec![p.start]))
        })
        .collect()
}

/// Address of the instruction whose execution can continue at `at`: the
/// last non-padding instruction before it, crossing NOP padding, unless
/// it ends the flow (return, jump, halt) or INT3 padding traps first.
/// A call continues unless it is the last instruction of its FDE: code
/// whose unwind description ends right after a call never returns there
/// (compilers end a function after a call only when it cannot return,
/// e.g. `__stack_chk_fail`, `_Unwind_Resume`). A decoded instruction
/// straddling `at` (instruction runs out of step) counts as continuing.
fn falls_into(
    instrs: &[DecodedInstr],
    at: u64,
    fde_ends: &HashSet<u64>,
) -> Option<u64> {
    let mut i = instrs.partition_point(|x| x.addr < at);
    let last = instrs.get(i.checked_sub(1)?)?;
    if last.addr + last.len as u64 != at {
        return Some(last.addr);
    }
    while i > 0 {
        i -= 1;
        let x = &instrs[i];
        match pad_kind(&x.raw) {
            Some(Pad::Trap) => return None,
            Some(Pad::Nop) => continue,
            None => {
                let end = x.addr + x.len as u64;
                let ends_fde = x.is_call && fde_ends.contains(&end);
                return (continues(x.flow) && !ends_fde).then_some(x.addr);
            }
        }
    }
    None
}

/// True if execution can continue past an instruction of this flow.
fn continues(flow: FlowType) -> bool {
    !matches!(
        flow,
        FlowType::Return
            | FlowType::UnconditionalBranch
            | FlowType::IndirectBranch
            | FlowType::Halt
    )
}

/// Classify x86 alignment padding: INT3, or a NOP (`90`, `0F 1F /0`,
/// with optional `66`/`2E` prefixes). None for any other instruction.
fn pad_kind(raw: &[u8]) -> Option<Pad> {
    if raw == [0xCC] {
        return Some(Pad::Trap);
    }
    let p = raw.iter().take_while(|&&b| b == 0x66 || b == 0x2E).count();
    let body = &raw[p..];
    (body == [0x90] || body.starts_with(&[0x0F, 0x1F])).then_some(Pad::Nop)
}

/// References through relative tables: for each RIP-relative operand
/// addressing a data section, the consecutive 32-bit entries at that
/// address whose `address + entry` lands in .text become targets of the
/// referencing instruction, up to the first entry that does not or the
/// next RIP-referenced address (the next table). Over-approximates
/// `.long case - table` switch tables, including tables whose cases lie
/// in another FDE (a GCC `.cold` part), and relative lookup tables of
/// function pointers.
fn table_links(
    data: &[u8],
    instrs: &[DecodedInstr],
    data_secs: &[Section],
    ts: u64,
    te: u64,
) -> Vec<DecodedInstr> {
    let mut bounds: Vec<u64> =
        instrs.iter().filter_map(|x| x.pc_rel_target).collect();
    bounds.sort_unstable();
    bounds.dedup();
    let mut tables: HashMap<u64, Vec<u64>> = HashMap::new();
    let mut out = Vec::new();
    for x in instrs {
        let Some(base) = x.pc_rel_target.filter(|b| b % 4 == 0) else {
            continue;
        };
        let targets = tables.entry(base).or_insert_with(|| {
            let i = bounds.partition_point(|&b| b <= base);
            let end = bounds.get(i).copied().unwrap_or(u64::MAX);
            table_targets(data, data_secs, base, end, ts, te)
        });
        if !targets.is_empty() {
            out.push(link(x.addr, targets.clone()));
        }
    }
    out
}

/// Targets in `[ts, te)` of the consecutive 32-bit relative entries in
/// `[base, end)`, which must lie in one of `secs`.
fn table_targets(
    data: &[u8],
    secs: &[Section],
    base: u64,
    end: u64,
    ts: u64,
    te: u64,
) -> Vec<u64> {
    let Some(sec) = secs
        .iter()
        .find(|s| base >= s.vaddr && base - s.vaddr < s.size)
    else {
        return Vec::new();
    };
    let room = (sec.vaddr.saturating_add(sec.size).min(end) - base) / 4;
    let off = sec.offset.saturating_add(base - sec.vaddr) as usize;
    let mut out = Vec::new();
    for k in 0..(room as usize).min(MAX_TABLE_ENTRIES) {
        let at = off.saturating_add(4 * k);
        let Some(b) = data.get(at..at.saturating_add(4)) else { break };
        let entry = read_le(b) as u32 as i32 as i64;
        let t = base.wrapping_add(entry as u64);
        if !(ts..te).contains(&t) {
            break;
        }
        out.push(t);
    }
    out
}
