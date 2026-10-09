//! ELF binary analysis and dead code compaction.
//!
//! Parses ELF headers, section tables, and symbol tables to build a function
//! map. After dead code analysis, physically compacts the .text section by
//! removing dead regions and patching all affected metadata (relocations,
//! symbols, program headers, entry point, unwind tables). Dead functions in
//! other executable sections are zero-filled in place: only .text moves.

pub mod ehframe;
pub mod nativeaot;
pub mod patch;
pub mod relr;
pub mod sections;
pub mod symbols;

use crate::analysis::reachability::{compute_live_set, find_dead};
use crate::analysis::roots::determine_roots;
use crate::decode::callgraph::build_ref_graph_fast;
use crate::decode::scan::scan_data_for_func_addrs;
use crate::analysis::cfg::DeadBlock;
use crate::patch::compact::{compact_text, compaction_fits};
use crate::patch::data_ptrs::{patch_data_ptrs, patch_slot_ptrs, PtrSlot};
use crate::patch::relptr::{patch_relptr32, relptr32_conflict};
use nativeaot::R2rPlan;
use crate::patch::relocs::{
    block_intervals, combine_intervals, dead_intervals,
    defrag_intervals,
};
use crate::patch::zerofill::{zero_fill, zero_fill_blocks};
use crate::types::{
    Arch, DecodedInstr, Endian, FuncMap, Section,
};
use std::collections::{HashMap, HashSet};

/// ELF code sections other than .text that may branch into .text.
/// `__managedcode` and `__unbox` hold .NET NativeAOT managed code, which
/// calls runtime and System.Native helpers living in .text.
const EXTRA_CODE_SECTIONS: &[&str] = &[
    ".plt", ".plt.got", ".plt.sec", ".init", ".fini",
    "__managedcode", "__unbox",
];

/// .NET NativeAOT module list: the ReadyToRun module headers the runtime
/// registers at startup. NativeAOT images reach code through 32-bit
/// self-relative pointers in the ReadyToRun tables, the dehydrated data
/// and the unwind info. .text is compacted only when `nativeaot` models
/// them exactly and the layout lets them follow (see
/// `nativeaot::compaction_plan`); otherwise dead code is zero-filled
/// in place, which keeps every one of them valid.
const NATIVEAOT_MODULES: &str = "__modules";

/// .NET NativeAOT managed code sections.
const NATIVEAOT_CODE: &[&str] = &["__managedcode", "__unbox"];

/// Analyze an ELF binary: returns (funcs, dead, sections).
pub fn analyze_elf(
    data: &[u8],
) -> (FuncMap, HashMap<String, (u64, u64)>, Vec<Section>) {
    let (funcs, dead, sections, _) = analyze_elf_full(data);
    (funcs, dead, sections)
}

/// Analyze ELF returning import names (PLT) alongside.
pub fn analyze_elf_full(
    data: &[u8],
) -> (
    FuncMap,
    HashMap<String, (u64, u64)>,
    Vec<Section>,
    HashMap<u64, String>,
) {
    let elf = match goblin::elf::Elf::parse(data) {
        Ok(e) => e,
        Err(_) => return empty_full(),
    };
    let sections = sections::get_sections(&elf);
    if let Some(name) = code_outside_file(data.len(), &sections) {
        eprintln!(
            "  note: code section {} runs past the end of the file; \
             left unchanged",
            name
        );
        return empty_full();
    }
    let (ts, te) = match sections::text_bounds(&sections) {
        Some(b) => b,
        None => return empty_full(),
    };
    let text_sec =
        match sections.iter().find(|s| s.name == ".text") {
            Some(s) => s,
            None => return empty_full(),
        };
    let arch = detect_arch(data);
    let instrs = crate::arch::decode_text(
        data,
        text_sec.offset,
        text_sec.vaddr,
        text_sec.size,
        arch,
    );
    if instrs.is_empty() {
        return empty_full();
    }
    let (funcs, links) =
        build_func_map(&elf, data, &sections, &instrs, ts, te);
    if funcs.is_empty() {
        return empty_full();
    }
    let plt_names =
        symbols::get_plt_names(&elf, &sections);
    // Branches from code outside .text (PLT, init/fini, NativeAOT managed
    // code) must count as references; outside the function map they
    // become orphan references, i.e. roots.
    let mut instrs = instrs;
    instrs.extend(decode_named(data, &sections, EXTRA_CODE_SECTIONS));
    instrs.extend(links);
    let dead = run_analysis(&funcs, &instrs, data, &sections);
    (funcs, dead, sections, plt_names)
}

/// Build the function map from symtab; fall back to inference if stripped,
/// refined by `.eh_frame` FDE boundaries where `fde_hints` allows. Also
/// returns extra references (synthetic instructions) the reference graph
/// must include: fall-through and jump-table edges between functions.
/// Either way every `.dynsym` code entry point is a root: on the symtab
/// path through the function holding it (`root_dynamic_exports`).
fn build_func_map(
    elf: &goblin::elf::Elf,
    data: &[u8],
    sections: &[Section],
    instrs: &[DecodedInstr],
    ts: u64,
    te: u64,
) -> (FuncMap, Vec<DecodedInstr>) {
    use crate::decode::infer;
    let mut funcs = symbols::get_functions_symtab(elf);
    if !funcs.is_empty() {
        symbols::root_dynamic_exports(elf, &mut funcs);
        return (funcs, Vec::new());
    }
    let dynsyms = symbols::get_dynamic_symbols(elf);
    match fde_hints(elf, data, sections) {
        Some(h) => infer::infer_functions_fde(
            elf.entry, &dynsyms, data, sections, instrs, ts, te, &h,
        ),
        None => {
            let funcs = infer::infer_functions(
                elf.entry, &dynsyms, data, sections, instrs, ts, te,
                elf.is_64,
            );
            (funcs, Vec::new())
        }
    }
}

/// FDE boundary hints for a stripped 64-bit x86-64 image with
/// `.eh_frame`. None for other architectures: their decoders do not
/// resolve address formation exactly (ADRP/ADD, AUIPC, LUI pairs,
/// GOT-relative offsets), so a function split off at its FDE could lose
/// references it has. None for x32 (ELFCLASS32), whose pointer scans
/// assume 8-byte pointers. None for a NativeAOT image whose ReadyToRun
/// references are not modelled exactly: split at FDEs, code reached
/// only through 32-bit self-relative pointers in ReadyToRun data would
/// lose its only reference. With an exact model those pointers make
/// their targets roots (`nativeaot::root_names`).
fn fde_hints(
    elf: &goblin::elf::Elf,
    data: &[u8],
    sections: &[Section],
) -> Option<crate::decode::infer::FdeHints> {
    if detect_arch(data) != Arch::X86_64 || !elf.is_64 {
        return None;
    }
    if is_nativeaot(sections) && nativeaot::nativeaot_refs(data).is_err() {
        return None;
    }
    let fdes = ehframe::fde_ranges(data, sections);
    if fdes.is_empty() {
        return None;
    }
    let fixed = elf.header.e_type == goblin::elf::header::ET_EXEC;
    let (data_secs, ptr_secs, code_secs) =
        alloc_sections(elf, fixed || has_textrel(elf));
    Some(crate::decode::infer::FdeHints {
        fdes,
        personalities: ehframe::personality_targets(data, sections),
        data_secs,
        ptr_secs,
        code_secs,
        fixed,
    })
}

/// True if the image has text relocations (DT_TEXTREL or DF_TEXTREL):
/// dynamic relocations may then write absolute addresses anywhere.
fn has_textrel(elf: &goblin::elf::Elf) -> bool {
    use goblin::elf::dynamic::DF_TEXTREL;
    elf.dynamic.as_ref().is_some_and(|d| {
        d.info.textrel || d.info.flags as u64 & DF_TEXTREL != 0
    })
}

/// Allocated, file-backed sections as (data, pointer, code) lists. The
/// unwind tables are left out of the data: their FDE pointers name every
/// function. Pointer sections are the data sections that can hold an
/// absolute code address: all of them when `all_ptrs` (fixed-address
/// image, text relocations); otherwise only those dynamic relocations
/// write (writable sections) and the relocation tables (addends).
fn alloc_sections(
    elf: &goblin::elf::Elf,
    all_ptrs: bool,
) -> (Vec<Section>, Vec<Section>, Vec<Section>) {
    use goblin::elf::section_header::{
        SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE, SHT_NOBITS, SHT_REL, SHT_RELA,
    };
    let (mut data, mut ptrs, mut code) = (Vec::new(), Vec::new(), Vec::new());
    for sh in &elf.section_headers {
        let flags = sh.sh_flags;
        if flags & SHF_ALLOC as u64 == 0 || sh.sh_type == SHT_NOBITS {
            continue;
        }
        let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
        let sec = Section {
            name: name.to_string(),
            size: sh.sh_size,
            vaddr: sh.sh_addr,
            offset: sh.sh_offset,
            align: sh.sh_addralign,
        };
        if flags & SHF_EXECINSTR as u64 != 0 {
            code.push(sec);
            continue;
        }
        if name.starts_with(".eh_frame") {
            continue;
        }
        let relocated = flags & SHF_WRITE as u64 != 0
            || sh.sh_type == SHT_RELA
            || sh.sh_type == SHT_REL;
        if all_ptrs || relocated {
            ptrs.push(sec.clone());
        }
        data.push(sec);
    }
    (data, ptrs, code)
}

/// Run reachability analysis: build call graph, determine roots, find dead.
fn run_analysis(
    funcs: &FuncMap,
    instrs: &[DecodedInstr],
    data: &[u8],
    sections: &[Section],
) -> HashMap<String, (u64, u64)> {
    let (graph, orphan_refs) = build_ref_graph_fast(funcs, instrs);
    let func_addrs: HashSet<u64> =
        funcs.values().map(|fi| fi.addr).collect();
    let is64 = detect_is64(data);
    let endian = detect_endian(data);
    let data_refs = scan_data_for_func_addrs(
        data, &func_addrs, sections, is64, endian,
    );
    let by_addr: HashMap<u64, &str> = funcs
        .iter()
        .map(|(n, fi)| (fi.addr, n.as_str()))
        .collect();
    let mut data_names: HashSet<String> = data_refs
        .iter()
        .filter_map(|a| by_addr.get(a).map(|n| n.to_string()))
        .collect();
    if is_nativeaot(sections) {
        data_names.extend(managed_funcs(funcs, sections));
        data_names.extend(nativeaot::root_names(data, funcs));
    }
    let roots = determine_roots(funcs, &data_names, &orphan_refs);
    let live = compute_live_set(&roots, &graph, funcs);
    find_dead(funcs, &live)
}

/// Names of the functions inside NativeAOT managed code sections; all of
/// them count as live. The runtime reaches managed methods through
/// MethodTable vtables stored dehydrated (compressed, relative pointers)
/// and rebuilt at startup into the NOBITS `.hydrated` section, so the
/// file holds no reference to them that trim can see.
fn managed_funcs(funcs: &FuncMap, sections: &[Section]) -> Vec<String> {
    let managed: Vec<&Section> = sections
        .iter()
        .filter(|s| NATIVEAOT_CODE.contains(&s.name.as_str()))
        .collect();
    funcs
        .iter()
        .filter(|(_, fi)| {
            managed.iter().any(|s| {
                fi.addr >= s.vaddr && fi.addr - s.vaddr < s.size
            })
        })
        .map(|(n, _)| n.clone())
        .collect()
}

/// Name of the first code section trim decodes (.text and
/// `EXTRA_CODE_SECTIONS`) whose file range is not wholly inside a file
/// of `len` bytes (crafted or truncated input). Its instructions cannot
/// be read, so references from it would be missed and its branches left
/// unpatched: such a file is left unchanged.
fn code_outside_file(len: usize, sections: &[Section]) -> Option<&str> {
    let decoded = |s: &&Section| {
        s.name == ".text" || EXTRA_CODE_SECTIONS.contains(&s.name.as_str())
    };
    sections
        .iter()
        .filter(decoded)
        .find(|s| s.offset.checked_add(s.size).map_or(true, |e| e > len as u64))
        .map(|s| s.name.as_str())
}

/// Return empty results tuple for early-exit paths.
fn empty_full() -> (
    FuncMap,
    HashMap<String, (u64, u64)>,
    Vec<Section>,
    HashMap<u64, String>,
) {
    (FuncMap::new(), HashMap::new(), Vec::new(), HashMap::new())
}

/// Reassemble: patch refs, compact .text, update ELF metadata.
/// Only .text is compacted (compacting the other executable sections is
/// future work), so dead functions elsewhere are zero-filled in place
/// and never reach the interval and drain math, which assumes every
/// interval lies inside .text. Dead code that lies in no single
/// executable section is left untouched.
/// Returns (func_count, func_saved, block_count, block_saved).
pub fn reassemble_elf(
    data: &mut Vec<u8>,
    dead: &HashMap<String, (u64, u64)>,
    dead_blocks: &[DeadBlock],
    sections: &[Section],
) -> (usize, u64, usize, u64) {
    let arch = detect_arch(data);
    // Landing pads are reachable only through the unwinder (LSDA).
    let dead_blocks =
        &ehframe::retain_unwindable_blocks(data, sections, dead_blocks);
    let bounds = sections::text_bounds(sections);
    let split = split_dead(dead, bounds, &other_code_spans(data));
    if split.skipped > 0 {
        eprintln!(
            "  note: {} dead functions lie in no single code section; \
             left in place",
            split.skipped
        );
    }
    // Read before anything is written: the model parses the original data.
    let r2r = is_nativeaot(sections)
        .then(|| nativeaot::compaction_plan(data, EXTRA_CODE_SECTIONS));
    let (oc, os) = zero_fill_ranges(data, &split.other);
    let (fc, fs, bc, bs) = match r2r {
        None => compact_or_fill(data, &split.text, dead_blocks, sections, arch, None),
        Some(Ok(plan)) => {
            compact_or_fill(data, &split.text, dead_blocks, sections, arch, Some(&plan))
        }
        Some(Err(why)) => {
            zero_fill_in_place(data, &split.text, dead_blocks, sections, arch, &why)
        }
    };
    (fc + oc, fs + os, bc, bs)
}

/// Compact .text by the dead functions and blocks lying wholly inside
/// it (`dead` holds only such functions). Falls back to zero-filling
/// them in place when there is no .text, nothing decodes, or the plan
/// does not fit the file; that check runs before any patching. For a
/// NativeAOT image `r2r` holds its ReadyToRun RELPTR32s and absolute
/// pointer slots (`nativeaot::compaction_plan`): the RELPTR32s must all
/// be able to follow the plan too, and are re-pointed with the other
/// references; data pointers are patched at the known slots only.
fn compact_or_fill(
    data: &mut Vec<u8>,
    dead: &HashMap<String, (u64, u64)>,
    dead_blocks: &[DeadBlock],
    sections: &[Section],
    arch: Arch,
    r2r: Option<&R2rPlan>,
) -> (usize, u64, usize, u64) {
    let (ts, te) = match sections::text_bounds(sections) {
        Some(b) => b,
        None => return fill_in_place(data, dead, dead_blocks, sections, arch),
    };
    let all_blocks = dead_blocks.len();
    let dead_blocks = &blocks_within(dead_blocks, ts, te);
    if dead_blocks.len() < all_blocks {
        eprintln!(
            "  note: {} dead branches lie outside .text; left in place",
            all_blocks - dead_blocks.len()
        );
    }
    let func_ivs = dead_intervals(dead);
    let blk_ivs = block_intervals(dead_blocks);
    let combined = combine_intervals(&func_ivs, &blk_ivs);
    let intervals = defrag_intervals(
        &combined,
        data,
        sections,
        crate::arch::padding_fn(arch),
        crate::arch::instr_align(arch),
    );
    // Live functions whose unwind rows cannot follow a shrink stay whole.
    let intervals = ehframe::unwind_safe_intervals(
        data, sections, &intervals, ts, te, crate::arch::instr_align(arch),
    );
    let dead_blocks = &blocks_removed(dead_blocks, &intervals);
    let instrs = decode_sections(data, sections);
    let fits = !instrs.is_empty()
        && compaction_fits(data.len(), sections, &intervals);
    if let Some(why) = compaction_blocker(fits, r2r, &intervals, ts, te) {
        return match r2r {
            Some(_) => zero_fill_in_place(data, dead, dead_blocks, sections, arch, &why),
            None => fill_in_place(data, dead, dead_blocks, sections, arch),
        };
    }
    let slots = r2r.map(|p| p.slots.as_slice());
    apply_patches(
        data, &instrs, &intervals, sections, ts, te, arch, slots,
    );
    if let Some(plan) = r2r {
        patch_r2r(data, plan, &intervals, ts, te);
    }
    let saved = compact_text(data, sections, &intervals);
    let blk_bytes: u64 =
        dead_blocks.iter().map(|b| b.size).sum();
    let func_saved = saved.saturating_sub(blk_bytes);
    (dead.len(), func_saved, dead_blocks.len(), blk_bytes)
}

/// Why compaction cannot go ahead: nothing decoded or a plan that does
/// not fit the file (`fits` false), a ReadyToRun RELPTR32 of `r2r` that
/// cannot follow `intervals`, or an absolute pointer of `r2r` into code
/// they remove. None if it can.
fn compaction_blocker(
    fits: bool,
    r2r: Option<&R2rPlan>,
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
) -> Option<String> {
    if !fits {
        return Some("compaction plan does not fit the file".to_string());
    }
    let plan = r2r?;
    relptr32_conflict(&plan.relptrs, intervals, ts, te)
        .or_else(|| removed_pointee(&plan.absolute, intervals))
}

/// Why an absolute pointer blocks compaction: one of `targets` lies in
/// removed code, so no new address exists for it.
fn removed_pointee(targets: &[u64], intervals: &[(u64, u64)]) -> Option<String> {
    targets
        .iter()
        .find(|&&t| crate::patch::relocs::in_dead_range(t, intervals))
        .map(|t| format!("absolute pointer designates removed code at {:#x}", t))
}

/// Re-point the ReadyToRun RELPTR32s of `plan` whose location and target
/// move apart (data after .text designating .text code), noting counts.
fn patch_r2r(
    data: &mut [u8],
    plan: &R2rPlan,
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
) {
    let (moved, kept) = patch_relptr32(data, &plan.relptrs, intervals, ts, te);
    eprintln!(
        "  note: NativeAOT: .text compacted; {} ReadyToRun references \
         re-pointed, {} unchanged",
        moved, kept
    );
}

/// Zero-fill dead functions and blocks in place, moving nothing.
fn fill_in_place(
    data: &mut [u8],
    dead: &HashMap<String, (u64, u64)>,
    dead_blocks: &[DeadBlock],
    sections: &[Section],
    arch: Arch,
) -> (usize, u64, usize, u64) {
    let (fc, fs) = zero_fill(data, dead, sections);
    let (bc, bs) = zero_fill_blocks(data, dead_blocks, sections, arch);
    (fc, fs, bc, bs)
}

/// Dead functions sorted by where trim may remove them.
struct DeadSplit {
    /// Lying wholly inside .text: compacted (or zero-filled in place).
    text: HashMap<String, (u64, u64)>,
    /// Lying wholly inside another executable section: the file ranges
    /// `(offset, len)` to zero-fill in place.
    other: Vec<(usize, usize)>,
    /// Lying in no single executable section: left untouched.
    skipped: usize,
}

/// A file-backed executable section other than .text.
struct CodeSpan {
    /// First vaddr.
    start: u64,
    /// End vaddr (exclusive).
    end: u64,
    /// File offset of `start`.
    offset: u64,
}

/// File-backed (PROGBITS) executable sections other than .text, read
/// from the section headers. Sections whose address or file range
/// overflows or runs past the end of the file are left out.
fn other_code_spans(data: &[u8]) -> Vec<CodeSpan> {
    use goblin::elf::section_header::{SHF_ALLOC, SHF_EXECINSTR, SHT_PROGBITS};
    let elf = match goblin::elf::Elf::parse(data) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };
    let flags = u64::from(SHF_ALLOC | SHF_EXECINSTR);
    elf.section_headers
        .iter()
        .filter(|sh| sh.sh_type == SHT_PROGBITS && sh.sh_flags & flags == flags)
        .filter(|sh| elf.shdr_strtab.get_at(sh.sh_name) != Some(".text"))
        .filter_map(|sh| {
            let end = sh.sh_addr.checked_add(sh.sh_size)?;
            let file_end = sh.sh_offset.checked_add(sh.sh_size)?;
            (file_end <= data.len() as u64).then_some(CodeSpan {
                start: sh.sh_addr,
                end,
                offset: sh.sh_offset,
            })
        })
        .collect()
}

/// True if `[addr, addr + size)` lies within `[lo, hi)`.
fn lies_within(addr: u64, size: u64, lo: u64, hi: u64) -> bool {
    addr >= lo && addr.checked_add(size).map_or(false, |e| e <= hi)
}

/// Split the dead functions by place: wholly inside .text (`bounds`),
/// wholly inside one of `spans`, or neither (skipped: never touched).
fn split_dead(
    dead: &HashMap<String, (u64, u64)>,
    bounds: Option<(u64, u64)>,
    spans: &[CodeSpan],
) -> DeadSplit {
    let mut split = DeadSplit {
        text: HashMap::new(),
        other: Vec::new(),
        skipped: 0,
    };
    for (name, &(addr, size)) in dead {
        let in_text = bounds
            .map_or(false, |(ts, te)| lies_within(addr, size, ts, te));
        if in_text {
            split.text.insert(name.clone(), (addr, size));
        } else if let Some(r) = span_range(spans, addr, size) {
            split.other.push(r);
        } else {
            split.skipped += 1;
        }
    }
    split
}

/// File range `(offset, len)` of `[addr, addr + size)` if it lies
/// wholly inside one of `spans`.
fn span_range(spans: &[CodeSpan], addr: u64, size: u64) -> Option<(usize, usize)> {
    let s = spans
        .iter()
        .find(|s| lies_within(addr, size, s.start, s.end))?;
    let off = usize::try_from(s.offset + (addr - s.start)).ok()?;
    Some((off, usize::try_from(size).ok()?))
}

/// Zero-fill the file ranges `(offset, len)` in place, skipping any that
/// fall outside `data`. Returns (count, total_bytes).
fn zero_fill_ranges(data: &mut [u8], ranges: &[(usize, usize)]) -> (usize, u64) {
    let mut count = 0;
    let mut total = 0u64;
    for &(off, len) in ranges {
        let hit = off.checked_add(len).and_then(|e| data.get_mut(off..e));
        if let Some(bytes) = hit {
            bytes.fill(0x00);
            count += 1;
            total += len as u64;
        }
    }
    (count, total)
}

/// The dead blocks lying wholly inside .text `[ts, te)`; compaction
/// never sees any other.
fn blocks_within(blocks: &[DeadBlock], ts: u64, te: u64) -> Vec<DeadBlock> {
    blocks
        .iter()
        .filter(|b| lies_within(b.addr, b.size, ts, te))
        .cloned()
        .collect()
}

/// The dead blocks lying wholly inside one of `intervals`: those a
/// compaction by `intervals` removes. Blocks of functions kept whole by
/// `ehframe::unwind_safe_intervals` are left out.
fn blocks_removed(blocks: &[DeadBlock], intervals: &[(u64, u64)]) -> Vec<DeadBlock> {
    blocks
        .iter()
        .filter(|b| {
            intervals.iter().any(|&(s, e)| lies_within(b.addr, b.size, s, e))
        })
        .cloned()
        .collect()
}

/// True for a .NET NativeAOT image: it has the `__modules` section and
/// at least one managed code section (names survive `strip`). Managed
/// code sections alone are not enough: without `__modules` there are no
/// ReadyToRun tables to keep valid, so compaction stays safe.
fn is_nativeaot(sections: &[Section]) -> bool {
    let has = |name: &str| sections.iter().any(|s| s.name == name);
    has(NATIVEAOT_MODULES) && NATIVEAOT_CODE.iter().any(|n| has(n))
}

/// Zero-fill the dead functions and blocks of a NativeAOT image in
/// place, noting on stderr `why` it is not compacted. No code moves and
/// the file keeps its size, so every ReadyToRun reference stays valid
/// (see `NATIVEAOT_MODULES`).
fn zero_fill_in_place(
    data: &mut [u8],
    dead: &HashMap<String, (u64, u64)>,
    dead_blocks: &[DeadBlock],
    sections: &[Section],
    arch: Arch,
    why: &str,
) -> (usize, u64, usize, u64) {
    eprintln!(
        "  note: NativeAOT image detected; dead code zero-filled in \
         place (no compaction: {})",
        why
    );
    fill_in_place(data, dead, dead_blocks, sections, arch)
}

/// Decode instructions from all ELF code sections (.text and extras).
fn decode_sections(
    data: &[u8],
    sections: &[Section],
) -> Vec<DecodedInstr> {
    let mut instrs = decode_named(data, sections, &[".text"]);
    instrs.extend(decode_named(data, sections, EXTRA_CODE_SECTIONS));
    instrs
}

/// Decode instructions from the named ELF sections that are present.
fn decode_named(
    data: &[u8],
    sections: &[Section],
    names: &[&str],
) -> Vec<DecodedInstr> {
    let arch = detect_arch(data);
    let mut instrs = Vec::new();
    for name in names {
        if let Some(sec) = sections.iter().find(|s| s.name == *name)
        {
            instrs.extend(crate::arch::decode_text(
                data, sec.offset, sec.vaddr, sec.size, arch,
            ));
        }
    }
    instrs
}

/// Apply arch-specific branch patches, data pointer patches, and ELF
/// metadata updates (relocations, symbols, dynamic, headers). With
/// `slots` (every absolute pointer of the image is known) only those
/// are patched; otherwise data sections are scanned for pointer values.
fn apply_patches(
    data: &mut Vec<u8>,
    instrs: &[DecodedInstr],
    intervals: &[(u64, u64)],
    sections: &[Section],
    ts: u64,
    te: u64,
    arch: Arch,
    slots: Option<&[PtrSlot]>,
) {
    match arch {
        Arch::X86_64 | Arch::X86_32 => {
            use crate::arch::x86_patch;
            x86_patch::patch_call_jmp(
                data, instrs, intervals, sections, ts, te,
            );
            x86_patch::patch_pc_rel(
                data, instrs, intervals, sections, ts, te,
            );
            x86_patch::patch_jump_tables(
                data, instrs, sections, intervals, ts, te,
            );
        }
        Arch::Aarch64 => {
            crate::arch::aarch64_patch::patch_branches(
                data, instrs, intervals, sections, ts, te,
            );
        }
        Arch::Arm32 => {
            crate::arch::arm32_patch::patch_branches(
                data, instrs, intervals, sections, ts, te,
            );
        }
        Arch::RiscV64 | Arch::RiscV32 => {
            crate::arch::riscv_patch::patch_branches(
                data, instrs, intervals, sections, ts, te,
            );
        }
        Arch::Mips32 | Arch::Mips64 => {
            let big_endian = detect_endian(data) == Endian::Big;
            crate::arch::mips_patch::patch_branches(
                data, instrs, intervals, sections, ts, te,
                big_endian,
            );
        }
        Arch::S390x => {
            crate::arch::s390x_patch::patch_branches(
                data, instrs, intervals, sections, ts, te,
            );
        }
        Arch::LoongArch64 => {
            crate::arch::loongarch_patch::patch_branches(
                data, instrs, intervals, sections, ts, te,
            );
        }
    }
    let is64 = detect_is64(data);
    let endian = detect_endian(data);
    match slots {
        Some(s) => {
            patch_slot_ptrs(data, s, intervals, ts, te);
        }
        None => patch_data_ptrs(data, sections, intervals, ts, te, is64, endian),
    }
    ehframe::patch_eh_frame(data, sections, intervals, ts, te);
    patch::patch_rela_dyn(data, sections, intervals, ts, te);
    patch::patch_entry_point(data, intervals, ts, te);
    patch::patch_symbols(data, sections, intervals, ts, te);
    patch::patch_dynamic(data, sections, intervals, ts, te);
    patch::patch_headers(data, sections, intervals, ts, te);
}

/// Detect CPU architecture from the ELF e_machine field.
fn detect_arch(data: &[u8]) -> Arch {
    if data.len() < 20 {
        return Arch::X86_64;
    }
    let is_be = data.len() > 5 && data[5] == 2;
    let e_machine = if is_be {
        u16::from_be_bytes(
            data[18..20].try_into().unwrap_or([0; 2]),
        )
    } else {
        u16::from_le_bytes(
            data[18..20].try_into().unwrap_or([0; 2]),
        )
    };
    let is64 = data.len() > 4 && data[4] == 2;
    match e_machine {
        0x3E => Arch::X86_64,
        0x03 => Arch::X86_32,
        0xB7 => Arch::Aarch64,
        0x28 => Arch::Arm32,
        0xF3 => {
            if is64 { Arch::RiscV64 } else { Arch::RiscV32 }
        }
        0x08 => {
            if is64 { Arch::Mips64 } else { Arch::Mips32 }
        }
        0x16 => Arch::S390x,
        0x102 => Arch::LoongArch64,
        _ => Arch::X86_64,
    }
}

/// Return true if the ELF is 64-bit (EI_CLASS == ELFCLASS64).
fn detect_is64(data: &[u8]) -> bool {
    data.len() > 4 && data[4] == 2
}

/// Detect endianness from EI_DATA byte.
fn detect_endian(data: &[u8]) -> Endian {
    if data.len() > 5 && data[5] == 2 {
        Endian::Big
    } else {
        Endian::Little
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patch::relptr::RelField;

    /// .text [0x1000, 0x3000) losing [0x1100, 0x2180).
    const IVS: &[(u64, u64)] = &[(0x1100, 0x2180)];

    /// A plan whose one RELPTR32 at 0x3010 designates `relptr_target`
    /// and whose one absolute pointer designates `absolute`.
    fn plan(relptr_target: u64, absolute: u64) -> R2rPlan {
        let field = RelField { location: 0x3010, offset: 0x10, target: relptr_target };
        R2rPlan { relptrs: vec![field], slots: Vec::new(), absolute: vec![absolute] }
    }

    /// Compaction goes ahead only when the plan fits and no RELPTR32 or
    /// absolute pointer designates removed code.
    #[test]
    fn blocks_compaction_on_pointers_into_removed_code() {
        let ok = plan(0x2200, 0x1080);
        assert_eq!(compaction_blocker(true, Some(&ok), IVS, 0x1000, 0x3000), None);
        assert_eq!(compaction_blocker(true, None, IVS, 0x1000, 0x3000), None);
        assert!(compaction_blocker(false, None, IVS, 0x1000, 0x3000).is_some());
        let relptr = plan(0x1200, 0x1080);
        let why = compaction_blocker(true, Some(&relptr), IVS, 0x1000, 0x3000);
        assert!(why.is_some_and(|w| w.contains("RELPTR32")));
        let absolute = plan(0x2200, 0x1100);
        let why = compaction_blocker(true, Some(&absolute), IVS, 0x1000, 0x3000);
        assert!(why.is_some_and(|w| w.contains("absolute pointer")));
    }
}
