//! .NET NativeAOT ReadyToRun references: a read-only, exact model.
//!
//! NativeAOT images reach code and data through 32-bit self-relative
//! pointers (RELPTR32: target = location + value) held in ReadyToRun
//! (R2R) structures the runtime reads at startup and on demand. This
//! module lists every such pointer the runtime dereferences. It starts
//! at the `__modules` section and parses each structure the way the
//! runtime reads it; it never scans for plausible values:
//!
//! - the R2R header (`__modules` -> header -> section table);
//! - dehydrated data (section 207): the destination pointer, the inline
//!   pointers of the command stream and the fixup table after it;
//! - ExternalReferences tables (sections 308, 331, 333);
//! - RELPTR32 arrays: the GC static region (201) and the GC static
//!   blocks it names, eager class constructors (205), module
//!   initializers (213);
//! - sealed vtables, named by the MethodTables the dehydrated data
//!   rebuilds;
//! - unwind info in `.dotnet_eh_table`, reached from `.eh_frame` FDEs:
//!   the main-LSDA, associated-data and EH-info pointers, the target of
//!   an unboxing stub held in associated data, and the caught type of
//!   typed EH clauses.
//!
//! A sealed vtable stores no slot count: it runs to the next known
//! object start, and each slot must point at code or the model is
//! refused. Not listed: generic composition arguments, which the runtime
//! reaches only through MethodTable fields; they point at MethodTables,
//! never at code.
//!
//! Layouts follow the .NET runtime sources (ModuleHeaders.h,
//! StartupCodeHelpers.cs, DehydratedData.cs, ExternalReferencesTable.cs,
//! MethodTable.cs, UnixNativeCodeManager.cpp). They are verified for
//! ReadyToRun major version 16 (.NET 10) on 64-bit little-endian ELF;
//! other versions are refused.

use super::ehframe;
use crate::types::{FuncMap, Section};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// "RTR": ReadyToRun header signature.
const R2R_SIGNATURE: u32 = 0x0052_5452;
/// The ReadyToRun major version whose layouts this module verifies.
const R2R_MAJOR: u16 = 16;
/// Bytes before the section table of a ReadyToRun header.
const R2R_HEADER_SIZE: u64 = 16;
/// ModuleInfoRow flag: the row has an end pointer.
const ROW_HAS_END: u32 = 1;

/// R2R section: GC static region (RELPTR32 per GC static block).
const SEC_GC_STATIC_REGION: u32 = 201;
/// R2R section: thread static region (absolute pointers only).
const SEC_THREAD_STATIC_REGION: u32 = 202;
/// R2R section: the type manager indirection cell.
const SEC_TYPE_MANAGER_INDIRECTION: u32 = 204;
/// R2R section: eager class constructors (RELPTR32 per method).
const SEC_EAGER_CCTOR: u32 = 205;
/// R2R section: frozen objects (rebuilt from the dehydrated data).
const SEC_FROZEN_OBJECTS: u32 = 206;
/// R2R section: dehydrated data.
const SEC_DEHYDRATED_DATA: u32 = 207;
/// R2R section: module initializers (RELPTR32 per method).
const SEC_MODULE_INITIALIZERS: u32 = 213;
/// R2R sections 300..=399 are blobs (300 + ReflectionMapBlob id).
const SEC_BLOB_FIRST: u32 = 300;
/// Last blob section id.
const SEC_BLOB_LAST: u32 = 399;
/// Blob sections that are ExternalReferences tables: CommonFixupsTable,
/// NativeReferences and NativeStatics.
const SEC_EXTERNAL_REFERENCES: [u32; 3] = [308, 331, 333];
/// Blob section: stack trace method mapping (RELPTR32 per method when
/// stack trace data is compiled in; that layout is not modelled).
const SEC_STACK_TRACE_MAPPING: u32 = 327;

/// Dehydrated data command: copy the payload bytes.
const CMD_COPY: u8 = 0;
/// Dehydrated data command: write `payload` zero bytes.
const CMD_ZERO_FILL: u8 = 1;
/// Dehydrated data command: RELPTR32 to fixup `payload`.
const CMD_RELPTR32_RELOC: u8 = 2;
/// Dehydrated data command: pointer to fixup `payload`.
const CMD_PTR_RELOC: u8 = 3;
/// Dehydrated data command: `payload` inline RELPTR32s rebuilt as
/// RELPTR32s.
const CMD_INLINE_RELPTR32_RELOC: u8 = 4;
/// Dehydrated data command: `payload` inline RELPTR32s rebuilt as
/// pointers.
const CMD_INLINE_PTR_RELOC: u8 = 5;
/// Largest payload a command byte holds by itself; larger payloads
/// follow in 1 to 3 extra bytes.
const MAX_SHORT_PAYLOAD: usize = 28;

/// MethodTable fixed part: flags, base size, related type, vtable and
/// interface counts, hash code.
const MT_FIXED: u64 = 24;
/// MethodTable flag: has a dispatch map field.
const MT_HAS_DISPATCH_MAP: u32 = 0x0004_0000;
/// MethodTable flag: has a finalizer field.
const MT_HAS_FINALIZER: u32 = 0x0010_0000;
/// MethodTable flag: has a sealed vtable field.
const MT_HAS_SEALED_VTABLE: u32 = 0x0040_0000;
/// Most vtable plus interface slots a MethodTable can count.
const MT_MAX_SLOTS: u64 = 2 * u16::MAX as u64;

/// GC static block state bit: has pre-initialized data.
const GC_STATIC_HAS_PREINIT: u64 = 2;

/// Unwind block flags: function kind (0 = root, else funclet).
const UBF_FUNC_KIND_MASK: u8 = 0x03;
/// Unwind block flag: the LSDA points at EH info.
const UBF_HAS_EHINFO: u8 = 0x04;
/// Unwind block flag: the LSDA points at associated data.
const UBF_HAS_ASSOCIATED_DATA: u8 = 0x10;
/// Associated data flag: a RELPTR32 to the unboxing stub target follows.
const ASSOC_HAS_UNBOXING_STUB_TARGET: u8 = 0x01;
/// EH clause kind: typed (catch); a RELPTR32 to the type follows.
const EH_CLAUSE_TYPED: u32 = 0;
/// EH clause kind: fault or finally.
const EH_CLAUSE_FAULT: u32 = 1;
/// EH clause kind: filter.
const EH_CLAUSE_FILTER: u32 = 2;

/// Section holding NativeAOT's LSDAs.
const EH_TABLE: &str = ".dotnet_eh_table";

/// What kind of structure holds a RELPTR32.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RefKind {
    /// First word of the dehydrated data: where it is rebuilt.
    DehydratedDest,
    /// Inline pointer of a dehydrated data command (unaligned).
    DehydratedInline,
    /// Entry of the fixup table that follows the dehydrated commands.
    DehydratedFixup,
    /// Entry of an ExternalReferences table.
    ExternalReference,
    /// Entry of the GC static region: a GC static block.
    GcStaticBlock,
    /// First word of a GC static block: its MethodTable, with state
    /// bits in the low two bits of the target.
    GcStaticType,
    /// Second word of a GC static block: its pre-initialized data.
    GcStaticPreInit,
    /// Eager class constructor.
    EagerCctor,
    /// Module initializer.
    ModuleInitializer,
    /// Sealed vtable slot.
    SealedVTableSlot,
    /// Funclet LSDA: the LSDA of its main function.
    LsdaMain,
    /// Main LSDA: associated data.
    LsdaAssociatedData,
    /// Main LSDA: EH info.
    LsdaEhInfo,
    /// Associated data: the method an unboxing stub calls.
    UnboxingStubTarget,
    /// Typed EH clause: the caught type.
    EhClauseType,
}

/// The structure that owns a RELPTR32.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Owner {
    /// Reached from this ReadyToRun section (sealed vtables: from the
    /// MethodTables of the dehydrated data, 207).
    R2r(u32),
    /// Reached from `.eh_frame` FDEs (LSDAs in `.dotnet_eh_table`).
    UnwindInfo,
}

/// One RELPTR32 the runtime dereferences.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelPtr {
    /// Address of the 32-bit field.
    pub location: u64,
    /// `location` plus the field's signed value.
    pub target: u64,
    /// Structure the field belongs to.
    pub kind: RefKind,
    /// Where that structure is reached from.
    pub owner_section: Owner,
}

impl RelPtr {
    /// A reference at `location` designating `target`.
    fn new(location: u64, target: u64, kind: RefKind, owner_section: Owner) -> Self {
        RelPtr { location, target, kind, owner_section }
    }
}

/// Why the model could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelError {
    /// `__modules` names no ReadyToRun header: nothing to model.
    NoHeader,
    /// A structure does not parse the way the runtime reads it, or is
    /// not modelled: the list would be incomplete.
    Malformed(String),
}

/// Shorthand for a `ModelError::Malformed`.
fn malformed(what: &str) -> ModelError {
    ModelError::Malformed(what.to_string())
}

// ---- Image view ----------------------------------------------------------

/// An allocated section of the image.
struct Region {
    /// Section name.
    name: String,
    /// First vaddr.
    start: u64,
    /// End vaddr (exclusive).
    end: u64,
    /// File offset of `start`.
    offset: u64,
    /// Backed by file bytes (not NOBITS).
    file: bool,
    /// Executable.
    exec: bool,
}

/// What the model reads from the image: allocated sections by address
/// and the addends of RELATIVE relocations.
struct Image<'a> {
    /// Whole file.
    data: &'a [u8],
    /// Allocated non-TLS sections, sorted by start.
    regions: Vec<Region>,
    /// RELATIVE relocation addend by slot address (RELA images).
    relative: HashMap<u64, u64>,
    /// Section list in the crate's form (for `.eh_frame` parsing).
    sections: Vec<Section>,
}

impl<'a> Image<'a> {
    /// Parse the ELF view. Only 64-bit little-endian images qualify.
    fn parse(data: &'a [u8]) -> Result<Self, ModelError> {
        let elf = goblin::elf::Elf::parse(data).map_err(|_| malformed("ELF"))?;
        if !elf.is_64 || !elf.little_endian {
            return Err(malformed("not a 64-bit little-endian ELF"));
        }
        Ok(Image {
            data,
            regions: regions_of(&elf, data.len()),
            relative: relative_addends(&elf),
            sections: super::sections::get_sections(&elf),
        })
    }

    /// The region holding `addr`.
    fn region(&self, addr: u64) -> Option<&Region> {
        let i = self.regions.partition_point(|r| r.start <= addr);
        let r = self.regions.get(i.checked_sub(1)?)?;
        (addr < r.end).then_some(r)
    }

    /// The region named `name`.
    fn named(&self, name: &str) -> Option<&Region> {
        self.regions.iter().find(|r| r.name == name)
    }

    /// File bytes `[addr, addr + len)`, if file-backed in one region.
    fn bytes(&self, addr: u64, len: u64) -> Option<&'a [u8]> {
        let r = self.region(addr).filter(|r| r.file)?;
        if addr.checked_add(len)? > r.end {
            return None;
        }
        let off = usize::try_from(r.offset + (addr - r.start)).ok()?;
        self.data.get(off..off.checked_add(usize::try_from(len).ok()?)?)
    }

    /// Byte at `addr`.
    fn u8_at(&self, addr: u64) -> Option<u8> {
        self.bytes(addr, 1).map(|b| b[0])
    }

    /// Little-endian u32 at `addr`.
    fn u32_at(&self, addr: u64) -> Option<u32> {
        let b = self.bytes(addr, 4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Target of the RELPTR32 at `addr`.
    fn relptr(&self, addr: u64) -> Option<u64> {
        let v = self.u32_at(addr)? as i32;
        Some(addr.wrapping_add(v as i64 as u64))
    }

    /// Pointer stored at `addr`: the RELATIVE addend for that slot if
    /// there is one, else the bytes in place (REL, RELR, non-PIE).
    fn ptr(&self, addr: u64) -> Option<u64> {
        if let Some(&a) = self.relative.get(&addr) {
            return Some(a);
        }
        let b = self.bytes(addr, 8)?;
        let mut w = [0u8; 8];
        w.copy_from_slice(b);
        Some(u64::from_le_bytes(w))
    }

    /// True if `addr` lies in an executable section.
    fn is_exec(&self, addr: u64) -> bool {
        self.region(addr).map_or(false, |r| r.exec)
    }
}

/// Allocated, non-TLS sections with an address, sorted by start.
fn regions_of(elf: &goblin::elf::Elf, file_len: usize) -> Vec<Region> {
    use goblin::elf::section_header::{
        SHF_ALLOC, SHF_EXECINSTR, SHF_TLS, SHT_NOBITS,
    };
    let mut v: Vec<Region> = elf
        .section_headers
        .iter()
        .filter(|sh| sh.sh_flags & SHF_ALLOC as u64 != 0)
        .filter(|sh| sh.sh_flags & SHF_TLS as u64 == 0)
        .filter(|sh| sh.sh_addr != 0 && sh.sh_size != 0)
        .filter_map(|sh| {
            let end = sh.sh_addr.checked_add(sh.sh_size)?;
            let file_end = sh.sh_offset.checked_add(sh.sh_size)?;
            Some(Region {
                name: elf.shdr_strtab.get_at(sh.sh_name)?.to_string(),
                start: sh.sh_addr,
                end,
                offset: sh.sh_offset,
                file: sh.sh_type != SHT_NOBITS && file_end <= file_len as u64,
                exec: sh.sh_flags & SHF_EXECINSTR as u64 != 0,
            })
        })
        .collect();
    v.sort_by_key(|r| r.start);
    v
}

/// RELATIVE relocation addends by slot address (x86-64 and AArch64).
fn relative_addends(elf: &goblin::elf::Elf) -> HashMap<u64, u64> {
    use goblin::elf::header::{EM_AARCH64, EM_X86_64};
    let rtype = match elf.header.e_machine {
        EM_X86_64 => 8,
        EM_AARCH64 => 1027,
        _ => return HashMap::new(),
    };
    elf.dynrelas
        .iter()
        .filter(|r| r.r_type == rtype)
        .filter_map(|r| Some((r.r_offset, r.r_addend? as u64)))
        .collect()
}

// ---- ReadyToRun header -----------------------------------------------------

/// One row of the ReadyToRun section table.
#[derive(Debug, Clone, Copy)]
struct R2rSection {
    /// Section id (ReadyToRunSectionType).
    id: u32,
    /// First address.
    start: u64,
    /// End address (exclusive); `start` for rows without an end pointer.
    end: u64,
}

/// The ReadyToRun headers `__modules` names: (header address, rows).
/// `NoHeader` if `__modules` is absent or names no header.
fn read_headers(img: &Image) -> Result<Vec<(u64, Vec<R2rSection>)>, ModelError> {
    let m = img.named("__modules").ok_or(ModelError::NoHeader)?;
    let mut out = Vec::new();
    let mut slot = m.start;
    while slot + 8 <= m.end {
        let h = img.ptr(slot).unwrap_or(0);
        if h != 0 && img.u32_at(h) == Some(R2R_SIGNATURE) {
            out.push((h, read_rows(img, h)?));
        }
        slot += 8;
    }
    if out.is_empty() {
        return Err(ModelError::NoHeader);
    }
    Ok(out)
}

/// Rows of the ReadyToRun header at `h`. Refuses versions other than
/// the verified one and rows too small for two pointers.
fn read_rows(img: &Image, h: u64) -> Result<Vec<R2rSection>, ModelError> {
    let hdr = img.bytes(h, R2R_HEADER_SIZE).ok_or(malformed("R2R header"))?;
    let major = u16::from_le_bytes([hdr[4], hdr[5]]);
    let minor = u16::from_le_bytes([hdr[6], hdr[7]]);
    if major != R2R_MAJOR {
        return Err(ModelError::Malformed(format!(
            "ReadyToRun version {}.{} not verified", major, minor
        )));
    }
    let count = u16::from_le_bytes([hdr[12], hdr[13]]) as u64;
    let size = hdr[14] as u64;
    if size < 24 {
        return Err(malformed("R2R section row size"));
    }
    (0..count)
        .map(|i| read_row(img, h + R2R_HEADER_SIZE + i * size))
        .collect()
}

/// The section table row at `row`.
fn read_row(img: &Image, row: u64) -> Result<R2rSection, ModelError> {
    let bad = || malformed("R2R section row");
    let id = img.u32_at(row).ok_or_else(bad)?;
    let flags = img.u32_at(row + 4).ok_or_else(bad)?;
    let start = img.ptr(row + 8).ok_or_else(bad)?;
    let end = if flags & ROW_HAS_END != 0 {
        img.ptr(row + 16).ok_or_else(bad)?
    } else {
        start
    };
    if end < start {
        return Err(bad());
    }
    Ok(R2rSection { id, start, end })
}

// ---- Entry points ------------------------------------------------------------

/// Every RELPTR32 the NativeAOT runtime dereferences in `data`, sorted
/// by location.
pub fn nativeaot_refs(data: &[u8]) -> Result<Vec<RelPtr>, ModelError> {
    refs_of(&Image::parse(data)?)
}

/// `nativeaot_refs` on a parsed image.
fn refs_of(img: &Image) -> Result<Vec<RelPtr>, ModelError> {
    let mut out = Vec::new();
    for (h, rows) in read_headers(img)? {
        module_refs(img, h, &rows, &mut out)?;
    }
    unwind_refs(img, &mut out)?;
    Ok(dedup(out))
}

/// Targets of `nativeaot_refs` that lie in executable sections: code
/// the runtime can reach through ReadyToRun data. Sorted, unique.
pub fn nativeaot_code_refs(data: &[u8]) -> Result<Vec<u64>, ModelError> {
    let img = Image::parse(data)?;
    let set: BTreeSet<u64> = refs_of(&img)?
        .iter()
        .map(|r| r.target)
        .filter(|&t| img.is_exec(t))
        .collect();
    Ok(set.into_iter().collect())
}

/// Liveness roots for a NativeAOT image: the functions holding a code
/// target of `nativeaot_code_refs`. If `__modules` names no ReadyToRun
/// header there is nothing to add. If the model cannot be built
/// exactly, every function is returned: what the runtime can reach is
/// then unknown, so nothing may be called dead (fail closed).
pub fn root_names(data: &[u8], funcs: &FuncMap) -> Vec<String> {
    match nativeaot_code_refs(data) {
        Ok(targets) => {
            let names = containing_funcs(funcs, &targets);
            eprintln!(
                "  note: NativeAOT: {} ReadyToRun references into code \
                 ({} functions kept live)",
                targets.len(),
                names.len()
            );
            names
        }
        Err(ModelError::NoHeader) => Vec::new(),
        Err(ModelError::Malformed(why)) => {
            eprintln!(
                "  note: NativeAOT: ReadyToRun data not modelled ({}); \
                 all functions kept live",
                why
            );
            funcs.keys().cloned().collect()
        }
    }
}

/// Names of the functions whose range holds one of `targets`.
fn containing_funcs(funcs: &FuncMap, targets: &[u64]) -> Vec<String> {
    let mut by_addr: Vec<(u64, u64, &String)> = funcs
        .iter()
        .map(|(n, f)| (f.addr, f.addr.saturating_add(f.size), n))
        .collect();
    by_addr.sort();
    let mut names = BTreeSet::new();
    for &t in targets {
        let i = by_addr.partition_point(|e| e.0 <= t);
        if let Some(&(_, end, n)) = i.checked_sub(1).and_then(|j| by_addr.get(j)) {
            if t < end {
                names.insert(n.clone());
            }
        }
    }
    names.into_iter().collect()
}

/// Sort by location and drop repeats of a location.
fn dedup(refs: Vec<RelPtr>) -> Vec<RelPtr> {
    let mut by_loc: BTreeMap<u64, RelPtr> = BTreeMap::new();
    for r in refs {
        by_loc.entry(r.location).or_insert(r);
    }
    by_loc.into_values().collect()
}

/// The references of the module whose header is at `h`.
fn module_refs(
    img: &Image,
    h: u64,
    rows: &[R2rSection],
    out: &mut Vec<RelPtr>,
) -> Result<(), ModelError> {
    for s in rows {
        section_refs(img, s, out)?;
    }
    let dehydrated = rows.iter().find(|s| s.id == SEC_DEHYDRATED_DATA);
    if let Some(s) = dehydrated {
        let hyd = dehydrate(img, s, out)?;
        let tmi = rows
            .iter()
            .find(|r| r.id == SEC_TYPE_MANAGER_INDIRECTION)
            .ok_or(malformed("no type manager indirection"))?;
        let starts = sealed_vtables(&hyd, tmi.start)?;
        let bounds = object_starts(img, &starts, h, rows, &hyd, out);
        sealed_slots(img, &starts, &bounds, out)?;
    }
    Ok(())
}

/// The references a ReadyToRun section holds directly, by section id.
/// Ids known to hold none are skipped; unknown ids are refused.
fn section_refs(
    img: &Image,
    s: &R2rSection,
    out: &mut Vec<RelPtr>,
) -> Result<(), ModelError> {
    match s.id {
        SEC_GC_STATIC_REGION => gc_static_region(img, s, out),
        SEC_EAGER_CCTOR => relptr_array(img, s, RefKind::EagerCctor, out),
        SEC_MODULE_INITIALIZERS => {
            relptr_array(img, s, RefKind::ModuleInitializer, out)
        }
        id if SEC_EXTERNAL_REFERENCES.contains(&id) => {
            relptr_array(img, s, RefKind::ExternalReference, out)
        }
        SEC_STACK_TRACE_MAPPING => stack_trace_mapping(img, s),
        SEC_THREAD_STATIC_REGION
        | SEC_TYPE_MANAGER_INDIRECTION
        | SEC_FROZEN_OBJECTS
        | SEC_DEHYDRATED_DATA => Ok(()),
        id if (SEC_BLOB_FIRST..=SEC_BLOB_LAST).contains(&id) => Ok(()),
        id => Err(ModelError::Malformed(format!(
            "ReadyToRun section {} not modelled",
            id
        ))),
    }
}

/// The stack trace method mapping: accepted only when empty (a zero
/// entry count), as compiled without stack trace data.
fn stack_trace_mapping(img: &Image, s: &R2rSection) -> Result<(), ModelError> {
    let len = s.end - s.start;
    let empty = len == 0 || (len == 4 && img.u32_at(s.start) == Some(0));
    if empty {
        Ok(())
    } else {
        Err(malformed("stack trace method mapping"))
    }
}

/// A section that is an array of RELPTR32s, each of kind `kind`.
fn relptr_array(
    img: &Image,
    s: &R2rSection,
    kind: RefKind,
    out: &mut Vec<RelPtr>,
) -> Result<(), ModelError> {
    let len = s.end - s.start;
    if len == 0 {
        return Ok(());
    }
    if len % 4 != 0 || img.bytes(s.start, len).is_none() {
        return Err(ModelError::Malformed(format!(
            "ReadyToRun section {} is not a RELPTR32 array",
            s.id
        )));
    }
    for loc in (s.start..s.end).step_by(4) {
        let target = img.relptr(loc).ok_or(malformed("RELPTR32"))?;
        out.push(RelPtr::new(loc, target, kind, Owner::R2r(s.id)));
    }
    Ok(())
}

/// The GC static region and the GC static blocks it names. A block's
/// first word points at its MethodTable (low bits: state); with the
/// pre-initialized-data bit set, its second word points at that data.
fn gc_static_region(
    img: &Image,
    s: &R2rSection,
    out: &mut Vec<RelPtr>,
) -> Result<(), ModelError> {
    let first = out.len();
    relptr_array(img, s, RefKind::GcStaticBlock, out)?;
    let blocks: Vec<u64> = out[first..].iter().map(|r| r.target).collect();
    let owner = Owner::R2r(s.id);
    for b in blocks {
        let t = img.relptr(b).ok_or(malformed("GC static block"))?;
        out.push(RelPtr::new(b, t, RefKind::GcStaticType, owner));
        if t & GC_STATIC_HAS_PREINIT != 0 {
            let p = img.relptr(b + 4).ok_or(malformed("GC static block"))?;
            out.push(RelPtr::new(b + 4, p, RefKind::GcStaticPreInit, owner));
        }
    }
    Ok(())
}

// ---- Dehydrated data -----------------------------------------------------------

/// Memory the dehydrated data rebuilds at startup.
struct Hydrated {
    /// Address the data is rebuilt at.
    base: u64,
    /// Rebuilt bytes; pointer slots hold zero.
    bytes: Vec<u8>,
    /// Pointers written, sorted by address: (address, width, target).
    writes: Vec<(u64, u64, u64)>,
}

impl Hydrated {
    /// Address of the next byte written.
    fn cursor(&self) -> u64 {
        self.base + self.bytes.len() as u64
    }

    /// Append `n` zero bytes.
    fn zero(&mut self, n: u64) {
        self.bytes.resize(self.bytes.len() + n as usize, 0);
    }

    /// Little-endian integer of `n` bytes at `addr`.
    fn uint(&self, addr: u64, n: usize) -> Option<u64> {
        let i = usize::try_from(addr.checked_sub(self.base)?).ok()?;
        let b = self.bytes.get(i..i.checked_add(n)?)?;
        Some(b.iter().rev().fold(0u64, |v, &x| (v << 8) | x as u64))
    }

    /// The write starting exactly at `addr`.
    fn write_at(&self, addr: u64) -> Option<&(u64, u64, u64)> {
        let i = self.writes.binary_search_by_key(&addr, |w| w.0).ok()?;
        self.writes.get(i)
    }

    /// True if no write overlaps `[addr, addr + n)`.
    fn plain(&self, addr: u64, n: u64) -> bool {
        let i = self.writes.partition_point(|w| w.0 + w.1 <= addr);
        self.writes.get(i).map_or(true, |w| w.0 >= addr + n)
    }

    /// True if the 8 bytes at `addr` are a pointer write or plain zero.
    fn ptr_or_null(&self, addr: u64) -> bool {
        if self.write_at(addr).map_or(false, |w| w.1 == 8) {
            return true;
        }
        self.plain(addr, 8) && self.uint(addr, 8) == Some(0)
    }
}

/// Decode the dehydrated data of section `s`: list its references
/// (destination, inline pointers, fixup table) and rebuild the memory
/// it describes.
fn dehydrate(
    img: &Image,
    s: &R2rSection,
    out: &mut Vec<RelPtr>,
) -> Result<Hydrated, ModelError> {
    let bad = |w: &str| ModelError::Malformed(format!("dehydrated data: {}", w));
    let owner = Owner::R2r(s.id);
    let dest = img.relptr(s.start).ok_or_else(|| bad("destination"))?;
    let room = img
        .region(dest)
        .filter(|r| !r.exec)
        .map(|r| r.end - dest)
        .ok_or_else(|| bad("destination"))?;
    out.push(RelPtr::new(s.start, dest, RefKind::DehydratedDest, owner));
    let len = s.end.checked_sub(s.start + 4).ok_or_else(|| bad("length"))?;
    let stream = img.bytes(s.start + 4, len).ok_or_else(|| bad("stream"))?;
    let mut hyd = Hydrated { base: dest, bytes: Vec::new(), writes: Vec::new() };
    let fixups = run_commands(img, s, stream, room, &mut hyd, out)?;
    resolve_fixups(img, s, &fixups, &mut hyd, out)?;
    hyd.writes.sort_unstable();
    Ok(hyd)
}

/// Run the command stream into `hyd`. Inline pointers go to `out`;
/// returns the fixup uses as (address written, width, fixup index).
fn run_commands(
    img: &Image,
    s: &R2rSection,
    stream: &[u8],
    room: u64,
    hyd: &mut Hydrated,
    out: &mut Vec<RelPtr>,
) -> Result<Vec<(u64, u64, u64)>, ModelError> {
    let bad = |w: &str| ModelError::Malformed(format!("dehydrated data: {}", w));
    let owner = Owner::R2r(s.id);
    let mut fixups = Vec::new();
    let mut p = 0usize;
    while p < stream.len() {
        let (cmd, payload, next) =
            decode_command(stream, p).ok_or_else(|| bad("command"))?;
        p = next;
        let size =
            command_output(cmd, payload).ok_or_else(|| bad("command"))?;
        if hyd.bytes.len() as u64 + size > room {
            return Err(bad("output overruns its section"));
        }
        match cmd {
            CMD_COPY => {
                let b = stream.get(p..p + payload as usize).ok_or_else(|| bad("copy"))?;
                hyd.bytes.extend_from_slice(b);
                p += payload as usize;
            }
            CMD_ZERO_FILL => hyd.zero(payload),
            CMD_RELPTR32_RELOC | CMD_PTR_RELOC => {
                fixups.push((hyd.cursor(), size, payload));
                hyd.zero(size);
            }
            _ => {
                let width = size / payload.max(1);
                for _ in 0..payload {
                    let loc = s.start + 4 + p as u64;
                    let t = img.relptr(loc).ok_or_else(|| bad("inline pointer"))?;
                    out.push(RelPtr::new(loc, t, RefKind::DehydratedInline, owner));
                    hyd.writes.push((hyd.cursor(), width, t));
                    hyd.zero(width);
                    p += 4;
                }
            }
        }
    }
    if p != stream.len() {
        return Err(bad("stream overruns its section"));
    }
    Ok(fixups)
}

/// Decode the command at `p`: (command, payload, position after it).
/// A payload above `MAX_SHORT_PAYLOAD` holds the count of 1 to 3 extra
/// little-endian payload bytes, added to `MAX_SHORT_PAYLOAD`.
fn decode_command(s: &[u8], p: usize) -> Option<(u8, u64, usize)> {
    let b = *s.get(p)?;
    let short = (b >> 3) as usize;
    if short <= MAX_SHORT_PAYLOAD {
        return Some((b & 7, short as u64, p + 1));
    }
    let extra = short - MAX_SHORT_PAYLOAD;
    let bytes = s.get(p + 1..p + 1 + extra)?;
    let v = bytes.iter().rev().fold(0u64, |v, &x| (v << 8) | x as u64);
    Some((b & 7, v + MAX_SHORT_PAYLOAD as u64, p + 1 + extra))
}

/// Bytes command `cmd` writes for `payload`; None for an unknown
/// command or an empty inline run.
fn command_output(cmd: u8, payload: u64) -> Option<u64> {
    match cmd {
        CMD_COPY | CMD_ZERO_FILL => Some(payload),
        CMD_RELPTR32_RELOC => Some(4),
        CMD_PTR_RELOC => Some(8),
        CMD_INLINE_RELPTR32_RELOC if payload > 0 => Some(4 * payload),
        CMD_INLINE_PTR_RELOC if payload > 0 => Some(8 * payload),
        _ => None,
    }
}

/// List the fixup table after the stream (as long as the largest index
/// used requires) and record the pointers its uses write.
fn resolve_fixups(
    img: &Image,
    s: &R2rSection,
    uses: &[(u64, u64, u64)],
    hyd: &mut Hydrated,
    out: &mut Vec<RelPtr>,
) -> Result<(), ModelError> {
    let count = match uses.iter().map(|u| u.2).max() {
        Some(m) => m + 1,
        None => return Ok(()),
    };
    let bad = || malformed("dehydrated data: fixup table");
    img.bytes(s.end, 4 * count).ok_or_else(bad)?;
    let mut targets = Vec::with_capacity(count as usize);
    for i in 0..count {
        let loc = s.end + 4 * i;
        let t = img.relptr(loc).ok_or_else(bad)?;
        out.push(RelPtr::new(loc, t, RefKind::DehydratedFixup, Owner::R2r(s.id)));
        targets.push(t);
    }
    for &(addr, width, idx) in uses {
        let t = *targets.get(idx as usize).ok_or_else(bad)?;
        hyd.writes.push((addr, width, t));
    }
    Ok(())
}

// ---- Sealed vtables ---------------------------------------------------------------

/// Sealed vtable addresses named by the rebuilt MethodTables. Each
/// MethodTable holds a RELPTR32 to the type manager indirection `tmi`
/// right after its vtable and interface list; its flags then say which
/// optional RELPTR32 fields follow: writable data (always), dispatch
/// map, finalizer, sealed vtable.
fn sealed_vtables(hyd: &Hydrated, tmi: u64) -> Result<BTreeSet<u64>, ModelError> {
    let mut starts = BTreeSet::new();
    let anchors = hyd.writes.iter().filter(|w| w.1 == 4 && w.2 == tmi);
    for &(field, _, _) in anchors {
        let m = method_table_start(hyd, field).ok_or(malformed("MethodTable"))?;
        let flags = hyd.uint(m, 4).ok_or(malformed("MethodTable"))? as u32;
        if flags & MT_HAS_SEALED_VTABLE == 0 {
            continue;
        }
        let mut at = field + 8;
        if flags & MT_HAS_DISPATCH_MAP != 0 {
            at += 4;
        }
        if flags & MT_HAS_FINALIZER != 0 {
            at += 4;
        }
        let w = hyd.write_at(at).filter(|w| w.1 == 4);
        starts.insert(w.ok_or(malformed("sealed vtable field"))?.2);
    }
    Ok(starts)
}

/// Start of the MethodTable whose type manager field is at `field`: an
/// `m` below it whose slot counts place the field there, with a plain
/// (non-pointer) non-zero first word (flags, base size), a plain count
/// word, and only pointers or null from the related type to the field.
/// Between `m` and the field the only plain non-zero words are the two
/// header words, so the only other `m` that can pass is 16 bytes above
/// the real one (two slots, the second null); the lower one wins.
fn method_table_start(hyd: &Hydrated, field: u64) -> Option<u64> {
    for n in 0..=MT_MAX_SLOTS {
        let m = field.checked_sub(MT_FIXED + 8 * n)?;
        if m < hyd.base {
            return None;
        }
        if is_method_table(hyd, m, n) {
            let below = m.checked_sub(16).filter(|&b| b >= hyd.base);
            let lower = below.filter(|&b| is_method_table(hyd, b, n + 2));
            return Some(lower.unwrap_or(m));
        }
    }
    None
}

/// True if a MethodTable with `n` vtable plus interface slots starts at
/// `m` (see `method_table_start`).
fn is_method_table(hyd: &Hydrated, m: u64, n: u64) -> bool {
    let slots = hyd.uint(m + 16, 2).zip(hyd.uint(m + 18, 2));
    if slots.map(|(v, i)| v + i) != Some(n) {
        return false;
    }
    hyd.uint(m, 8).map_or(false, |f| f != 0)
        && hyd.plain(m, 8)
        && hyd.plain(m + 16, 8)
        && hyd.ptr_or_null(m + 8)
        && (0..n).all(|j| hyd.ptr_or_null(m + MT_FIXED + 8 * j))
}

/// Addresses, inside the sections holding the sealed vtables `starts`,
/// where some known object starts: the header, section bounds, targets
/// of the rebuilt pointers and of the references found so far.
fn object_starts(
    img: &Image,
    starts: &BTreeSet<u64>,
    h: u64,
    rows: &[R2rSection],
    hyd: &Hydrated,
    out: &[RelPtr],
) -> BTreeSet<u64> {
    let spans: BTreeSet<(u64, u64)> = starts
        .iter()
        .filter_map(|&s| img.region(s).map(|r| (r.start, r.end)))
        .collect();
    let inside = |a: &u64| spans.iter().any(|&(lo, hi)| lo <= *a && *a < hi);
    let rows = rows.iter().flat_map(|r| [r.start, r.end]);
    let writes = hyd.writes.iter().map(|w| w.2);
    let refs = out.iter().map(|r| r.target);
    std::iter::once(h).chain(rows).chain(writes).chain(refs).filter(inside).collect()
}

/// List the slots of each sealed vtable. A sealed vtable stores no slot
/// count: it runs to the next known object start (`bounds`) or the end
/// of its section. Every slot must point into code, or the bound is not
/// exact and the model is refused.
fn sealed_slots(
    img: &Image,
    starts: &BTreeSet<u64>,
    bounds: &BTreeSet<u64>,
    out: &mut Vec<RelPtr>,
) -> Result<(), ModelError> {
    let bad = || malformed("sealed vtable");
    let owner = Owner::R2r(SEC_DEHYDRATED_DATA);
    for &s in starts {
        let r = img.region(s).filter(|r| r.file && !r.exec).ok_or_else(bad)?;
        let next = bounds.range(s + 1..).next().copied().unwrap_or(r.end);
        let end = next.min(r.end);
        if (end - s) % 4 != 0 {
            return Err(bad());
        }
        for loc in (s..end).step_by(4) {
            let t = img.relptr(loc).filter(|&t| img.is_exec(t));
            let t = t.ok_or_else(bad)?;
            out.push(RelPtr::new(loc, t, RefKind::SealedVTableSlot, owner));
        }
    }
    Ok(())
}

// ---- Unwind info ------------------------------------------------------------------

/// References in `.dotnet_eh_table` LSDAs (named by `.eh_frame` FDEs)
/// and in the associated data and EH info they point at.
fn unwind_refs(img: &Image, out: &mut Vec<RelPtr>) -> Result<(), ModelError> {
    let eh = match img.named(EH_TABLE) {
        Some(r) => (r.start, r.end),
        None => return Ok(()),
    };
    let mut assoc = BTreeSet::new();
    let mut infos = BTreeSet::new();
    let lsdas: BTreeSet<u64> = ehframe::fde_lsdas(img.data, &img.sections)
        .into_iter()
        .map(|(_, l)| l)
        .filter(|&l| eh.0 <= l && l < eh.1)
        .collect();
    for l in lsdas {
        lsda_refs(img, l, eh, out, &mut assoc, &mut infos)?;
    }
    for a in assoc {
        associated_refs(img, a, out)?;
    }
    for i in infos {
        eh_info_refs(img, i, out)?;
    }
    Ok(())
}

/// The pointers of the LSDA at `l`: a funclet's points at its main
/// LSDA (inside `eh`); a main LSDA's at its associated data and EH info
/// when its flags say so (collected into `assoc` and `infos`).
fn lsda_refs(
    img: &Image,
    l: u64,
    eh: (u64, u64),
    out: &mut Vec<RelPtr>,
    assoc: &mut BTreeSet<u64>,
    infos: &mut BTreeSet<u64>,
) -> Result<(), ModelError> {
    let bad = || malformed("LSDA");
    let flags = img.u8_at(l).ok_or_else(bad)?;
    let mut push = |loc: u64, kind: RefKind| -> Result<u64, ModelError> {
        let t = img.relptr(loc).ok_or_else(bad)?;
        out.push(RelPtr::new(loc, t, kind, Owner::UnwindInfo));
        Ok(t)
    };
    if flags & UBF_FUNC_KIND_MASK != 0 {
        let main = push(l + 1, RefKind::LsdaMain)?;
        return if eh.0 <= main && main < eh.1 { Ok(()) } else { Err(bad()) };
    }
    let mut q = l + 1;
    if flags & UBF_HAS_ASSOCIATED_DATA != 0 {
        assoc.insert(push(q, RefKind::LsdaAssociatedData)?);
        q += 4;
    }
    if flags & UBF_HAS_EHINFO != 0 {
        infos.insert(push(q, RefKind::LsdaEhInfo)?);
    }
    Ok(())
}

/// Associated data at `a`: a flags byte, then a RELPTR32 to the method
/// an unboxing stub calls when the flag says so.
fn associated_refs(img: &Image, a: u64, out: &mut Vec<RelPtr>) -> Result<(), ModelError> {
    let flags = img.u8_at(a).ok_or(malformed("associated data"))?;
    if flags & ASSOC_HAS_UNBOXING_STUB_TARGET != 0 {
        let t = img.relptr(a + 1).ok_or(malformed("associated data"))?;
        out.push(RelPtr::new(a + 1, t, RefKind::UnboxingStubTarget, Owner::UnwindInfo));
    }
    Ok(())
}

/// EH info at `i`: a clause count, then per clause the try start and
/// (try length << 2 | kind); a typed clause adds the handler offset and
/// a RELPTR32 to the caught type, a fault clause the handler offset, a
/// filter clause the handler and filter offsets. Offsets are NativeFormat
/// unsigned integers.
fn eh_info_refs(img: &Image, i: u64, out: &mut Vec<RelPtr>) -> Result<(), ModelError> {
    let bad = || malformed("EH info");
    let mut p = i;
    let count = read_unsigned(img, &mut p).ok_or_else(bad)?;
    for _ in 0..count {
        read_unsigned(img, &mut p).ok_or_else(bad)?;
        let kind = read_unsigned(img, &mut p).ok_or_else(bad)? & 3;
        read_unsigned(img, &mut p).ok_or_else(bad)?;
        match kind {
            EH_CLAUSE_TYPED => {
                let t = img.relptr(p).ok_or_else(bad)?;
                out.push(RelPtr::new(p, t, RefKind::EhClauseType, Owner::UnwindInfo));
                p += 4;
            }
            EH_CLAUSE_FAULT => {}
            EH_CLAUSE_FILTER => {
                read_unsigned(img, &mut p).ok_or_else(bad)?;
            }
            _ => return Err(bad()),
        }
    }
    Ok(())
}

/// Read a NativeFormat unsigned integer at `*p` and advance past it.
/// The low bits of the first byte give the length: x0 one byte, x01
/// two, x011 three, x0111 four, 1111 a full 32-bit value after it.
fn read_unsigned(img: &Image, p: &mut u64) -> Option<u32> {
    let b0 = img.u8_at(*p)? as u32;
    let len = (b0.trailing_ones() + 1).min(5) as u64;
    let v = if len == 5 {
        img.u32_at(*p + 1)?
    } else {
        let b = img.bytes(*p, len)?;
        let raw = b.iter().rev().fold(0u32, |v, &x| (v << 8) | x as u32);
        raw >> len
    };
    *p += len;
    Some(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::FuncInfo;

    /// Short payloads sit in the command byte; larger ones add 1 to 3
    /// little-endian bytes on top of MAX_SHORT_PAYLOAD.
    #[test]
    fn decodes_command_payloads() {
        assert_eq!(decode_command(&[(5 << 3) | 2], 0), Some((2, 5, 1)));
        assert_eq!(decode_command(&[(29 << 3), 0x10], 0), Some((0, 44, 2)));
        let three = [(31 << 3) | 1, 0x01, 0x02, 0x03];
        assert_eq!(decode_command(&three, 0), Some((1, 0x030201 + 28, 4)));
        assert_eq!(decode_command(&[(30 << 3) | 4, 0x01], 0), None);
    }

    /// Output sizes per command; unknown commands and empty inline runs
    /// are refused.
    #[test]
    fn sizes_command_output() {
        assert_eq!(command_output(CMD_COPY, 7), Some(7));
        assert_eq!(command_output(CMD_PTR_RELOC, 99), Some(8));
        assert_eq!(command_output(CMD_INLINE_RELPTR32_RELOC, 3), Some(12));
        assert_eq!(command_output(CMD_INLINE_PTR_RELOC, 0), None);
        assert_eq!(command_output(6, 1), None);
    }

    /// A MethodTable is found below its type manager field from its slot
    /// counts, with pointer or null slots between.
    #[test]
    fn finds_method_table_start() {
        let mut bytes = vec![0u8; 64];
        bytes[0] = 0x10; // flags
        bytes[16] = 2; // two vtable slots
        let hyd = Hydrated {
            base: 0x1000,
            bytes,
            writes: vec![(0x1018, 8, 0x500), (0x1028, 4, 0x9000)],
        };
        assert_eq!(method_table_start(&hyd, 0x1028), Some(0x1000));
        assert!(!hyd.plain(0x101c, 4));
        assert!(hyd.ptr_or_null(0x1020));
    }

    /// Targets map to the function whose range holds them.
    #[test]
    fn maps_targets_to_functions() {
        let mut funcs = FuncMap::new();
        let f = |addr, size| FuncInfo { addr, size, is_global: false };
        funcs.insert("a".into(), f(0x100, 0x10));
        funcs.insert("b".into(), f(0x120, 0x8));
        let names = containing_funcs(&funcs, &[0x105, 0x118, 0x120]);
        assert_eq!(names, vec!["a".to_string(), "b".to_string()]);
    }
}
