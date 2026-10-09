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
//! Stack trace data is not modelled: an image whose stack trace method
//! mapping (section 327) is not empty is refused, and then every function
//! is kept live. .NET compiles that data in by default; only images
//! published with `StackTraceSupport` set to false have an empty one.
//!
//! The parser is bounded for crafted input: it reads only file-backed
//! bytes of `__modules`, each header once; ReadyToRun rows must not
//! overlap; the references found may not outnumber the 4-byte fields of
//! the file; the rebuilt dehydrated data may not exceed a small multiple
//! of the file size; MethodTables, dispatch maps and EH info blocks must
//! not overlap, and each dispatch map is read once however many types
//! name it.
//!
//! The analysis runs once per image (`NativeAot`): analysis uses it for
//! liveness and function boundaries, compaction for its plan.
//!
//! Layouts follow the .NET runtime sources (ModuleHeaders.h,
//! StartupCodeHelpers.cs, DehydratedData.cs, ExternalReferencesTable.cs,
//! MethodTable.cs, UnixNativeCodeManager.cpp). They are verified for
//! ReadyToRun major version 16 (.NET 10) on 64-bit little-endian ELF;
//! other versions are refused.

use super::ehframe;
use crate::arch::x86_patch::TableEntry;
use crate::patch::data_ptrs::PtrSlot;
use crate::patch::relocs::{in_dead_range, total_shift};
use crate::patch::relptr::RelField;
use crate::types::{FuncMap, Section};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

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
/// Most bytes the dehydrated data may rebuild per byte of the file. Its
/// destination is usually a NOBITS section, whose size the file does not
/// bound; real images rebuild less than the file holds (.NET 10: about
/// 0.4 bytes per file byte), so this only stops crafted zero runs from
/// exhausting memory.
const HYDRATED_PER_FILE_BYTE: u64 = 4;

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

/// Dispatch map header: four 16-bit entry counts (standard, default,
/// standard static, default static).
const DISPATCH_HEADER: u64 = 8;
/// Bytes of an instance dispatch map entry: 16-bit interface index,
/// interface slot and implementation slot.
const DISPATCH_ENTRY: u64 = 6;
/// Bytes of a static dispatch map entry: an instance entry plus its
/// 16-bit generic context source.
const DISPATCH_STATIC_ENTRY: u64 = 8;
/// Implementation slots from here up are special (diamond,
/// reabstraction), not slots.
const DISPATCH_SPECIAL_SLOT: u64 = 0xfffe;

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
    /// `__modules` names no ReadyToRun header: nothing to model. Holds
    /// the number of non-null `__modules` slots (pointers to something
    /// that is not a ReadyToRun header).
    NoHeader(usize),
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
    /// Section type (`sh_type`).
    sh_type: u32,
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

    /// File offset of `[addr, addr + len)`, if file-backed in one region
    /// and inside the file.
    fn offset(&self, addr: u64, len: u64) -> Option<usize> {
        let r = self.region(addr).filter(|r| r.file)?;
        if addr.checked_add(len)? > r.end {
            return None;
        }
        let off = usize::try_from(r.offset + (addr - r.start)).ok()?;
        let end = off.checked_add(usize::try_from(len).ok()?)?;
        (end <= self.data.len()).then_some(off)
    }

    /// File bytes `[addr, addr + len)`, if file-backed in one region.
    fn bytes(&self, addr: u64, len: u64) -> Option<&'a [u8]> {
        let off = self.offset(addr, len)?;
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
                sh_type: sh.sh_type,
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
    /// The row has an end pointer (`ROW_HAS_END`).
    has_end: bool,
}

/// The ReadyToRun headers `__modules` names, each once, by address:
/// (header address, rows). Only the file-backed bytes of `__modules`
/// are read, one pointer per 8 bytes; a `__modules` that is not
/// file-backed (NOBITS, past the end of the file) is refused, as what
/// it holds at run time is unknown. `NoHeader` if `__modules` is absent
/// or names no header. The non-empty rows of all headers must not
/// overlap (`check_disjoint`).
fn read_headers(img: &Image) -> Result<Vec<(u64, Vec<R2rSection>)>, ModelError> {
    let m = img.named("__modules").ok_or(ModelError::NoHeader(0))?;
    if !m.file {
        return Err(malformed("__modules is not file-backed"));
    }
    let mut headers = BTreeSet::new();
    let mut non_null = 0;
    for i in 0..(m.end - m.start) / 8 {
        let h = img.ptr(m.start + 8 * i).unwrap_or(0);
        if h == 0 {
            continue;
        }
        non_null += 1;
        if img.u32_at(h) == Some(R2R_SIGNATURE) {
            headers.insert(h);
        }
    }
    if headers.is_empty() {
        return Err(ModelError::NoHeader(non_null));
    }
    let out = headers
        .into_iter()
        .map(|h| Ok((h, read_rows(img, h)?)))
        .collect::<Result<Vec<_>, ModelError>>()?;
    check_disjoint(&out)?;
    Ok(out)
}

/// Refuse headers whose non-empty rows overlap: each byte belongs to at
/// most one ReadyToRun section, so the work per byte stays bounded and
/// no structure is read twice under two meanings.
fn check_disjoint(headers: &[(u64, Vec<R2rSection>)]) -> Result<(), ModelError> {
    let mut spans: Vec<(u64, u64, u32)> = headers
        .iter()
        .flat_map(|(_, rows)| rows.iter())
        .filter(|s| s.start < s.end)
        .map(|s| (s.start, s.end, s.id))
        .collect();
    spans.sort_unstable();
    for w in spans.windows(2) {
        if w[1].0 < w[0].1 {
            return Err(ModelError::Malformed(format!(
                "ReadyToRun sections {} and {} overlap",
                w[0].2, w[1].2
            )));
        }
    }
    Ok(())
}

/// Rows of the ReadyToRun header at `h`. Refuses versions other than
/// the verified one, rows too small for two pointers and a section id
/// listed twice (the model reads one section per id).
fn read_rows(img: &Image, h: u64) -> Result<Vec<R2rSection>, ModelError> {
    let rows = read_table(img, h)?;
    let ids: BTreeSet<u32> = rows.iter().map(|s| s.id).collect();
    if ids.len() != rows.len() {
        return Err(malformed("R2R section id listed twice"));
    }
    Ok(rows)
}

/// The section table of the ReadyToRun header at `h`, as `read_rows`
/// describes it but for repeated ids.
fn read_table(img: &Image, h: u64) -> Result<Vec<R2rSection>, ModelError> {
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
        .map(|i| {
            let row = h.checked_add(R2R_HEADER_SIZE + i * size);
            read_row(img, row.ok_or(malformed("R2R section row"))?)
        })
        .collect()
}

/// The section table row at `row`.
fn read_row(img: &Image, row: u64) -> Result<R2rSection, ModelError> {
    let bad = || malformed("R2R section row");
    img.bytes(row, 24).ok_or_else(bad)?;
    let id = img.u32_at(row).ok_or_else(bad)?;
    let flags = img.u32_at(row + 4).ok_or_else(bad)?;
    let start = img.ptr(row + 8).ok_or_else(bad)?;
    let has_end = flags & ROW_HAS_END != 0;
    let end = if has_end {
        img.ptr(row + 16).ok_or_else(bad)?
    } else {
        start
    };
    if end < start {
        return Err(bad());
    }
    Ok(R2rSection { id, start, end, has_end })
}

// ---- Entry points ------------------------------------------------------------

/// Every RELPTR32 the NativeAOT runtime dereferences in `data`, sorted
/// by location.
pub fn nativeaot_refs(data: &[u8]) -> Result<Vec<RelPtr>, ModelError> {
    refs_of(&Image::parse(data)?).map(|m| m.refs)
}

/// The model of an image: its references, the sealed vtables whose
/// extent no second bound confirms, and the structures read in full.
#[derive(Debug, Default)]
struct Model {
    /// Every RELPTR32, sorted by location (`nativeaot_refs`).
    refs: Vec<RelPtr>,
    /// Sealed vtables `[start, end)` whose type's dispatch map uses
    /// fewer slots than the vtable runs to (`sealed_slots`): their tail
    /// is bounded by the next known object alone.
    unconfirmed: Vec<(u64, u64)>,
    /// File extents `[start, end)` of the structures whose layout the
    /// model knows: ReadyToRun headers and sections, dispatch maps,
    /// LSDAs, associated data and EH info. Every self-relative pointer
    /// in them is one of `refs`; their other bytes hold no address.
    parsed: Vec<(u64, u64)>,
}

/// `nativeaot_refs` on a parsed image, with the sealed vtables whose
/// extent is not confirmed and the structures read.
fn refs_of(img: &Image) -> Result<Model, ModelError> {
    let cap = img.data.len() / 4;
    let mut m = Model::default();
    for (h, rows) in read_headers(img)? {
        module_refs(img, h, &rows, &mut m)?;
        within_cap(&m.refs, cap)?;
    }
    unwind_refs(img, &mut m.refs, &mut m.parsed)?;
    within_cap(&m.refs, cap)?;
    m.refs = dedup(std::mem::take(&mut m.refs));
    Ok(m)
}

/// What trim learns of a NativeAOT image, once per run: the model of its
/// ReadyToRun references (or why there is none), the code the model
/// reaches, the code with managed unwind info, and the starts of
/// functions (`.eh_frame` FDEs, then the function map too).
pub struct NativeAot {
    /// The model, or why it could not be built.
    model: Result<Model, ModelError>,
    /// Targets of the model's references that lie in executable
    /// sections (`nativeaot_code_refs`).
    code_targets: Vec<u64>,
    /// Starts of the code with managed unwind info
    /// (`managed_unwind_starts`).
    managed_starts: Vec<u64>,
    /// Function starts: FDE starts, and those of `add_funcs`. Sorted,
    /// unique.
    func_starts: Vec<u64>,
}

impl NativeAot {
    /// Analyse the image `data`.
    pub fn new(data: &[u8]) -> Self {
        match Image::parse(data) {
            Ok(img) => Self::of(&img),
            Err(e) => NativeAot {
                model: Err(e),
                code_targets: Vec::new(),
                managed_starts: Vec::new(),
                func_starts: Vec::new(),
            },
        }
    }

    /// Analyse the parsed image `img`.
    fn of(img: &Image) -> Self {
        let model = refs_of(img);
        let code_targets = model.as_ref().map_or_else(|_| Vec::new(), |m| code_targets(img, m));
        let fdes = ehframe::fde_ranges(img.data, &img.sections);
        let mut func_starts: Vec<u64> = fdes.into_iter().map(|(b, _)| b).collect();
        func_starts.sort_unstable();
        func_starts.dedup();
        let managed_starts = managed_unwind_starts(img);
        NativeAot { model, code_targets, managed_starts, func_starts }
    }

    /// True if the ReadyToRun references are modelled exactly.
    pub fn is_exact(&self) -> bool {
        self.model.is_ok()
    }

    /// Count the functions of `funcs` among the function starts.
    pub fn add_funcs(&mut self, funcs: &FuncMap) {
        self.func_starts.extend(funcs.values().map(|f| f.addr));
        self.func_starts.sort_unstable();
        self.func_starts.dedup();
    }

    /// Liveness roots: the functions holding a code target of the model
    /// or code with managed unwind info. If `__modules` names no
    /// ReadyToRun header there is nothing to add (noted when it holds
    /// pointers to something else). If the model is not exact, every
    /// function is returned: what the runtime can reach is then unknown,
    /// so nothing may be called dead (fail closed).
    pub fn root_names(&self, funcs: &FuncMap) -> Vec<String> {
        match &self.model {
            Ok(_) => {
                let mut code = self.code_targets.clone();
                code.extend(&self.managed_starts);
                let names = containing_funcs(funcs, &code);
                eprintln!(
                    "  note: NativeAOT: {} ReadyToRun references into code \
                     ({} functions kept live)",
                    self.code_targets.len(),
                    names.len()
                );
                names
            }
            Err(ModelError::NoHeader(slots)) => {
                if *slots > 0 {
                    eprintln!(
                        "  note: NativeAOT: __modules holds {} non-null slots \
                         but none names a ReadyToRun header; no ReadyToRun \
                         references modelled",
                        slots
                    );
                }
                Vec::new()
            }
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
}

/// Targets of the references of `m` that lie in executable sections.
/// Sorted, unique.
fn code_targets(img: &Image, m: &Model) -> Vec<u64> {
    let set: BTreeSet<u64> = m.refs.iter().map(|r| r.target).filter(|&t| img.is_exec(t)).collect();
    set.into_iter().collect()
}

/// Refuse more references than the file has 4-byte fields (`cap`): each
/// is a distinct 32-bit field of the file, so more means structures
/// were read more than once.
fn within_cap(out: &[RelPtr], cap: usize) -> Result<(), ModelError> {
    if out.len() > cap {
        return Err(ModelError::Malformed(format!(
            "{} references for a file of {} 4-byte fields",
            out.len(),
            cap
        )));
    }
    Ok(())
}

/// Targets of `nativeaot_refs` that lie in executable sections: code
/// the runtime can reach through ReadyToRun data. Sorted, unique.
pub fn nativeaot_code_refs(data: &[u8]) -> Result<Vec<u64>, ModelError> {
    let img = Image::parse(data)?;
    Ok(code_targets(&img, &refs_of(&img)?))
}

/// `NativeAot::root_names` for `data`, analysed afresh.
pub fn root_names(data: &[u8], funcs: &FuncMap) -> Vec<String> {
    NativeAot::new(data).root_names(funcs)
}

// ---- Compaction ----------------------------------------------------------------

/// Largest section alignment the page-aligned drain keeps: the sections
/// after .text move by a multiple of this.
const DRAIN_PAGE: u64 = 4096;

/// What compacting the .text of a NativeAOT image must keep valid.
#[derive(Debug, Clone, Default)]
pub struct R2rPlan {
    /// Every RELPTR32 of `nativeaot_refs`, with its file offset.
    pub relptrs: Vec<RelField>,
    /// Every absolute pointer: the RELATIVE relocation slots holding
    /// their addend in place, the GOT word holding the link-time address
    /// of `.dynamic`, and lazy-binding JUMP_SLOT values into code.
    /// Nothing else in the data is an address.
    pub slots: Vec<PtrSlot>,
    /// Every address an absolute pointer designates: the RELATIVE
    /// addends (file-backed slot or not) and the targets of `slots`.
    /// None may lie in removed code.
    pub absolute: Vec<u64>,
    /// Stray words `(location, target)`: data words that, read as a
    /// RELPTR32, designate the start of a .text function, and that no
    /// listed field or known structure accounts for (`stray_words`). A
    /// linker writes such a word for a self-relative reference the model
    /// does not know; it would go stale if its ends moved apart.
    pub stray: Vec<(u64, u64)>,
}

impl R2rPlan {
    /// Why the patch sites of the plan and the jump table `entries` do
    /// not all stand apart: two of them overlap, so patching one would
    /// corrupt the other. None if no two overlap.
    pub fn site_overlap(&self, entries: &[TableEntry]) -> Option<String> {
        let mut sites: Vec<(u64, u64, &str)> = Vec::new();
        sites.extend(self.relptrs.iter().map(|f| (f.location, 4, "RELPTR32")));
        sites.extend(self.slots.iter().map(|s| (s.location, 8, "pointer slot")));
        sites.extend(entries.iter().map(|e| (e.location, 4, "jump table entry")));
        sites.sort_unstable();
        sites.windows(2).find(|w| w[1].0 < w[0].0.saturating_add(w[0].1)).map(|w| {
            format!("{} at {:#x} overlaps {} at {:#x}", w[0].2, w[0].0, w[1].2, w[1].0)
        })
    }

    /// Why a stray word (`R2rPlan::stray`) keeps .text `[ts, te)` from
    /// being compacted by `intervals`: its location and target move
    /// apart, or its target is removed. Words that overlap a jump table
    /// entry of `entries` are accounted for by the table.
    pub fn stray_conflict(
        &self,
        entries: &[TableEntry],
        intervals: &[(u64, u64)],
        ts: u64,
        te: u64,
    ) -> Option<String> {
        let tables = merged(entries.iter().map(|e| (e.location, e.location + 4)));
        let stale: Vec<&(u64, u64)> = self
            .stray
            .iter()
            .filter(|&&(loc, _)| !overlaps(&tables, loc, loc + 4))
            .filter(|&&(loc, t)| {
                in_dead_range(t, intervals)
                    || total_shift(loc, intervals, ts, te) != total_shift(t, intervals, ts, te)
            })
            .collect();
        let &&(loc, t) = stale.first()?;
        Some(format!(
            "{} data words read as self-relative pointers to moved functions \
             and are not known references (first at {:#x} designates {:#x})",
            stale.len(),
            loc,
            t
        ))
    }
}

/// `NativeAot::compaction_plan` for `data`, analysed afresh.
pub fn compaction_plan(data: &[u8], decoded: &[&str]) -> Result<R2rPlan, String> {
    NativeAot::new(data).compaction_plan(data, decoded)
}

impl NativeAot {
    /// The references compacting .text must keep valid, or why this
    /// image cannot be compacted (it is then zero-filled in place).
    /// `data` is the image analysed. Compaction is refused unless the
    /// image is one whose absolute pointers are all known
    /// (`image_conflict`), no dynamic relocation writes into .text, the
    /// model is exact (no `ModelError`: verified version, every section
    /// modelled, no stack trace data), the ReadyToRun sections and every
    /// listed field lie outside .text, no sealed vtable whose extent is
    /// unconfirmed points into .text (`sealed_conflict`), and the layout
    /// lets the data the model does not list (data to data RELPTR32s)
    /// move as one block (`layout_conflict`). `decoded` names the code
    /// sections besides .text whose branches the compaction patches.
    pub fn compaction_plan(&self, data: &[u8], decoded: &[&str]) -> Result<R2rPlan, String> {
        let img = Image::parse(data).map_err(|e| model_reason(&e))?;
        let elf = goblin::elf::Elf::parse(data).map_err(|_| "ELF does not parse".to_string())?;
        let text = img.named(".text").ok_or("no .text")?;
        let (ts, te) = (text.start, text.end);
        let conflict = image_conflict(&elf)
            .or_else(|| reloc_in_text(&elf, ts, te))
            .or_else(|| layout_conflict(&elf, ts, te, decoded));
        if let Some(why) = conflict {
            return Err(why);
        }
        let model = self.model.as_ref().map_err(model_reason)?;
        if let Some(why) = r2r_in_text(&img, ts, te).or_else(|| sealed_conflict(model, ts, te)) {
            return Err(why);
        }
        let relptrs = model.refs.iter().map(|r| rel_field(&img, r)).collect::<Result<_, _>>()?;
        let (slots, absolute) = absolute_pointers(&img, &elf);
        let stray = stray_words(&img, model, &slots, &self.func_starts, ts, te);
        Ok(R2rPlan { relptrs, slots, absolute, stray })
    }
}

/// Sections whose words `stray_words` does not read: the unwind tables,
/// which `ehframe` patches, and dynamic-linking metadata
/// (`metadata_section`, `.dynamic`), whose records hold no self-relative
/// field.
fn unscanned(name: &str, sh_type: u32) -> bool {
    matches!(name, ".eh_frame" | ".eh_frame_hdr" | ".dynamic") || metadata_section(sh_type, name)
}

/// The stray words of `img` (`R2rPlan::stray`): at every byte of each
/// file-backed, non-executable section not `unscanned`, a 4-byte word
/// whose RELPTR32 target is one of `starts` inside .text `[ts, te)`, and
/// that overlaps no field of `model`, no pointer slot of `slots` and no
/// structure the model read in full (`Model::parsed`).
fn stray_words(
    img: &Image,
    model: &Model,
    slots: &[PtrSlot],
    starts: &[u64],
    ts: u64,
    te: u64,
) -> Vec<(u64, u64)> {
    let starts: HashSet<u64> = starts.iter().copied().filter(|&a| ts <= a && a < te).collect();
    let known = merged(
        model
            .refs
            .iter()
            .map(|r| (r.location, r.location + 4))
            .chain(slots.iter().map(|s| (s.location, s.location + 8)))
            .chain(model.parsed.iter().copied()),
    );
    let mut out = Vec::new();
    for r in img.regions.iter().filter(|r| r.file && !r.exec && !unscanned(&r.name, r.sh_type)) {
        let Some(bytes) = img.bytes(r.start, r.end - r.start) else { continue };
        for (i, w) in bytes.windows(4).enumerate() {
            let loc = r.start + i as u64;
            let t = loc.wrapping_add(i32::from_le_bytes([w[0], w[1], w[2], w[3]]) as i64 as u64);
            if ts <= t && t < te && starts.contains(&t) && !overlaps(&known, loc, loc + 4) {
                out.push((loc, t));
            }
        }
    }
    out
}

/// `spans` sorted by start, overlapping and touching ones merged.
fn merged(spans: impl Iterator<Item = (u64, u64)>) -> Vec<(u64, u64)> {
    let mut v: Vec<(u64, u64)> = spans.filter(|s| s.0 < s.1).collect();
    v.sort_unstable();
    let mut out: Vec<(u64, u64)> = Vec::with_capacity(v.len());
    for (s, e) in v {
        match out.last_mut() {
            Some(last) if s <= last.1 => last.1 = last.1.max(e),
            _ => out.push((s, e)),
        }
    }
    out
}

/// True if `[start, end)` overlaps one of `spans` (`merged`).
fn overlaps(spans: &[(u64, u64)], start: u64, end: u64) -> bool {
    let i = spans.partition_point(|s| s.1 <= start);
    spans.get(i).is_some_and(|s| s.0 < end)
}

/// True if `a` lies in one of `spans` (`merged`).
fn in_spans(spans: &[(u64, u64)], a: u64) -> bool {
    overlaps(spans, a, a + 1)
}

/// Why a dynamic relocation keeps .text `[ts, te)` from moving: one
/// writes into it, so its offset would follow the code it patches.
fn reloc_in_text(elf: &goblin::elf::Elf, ts: u64, te: u64) -> Option<String> {
    elf.dynrelas
        .iter()
        .chain(elf.pltrelocs.iter())
        .chain(elf.dynrels.iter())
        .find(|r| ts <= r.r_offset && r.r_offset < te)
        .map(|r| format!("dynamic relocation at {:#x} lies in .text", r.r_offset))
}

/// Why the ReadyToRun data keeps .text `[ts, te)` from moving: one of
/// its sections lies in it (a row without an end pointer counts as one
/// byte).
fn r2r_in_text(img: &Image, ts: u64, te: u64) -> Option<String> {
    let headers = read_headers(img).ok()?;
    let mut rows = headers.iter().flat_map(|(_, rows)| rows.iter());
    rows.find(|s| s.start < te && ts < s.end.max(s.start + 1))
        .map(|s| format!("ReadyToRun section {} lies in .text", s.id))
}

/// The absolute pointer slots of `R2rPlan::slots`, sorted by location,
/// and every address an absolute pointer designates
/// (`R2rPlan::absolute`), sorted and unique.
fn absolute_pointers(img: &Image, elf: &goblin::elf::Elf) -> (Vec<PtrSlot>, Vec<u64>) {
    let mut slots = ptr_slots(img);
    slots.extend(jump_slots(img, elf));
    slots.sort_by_key(|s| s.location);
    let mut absolute: Vec<u64> = img.relative.values().copied().collect();
    absolute.extend(slots.iter().map(|s| s.target));
    absolute.sort_unstable();
    absolute.dedup();
    (slots, absolute)
}

/// Why a sealed vtable keeps .text from being compacted: one of its
/// slots points into .text `[ts, te)`, so it must be re-pointed, but
/// only the next known object bounds the vtable (`Model::unconfirmed`):
/// a tail word may not be a slot, and re-pointing it would corrupt the
/// object it belongs to.
fn sealed_conflict(model: &Model, ts: u64, te: u64) -> Option<String> {
    let inside = |a: u64| model.unconfirmed.iter().find(|&&(s, e)| s <= a && a < e);
    model
        .refs
        .iter()
        .filter(|r| r.kind == RefKind::SealedVTableSlot && ts <= r.target && r.target < te)
        .find_map(|r| inside(r.location))
        .map(|&(s, e)| {
            format!(
                "sealed vtable at {:#x} points into .text, but its {} slots exceed \
                 what its dispatch map uses",
                s,
                (e - s) / 4
            )
        })
}

/// True if a dynamic tag names relocations other than RELA ones: REL,
/// RELR (packed RELATIVE) or Android's packed formats, whose slots the
/// plan does not read. Checked besides the section types, which a
/// stripped or crafted image need not keep.
fn foreign_reloc_tags(elf: &goblin::elf::Elf) -> bool {
    elf.dynamic.as_ref().is_some_and(|d| d.dyns.iter().any(|x| foreign_reloc_tag(x.d_tag)))
}

/// True for a dynamic tag of REL, RELR or Android packed relocations.
fn foreign_reloc_tag(tag: u64) -> bool {
    use goblin::elf::dynamic::{DT_REL, DT_RELENT, DT_RELSZ};
    /// DT_RELRSZ, DT_RELR, DT_RELRENT.
    const RELR: [u64; 3] = [35, 36, 37];
    /// DT_ANDROID_REL, _RELSZ, _RELA, _RELASZ.
    const ANDROID: [u64; 4] = [0x6000_000f, 0x6000_0010, 0x6000_0011, 0x6000_0012];
    matches!(tag, DT_REL | DT_RELSZ | DT_RELENT) || RELR.contains(&tag) || ANDROID.contains(&tag)
}

/// Why the image's absolute pointers are not all known from relocations,
/// or not all patched: compaction needs an x86-64 (the only architecture
/// verified) position-independent image without text relocations whose
/// dynamic relocations are RELA (by section type and dynamic tag), none
/// of them IRELATIVE (resolver address in the addend) or symbol-less
/// absolute.
fn image_conflict(elf: &goblin::elf::Elf) -> Option<String> {
    use goblin::elf::dynamic::DF_TEXTREL;
    use goblin::elf::header::{EM_X86_64, ET_DYN};
    use goblin::elf::reloc::{R_X86_64_64, R_X86_64_IRELATIVE};
    use goblin::elf::section_header::SHT_REL;
    /// SHT_RELR (packed RELATIVE relocations).
    const SHT_RELR: u32 = 19;
    if elf.header.e_machine != EM_X86_64 {
        return Some("only x86-64 is verified".to_string());
    }
    if elf.header.e_type != ET_DYN {
        return Some("not position-independent".to_string());
    }
    let textrel = elf.dynamic.as_ref().is_some_and(|d| {
        d.info.textrel || d.info.flags as u64 & DF_TEXTREL != 0
    });
    if textrel {
        return Some("text relocations".to_string());
    }
    let rel_sections =
        elf.section_headers.iter().any(|sh| sh.sh_type == SHT_REL || sh.sh_type == SHT_RELR);
    if rel_sections || foreign_reloc_tags(elf) {
        return Some("REL or RELR relocations".to_string());
    }
    let relocs = elf.dynrelas.iter().chain(elf.pltrelocs.iter());
    let unknown = relocs
        .filter(|r| r.r_type == R_X86_64_IRELATIVE || (r.r_type == R_X86_64_64 && r.r_sym == 0))
        .count();
    (unknown > 0).then(|| format!("{} IRELATIVE or symbol-less absolute relocations", unknown))
}

/// The absolute pointer slots of `R2rPlan::slots`. A RELATIVE slot whose
/// in-place value is not its addend (or that is not file-backed) is left
/// out: the loader writes it from the addend alone.
fn ptr_slots(img: &Image) -> Vec<PtrSlot> {
    let mut slots: Vec<PtrSlot> = img
        .relative
        .iter()
        .filter_map(|(&location, &target)| {
            let offset = img.offset(location, 8)?;
            let held = img.bytes(location, 8)?;
            let held = u64::from_le_bytes(held.try_into().ok()?);
            (held == target).then_some(PtrSlot { location, offset, target })
        })
        .collect();
    slots.extend(dynamic_slot(img));
    slots.sort_by_key(|s| s.location);
    slots
}

/// The in-place values of JUMP_SLOT relocations that point into code
/// (a `.plt` stub): a lazy-binding loader jumps through them before the
/// first call binds the slot, so they must follow code that moves.
fn jump_slots(img: &Image, elf: &goblin::elf::Elf) -> Vec<PtrSlot> {
    use goblin::elf::reloc::R_X86_64_JUMP_SLOT;
    elf.pltrelocs
        .iter()
        .filter(|r| r.r_type == R_X86_64_JUMP_SLOT)
        .filter_map(|r| {
            let location = r.r_offset;
            let held = u64::from_le_bytes(img.bytes(location, 8)?.try_into().ok()?);
            (held != 0 && img.is_exec(held)).then_some(PtrSlot {
                location,
                offset: img.offset(location, 8)?,
                target: held,
            })
        })
        .collect()
}

/// The word of `.got` or `.got.plt` holding the link-time address of
/// `.dynamic` (`_GLOBAL_OFFSET_TABLE_[0]`), if one does and is not a
/// relocation slot.
fn dynamic_slot(img: &Image) -> Option<PtrSlot> {
    let dynamic = img.named(".dynamic")?.start;
    [".got.plt", ".got"].iter().find_map(|name| {
        let location = img.named(name)?.start;
        let held = img.ptr(location)?;
        let fixed = !img.relative.contains_key(&location);
        (fixed && held == dynamic).then_some(PtrSlot {
            location,
            offset: img.offset(location, 8)?,
            target: dynamic,
        })
    })
}

/// A model reference as a patchable field (its file offset added).
fn rel_field(img: &Image, r: &RelPtr) -> Result<RelField, String> {
    let offset = img
        .offset(r.location, 4)
        .ok_or_else(|| format!("RELPTR32 at {:#x} is not file-backed", r.location))?;
    Ok(RelField { location: r.location, offset, target: r.target })
}

/// Why the model could not be built, as a note.
fn model_reason(e: &ModelError) -> String {
    match e {
        ModelError::NoHeader(_) => "no ReadyToRun header".to_string(),
        ModelError::Malformed(why) => format!("ReadyToRun data not modelled ({})", why),
    }
}

/// Why the section layout keeps .text from being compacted. Compaction
/// moves .text code by the per-interval shift and every section after
/// .text by the same page-aligned drain. The model lists the RELPTR32s
/// into code, but not those from data to data, which stay valid only
/// while both ends move together. So every allocated section before
/// .text must hold dynamic-linking metadata only (`metadata_section`) or
/// be decoded code; nothing may overlap .text; every other executable
/// section must be decoded (its branches into .text are patched); and no
/// section after .text may need more than page alignment.
fn layout_conflict(
    elf: &goblin::elf::Elf,
    ts: u64,
    te: u64,
    decoded: &[&str],
) -> Option<String> {
    use goblin::elf::section_header::{SHF_ALLOC, SHF_EXECINSTR};
    for sh in &elf.section_headers {
        let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("?");
        if sh.sh_flags & SHF_ALLOC as u64 == 0 || sh.sh_size == 0 || name == ".text" {
            continue;
        }
        let end = sh.sh_addr.saturating_add(sh.sh_size);
        let exec = sh.sh_flags & SHF_EXECINSTR as u64 != 0;
        if sh.sh_addr < te && ts < end {
            return Some(format!("section {} overlaps .text", name));
        }
        if exec && !decoded.contains(&name) {
            return Some(format!("executable section {} is not decoded", name));
        }
        if sh.sh_addr < ts && !exec && !metadata_section(sh.sh_type, name) {
            return Some(format!("section {} lies before .text", name));
        }
        if sh.sh_addr >= te && sh.sh_addralign > DRAIN_PAGE {
            return Some(format!("section {} needs {}-byte alignment", name, sh.sh_addralign));
        }
    }
    None
}

/// True for a section holding dynamic-linking metadata only (notes,
/// symbol and hash tables, version tables, relocations, the interpreter
/// path): no RELPTR32 lives in it or designates it, and its absolute
/// addresses are patched by the ELF metadata patchers.
fn metadata_section(sh_type: u32, name: &str) -> bool {
    use goblin::elf::section_header::{
        SHT_DYNSYM, SHT_GNU_HASH, SHT_GNU_VERDEF, SHT_GNU_VERNEED, SHT_GNU_VERSYM,
        SHT_HASH, SHT_NOTE, SHT_REL, SHT_RELA, SHT_STRTAB,
    };
    /// SHT_RELR (packed RELATIVE relocations).
    const SHT_RELR: u32 = 19;
    matches!(
        sh_type,
        SHT_NOTE | SHT_HASH | SHT_GNU_HASH | SHT_DYNSYM | SHT_STRTAB | SHT_GNU_VERSYM
            | SHT_GNU_VERDEF | SHT_GNU_VERNEED | SHT_RELA | SHT_REL | SHT_RELR
    ) || name == ".interp"
}

/// Names of the functions whose range holds one of `targets`, nested
/// and overlapping ranges included (`symbols::funcs_containing`).
fn containing_funcs(funcs: &FuncMap, targets: &[u64]) -> Vec<String> {
    super::symbols::funcs_containing(funcs, targets).into_iter().collect()
}

/// Sort by location and drop repeats of a location.
fn dedup(refs: Vec<RelPtr>) -> Vec<RelPtr> {
    let mut by_loc: BTreeMap<u64, RelPtr> = BTreeMap::new();
    for r in refs {
        by_loc.entry(r.location).or_insert(r);
    }
    by_loc.into_values().collect()
}

/// The references of the module whose header is at `h`, into `m`:
/// sealed vtables whose extent is not confirmed go to `m.unconfirmed`,
/// the header, its sections and the dispatch maps read to `m.parsed`.
fn module_refs(img: &Image, h: u64, rows: &[R2rSection], m: &mut Model) -> Result<(), ModelError> {
    m.parsed.push((h, header_end(img, h)));
    for s in rows {
        section_refs(img, s, &mut m.refs)?;
        m.parsed.push((s.start, s.end));
    }
    let dehydrated = rows.iter().find(|s| s.id == SEC_DEHYDRATED_DATA);
    if let Some(s) = dehydrated {
        let hyd = dehydrate(img, s, &mut m.refs)?;
        let tmi = rows
            .iter()
            .find(|r| r.id == SEC_TYPE_MANAGER_INDIRECTION)
            .ok_or(malformed("no type manager indirection"))?;
        let sealed = sealed_vtables(img, &hyd, tmi.start, &mut m.parsed)?;
        let bounds = object_starts(img, &sealed, h, rows, &hyd, &m.refs);
        sealed_slots(img, &sealed, &bounds, &mut m.refs, &mut m.unconfirmed)?;
    }
    Ok(())
}

/// End of the ReadyToRun header at `h` and its section table (its rows
/// were read, so the fields are file-backed).
fn header_end(img: &Image, h: u64) -> u64 {
    let hdr = img.bytes(h, R2R_HEADER_SIZE).unwrap_or(&[0; 16]);
    let count = u16::from_le_bytes([hdr[12], hdr[13]]) as u64;
    h + R2R_HEADER_SIZE + count * hdr[14] as u64
}

/// The references a ReadyToRun section holds directly, by section id.
/// Ids known to hold none are skipped; unknown ids are refused, and so
/// are rows of the sections read by length (`sized_section`) that have
/// no end pointer: their extent would be unknown.
fn section_refs(
    img: &Image,
    s: &R2rSection,
    out: &mut Vec<RelPtr>,
) -> Result<(), ModelError> {
    if sized_section(s.id) && !s.has_end {
        return Err(ModelError::Malformed(format!(
            "ReadyToRun section {} has no end pointer",
            s.id
        )));
    }
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

/// True for the sections the model reads from start to end: the RELPTR32
/// arrays, the dehydrated data and the stack trace method mapping.
fn sized_section(id: u32) -> bool {
    matches!(
        id,
        SEC_GC_STATIC_REGION
            | SEC_EAGER_CCTOR
            | SEC_MODULE_INITIALIZERS
            | SEC_DEHYDRATED_DATA
            | SEC_STACK_TRACE_MAPPING
    ) || SEC_EXTERNAL_REFERENCES.contains(&id)
}

/// The stack trace method mapping: accepted only when empty (a zero
/// entry count), as compiled without stack trace data. A non-empty one
/// (.NET's default, `StackTraceSupport` true) holds RELPTR32s to
/// methods in a layout not modelled: the model is refused and every
/// function kept live.
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
/// it describes. The rebuilt bytes may fill the destination section
/// up to its end, but no more than `HYDRATED_PER_FILE_BYTE` times the
/// file size.
fn dehydrate(
    img: &Image,
    s: &R2rSection,
    out: &mut Vec<RelPtr>,
) -> Result<Hydrated, ModelError> {
    let bad = |w: &str| ModelError::Malformed(format!("dehydrated data: {}", w));
    let owner = Owner::R2r(s.id);
    let dest = img.relptr(s.start).ok_or_else(|| bad("destination"))?;
    let cap = (img.data.len() as u64).saturating_mul(HYDRATED_PER_FILE_BYTE);
    let room = img
        .region(dest)
        .filter(|r| !r.exec)
        .map(|r| (r.end - dest).min(cap))
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
            return Err(bad("output overruns its section or the size cap"));
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

/// A rebuilt MethodTable that names a sealed vtable.
#[derive(Debug, Clone, Copy)]
struct SealedRef {
    /// Address of the sealed vtable.
    start: u64,
    /// The type's dispatch map, if it has one.
    map: Option<u64>,
    /// The type's vtable slot count.
    vtable_slots: u64,
}

/// Sealed vtable addresses named by the rebuilt MethodTables
/// (`sealed_refs`), each with the number of its slots the dispatch maps
/// of the types naming it use (`DispatchMap::used`). Each distinct
/// dispatch map is read once (`dispatch_maps`); their extents go to
/// `parsed`.
fn sealed_vtables(
    img: &Image,
    hyd: &Hydrated,
    tmi: u64,
    parsed: &mut Vec<(u64, u64)>,
) -> Result<BTreeMap<u64, u64>, ModelError> {
    let named = sealed_refs(hyd, tmi)?;
    let maps = dispatch_maps(img, named.iter().filter_map(|n| n.map))?;
    parsed.extend(maps.values().map(|d| (d.start, d.end)));
    let mut sealed = BTreeMap::new();
    for n in &named {
        let used = n.map.and_then(|m| maps.get(&m)).map_or(0, |d| d.used(n.vtable_slots));
        let e = sealed.entry(n.start).or_insert(0);
        *e = used.max(*e);
    }
    Ok(sealed)
}

/// The rebuilt MethodTables that name a sealed vtable. Each MethodTable
/// holds a RELPTR32 to the type manager indirection `tmi` right after
/// its vtable and interface list; its flags then say which optional
/// RELPTR32 fields follow: writable data (always), dispatch map,
/// finalizer, sealed vtable. MethodTables do not overlap, so each starts
/// above the type manager field of the one before it; that floor keeps
/// the search linear in the rebuilt size.
fn sealed_refs(hyd: &Hydrated, tmi: u64) -> Result<Vec<SealedRef>, ModelError> {
    let mut out = Vec::new();
    let anchors = hyd.writes.iter().filter(|w| w.1 == 4 && w.2 == tmi);
    let mut floor = hyd.base;
    for &(field, _, _) in anchors {
        let m = method_table_start(hyd, field, floor).ok_or(malformed("MethodTable"))?;
        floor = field + 4;
        let flags = hyd.uint(m, 4).ok_or(malformed("MethodTable"))? as u32;
        if flags & MT_HAS_SEALED_VTABLE == 0 {
            continue;
        }
        let vtable_slots = hyd.uint(m + 16, 2).ok_or(malformed("MethodTable"))?;
        let mut at = field + 8;
        let mut map = None;
        if flags & MT_HAS_DISPATCH_MAP != 0 {
            let w = hyd.write_at(at).filter(|w| w.1 == 4);
            map = Some(w.ok_or(malformed("dispatch map field"))?.2);
            at += 4;
        }
        if flags & MT_HAS_FINALIZER != 0 {
            at += 4;
        }
        let w = hyd.write_at(at).filter(|w| w.1 == 4);
        let start = w.ok_or(malformed("sealed vtable field"))?.2;
        out.push(SealedRef { start, map, vtable_slots });
    }
    Ok(out)
}

/// A dispatch map: its extent and the highest implementation slot of its
/// entries that is not special.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DispatchMap {
    /// Address of its header.
    start: u64,
    /// End of its last entry (exclusive).
    end: u64,
    /// Highest implementation slot below `DISPATCH_SPECIAL_SLOT`, if any
    /// entry has one.
    highest: Option<u64>,
}

impl DispatchMap {
    /// Sealed vtable slots the map uses for a type with `vtable_slots`
    /// vtable slots: one more than its highest implementation slot that
    /// is not a vtable slot (below `vtable_slots`) or special; 0 if none
    /// is. The runtime reads a type's sealed vtable at `slot -
    /// vtable_slots` for such entries of its own dispatch map.
    fn used(&self, vtable_slots: u64) -> u64 {
        self.highest.filter(|&h| h >= vtable_slots).map_or(0, |h| h - vtable_slots + 1)
    }
}

/// Read each distinct dispatch map of `maps` once, however many types
/// name it. Their extents (from the header counts) must not overlap,
/// which bounds the bytes read by the file size; overlapping maps are
/// refused before the second is read.
fn dispatch_maps(
    img: &Image,
    maps: impl Iterator<Item = u64>,
) -> Result<HashMap<u64, DispatchMap>, ModelError> {
    let distinct: BTreeSet<u64> = maps.collect();
    let mut out = HashMap::with_capacity(distinct.len());
    let mut prev_end = 0;
    for m in distinct {
        if m < prev_end {
            return Err(malformed("dispatch maps overlap"));
        }
        let d = read_dispatch_map(img, m)?;
        prev_end = d.end;
        out.insert(m, d);
    }
    Ok(out)
}

/// The dispatch map at `map`: a header of four 16-bit entry counts
/// (standard, default, standard static, default static), then 6-byte
/// instance and 8-byte static entries whose implementation slot is the
/// 16-bit word at offset 4. Refused unless it lies whole in one
/// file-backed section.
fn read_dispatch_map(img: &Image, map: u64) -> Result<DispatchMap, ModelError> {
    let bad = || malformed("dispatch map");
    let head = img.bytes(map, DISPATCH_HEADER).ok_or_else(bad)?;
    let count = |i: usize| u16::from_le_bytes([head[2 * i], head[2 * i + 1]]) as u64;
    let instance = count(0) + count(1);
    let statics = count(2) + count(3);
    let entries = map + DISPATCH_HEADER;
    let static_entries = entries + DISPATCH_ENTRY * instance;
    let end = static_entries + DISPATCH_STATIC_ENTRY * statics;
    img.bytes(map, end - map).ok_or_else(bad)?;
    let rows = (0..instance)
        .map(|i| entries + DISPATCH_ENTRY * i)
        .chain((0..statics).map(|i| static_entries + DISPATCH_STATIC_ENTRY * i));
    let mut highest = None;
    for row in rows {
        let b = img.bytes(row + 4, 2).ok_or_else(bad)?;
        let slot = u16::from_le_bytes([b[0], b[1]]) as u64;
        if slot < DISPATCH_SPECIAL_SLOT {
            highest = highest.max(Some(slot));
        }
    }
    Ok(DispatchMap { start: map, end, highest })
}

/// Start of the MethodTable whose type manager field is at `field`: an
/// `m` below it whose slot counts place the field there, with a plain
/// (non-pointer) non-zero first word (flags, base size), a plain count
/// word, and only pointers or null from the related type to the field.
/// Between `m` and the field the only plain non-zero words are the two
/// header words, so the only other `m` that can pass is 16 bytes above
/// the real one (two slots, the second null); the lower one wins. No
/// `m` below `floor` is considered. Candidates are tried from the field
/// down; once a word below the field is neither a pointer nor null no
/// lower candidate can pass (it would be one of its slots).
fn method_table_start(hyd: &Hydrated, field: u64, floor: u64) -> Option<u64> {
    for n in 0..=MT_MAX_SLOTS {
        let m = field.checked_sub(MT_FIXED + 8 * n)?;
        if m < floor {
            return None;
        }
        // The n words below the field are pointers or null (see below).
        if mt_header(hyd, m, n) {
            let below = m.checked_sub(16).filter(|&b| b >= floor);
            let lower = below.filter(|&b| is_method_table(hyd, b, n + 2));
            return Some(lower.unwrap_or(m));
        }
        if !hyd.ptr_or_null(field - 8 * (n + 1)) {
            return None;
        }
    }
    None
}

/// True if a MethodTable with `n` vtable plus interface slots starts at
/// `m` (see `method_table_start`).
fn is_method_table(hyd: &Hydrated, m: u64, n: u64) -> bool {
    mt_header(hyd, m, n) && (0..n).all(|j| hyd.ptr_or_null(m + MT_FIXED + 8 * j))
}

/// `is_method_table` but for the slots: the slot counts say `n`, the
/// first word is plain and non-zero, the count word plain and the
/// related type a pointer or null.
fn mt_header(hyd: &Hydrated, m: u64, n: u64) -> bool {
    let slots = hyd.uint(m + 16, 2).zip(hyd.uint(m + 18, 2));
    if slots.map(|(v, i)| v + i) != Some(n) {
        return false;
    }
    hyd.uint(m, 8).map_or(false, |f| f != 0)
        && hyd.plain(m, 8)
        && hyd.plain(m + 16, 8)
        && hyd.ptr_or_null(m + 8)
}

/// Addresses, inside the sections holding the sealed vtables `sealed`,
/// where some known object starts: the header, section bounds, targets
/// of the rebuilt pointers and of the references found so far. The
/// sections are merged and sorted, so each candidate is placed by a
/// binary search.
fn object_starts(
    img: &Image,
    sealed: &BTreeMap<u64, u64>,
    h: u64,
    rows: &[R2rSection],
    hyd: &Hydrated,
    out: &[RelPtr],
) -> BTreeSet<u64> {
    let spans = merged(sealed.keys().filter_map(|&s| img.region(s).map(|r| (r.start, r.end))));
    let inside = |a: &u64| in_spans(&spans, *a);
    let rows = rows.iter().flat_map(|r| [r.start, r.end]);
    let writes = hyd.writes.iter().map(|w| w.2);
    let refs = out.iter().map(|r| r.target);
    std::iter::once(h).chain(rows).chain(writes).chain(refs).filter(inside).collect()
}

/// List the slots of each sealed vtable of `sealed` (start -> slots its
/// dispatch maps use). A sealed vtable stores no slot count: it runs to
/// the next known object start (`bounds`) or the end of its section.
/// Every slot must point into code, or the bound is not exact and the
/// model is refused; so it is when the dispatch maps use more slots than
/// that extent holds. When they use fewer, nothing confirms the tail of
/// the extent: the vtable goes to `unconfirmed`.
fn sealed_slots(
    img: &Image,
    sealed: &BTreeMap<u64, u64>,
    bounds: &BTreeSet<u64>,
    out: &mut Vec<RelPtr>,
    unconfirmed: &mut Vec<(u64, u64)>,
) -> Result<(), ModelError> {
    let bad = || malformed("sealed vtable");
    let owner = Owner::R2r(SEC_DEHYDRATED_DATA);
    for (&s, &used) in sealed {
        let r = img.region(s).filter(|r| r.file && !r.exec).ok_or_else(bad)?;
        let next = bounds.range(s + 1..).next().copied().unwrap_or(r.end);
        let end = next.min(r.end);
        if (end - s) % 4 != 0 {
            return Err(bad());
        }
        let slots = (end - s) / 4;
        if used > slots {
            return Err(ModelError::Malformed(format!(
                "sealed vtable at {:#x}: {} slots, its dispatch map uses {}",
                s, slots, used
            )));
        }
        if used < slots {
            unconfirmed.push((s, end));
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

/// Starts of the code with managed unwind info: the FDEs whose LSDA lies
/// in `.dotnet_eh_table` (managed methods and their funclets). The
/// runtime enters a funclet through an offset in its main method's EH
/// clauses, which names no address, so this code must stay live
/// whatever references it. Empty without that section or when an LSDA
/// cannot be located (the model is then refused anyway).
fn managed_unwind_starts(img: &Image) -> Vec<u64> {
    let Some(eh) = img.named(EH_TABLE).map(|r| (r.start, r.end)) else {
        return Vec::new();
    };
    ehframe::fde_lsdas(img.data, &img.sections)
        .unwrap_or_default()
        .into_iter()
        .filter(|&(_, l)| eh.0 <= l && l < eh.1)
        .map(|(begin, _)| begin)
        .collect()
}

/// References in `.dotnet_eh_table` LSDAs (named by `.eh_frame` FDEs)
/// and in the associated data and EH info they point at; the extents of
/// those structures go to `parsed`. An FDE whose LSDA cannot be located
/// (DW_EH_PE_indirect, or an encoding that does not resolve) is refused:
/// it could name an LSDA of the table. EH info blocks must not overlap,
/// which keeps the walk linear in their size.
fn unwind_refs(
    img: &Image,
    out: &mut Vec<RelPtr>,
    parsed: &mut Vec<(u64, u64)>,
) -> Result<(), ModelError> {
    let eh = match img.named(EH_TABLE) {
        Some(r) => (r.start, r.end),
        None => return Ok(()),
    };
    let mut assoc = BTreeSet::new();
    let mut infos = BTreeSet::new();
    let lsdas: BTreeSet<u64> = ehframe::fde_lsdas(img.data, &img.sections)
        .map_err(|pc| {
            ModelError::Malformed(format!(
                "the LSDA of the FDE at {:#x} is indirect or does not resolve",
                pc
            ))
        })?
        .into_iter()
        .map(|(_, l)| l)
        .filter(|&l| eh.0 <= l && l < eh.1)
        .collect();
    for l in lsdas {
        lsda_refs(img, l, eh, out, &mut assoc, &mut infos)?;
        parsed.push((l, l + 1));
    }
    for a in assoc {
        associated_refs(img, a, out)?;
        parsed.push((a, a + 1));
    }
    let mut prev_end = 0;
    for i in infos {
        if i < prev_end {
            return Err(malformed("EH info blocks overlap"));
        }
        prev_end = eh_info_refs(img, i, out)?;
        parsed.push((i, prev_end));
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
/// unsigned integers. Returns the address just past the block.
fn eh_info_refs(img: &Image, i: u64, out: &mut Vec<RelPtr>) -> Result<u64, ModelError> {
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
    Ok(p)
}

/// Read a NativeFormat unsigned integer at `*p` and advance past it.
/// The low bits of the first byte give the length: x0 one byte, x01
/// two, x011 three, x0111 four, 01111 a full 32-bit value after it.
/// A first byte ending in five ones (11111) is invalid, as in the
/// runtime's decoder.
fn read_unsigned(img: &Image, p: &mut u64) -> Option<u32> {
    let b0 = img.u8_at(*p)? as u32;
    if b0.trailing_ones() >= 5 {
        return None;
    }
    let len = (b0.trailing_ones() + 1) as u64;
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
        assert_eq!(method_table_start(&hyd, 0x1028, hyd.base), Some(0x1000));
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

    /// Crafted images: each must be refused or read safely, and quickly.
    mod crafted {
        use super::super::*;
        use std::sync::mpsc;
        use std::time::Duration;

        /// Vaddr of file offset 0 in the crafted images.
        const VA: u64 = 0x40_0000;
        /// `.text`: 0x1000 bytes of code.
        const TEXT: u64 = VA + 0x1000;
        /// `__modules`, when file-backed.
        const MODULES: u64 = VA + 0x2000;
        /// `.data`: the ReadyToRun header, then its sections from `ARRAYS`.
        const DATA: u64 = VA + 0x4000;
        /// Where the ReadyToRun sections of `.data` start.
        const ARRAYS: u64 = DATA + 0x100;
        /// Address of a NOBITS section, past every file-backed one.
        const NOBITS: u64 = VA + 0x100_0000;

        /// Contents of a crafted section.
        enum Body {
            /// File-backed bytes at file offset `addr - VA`.
            Bits(Vec<u8>),
            /// NOBITS of this size.
            NoBits(u64),
        }

        /// A section of a crafted image.
        struct Sec {
            /// Section name.
            name: &'static str,
            /// Vaddr.
            addr: u64,
            /// Executable (else writable data).
            exec: bool,
            /// Contents.
            body: Body,
        }

        /// A writable data section.
        fn data_sec(name: &'static str, addr: u64, bytes: Vec<u8>) -> Sec {
            Sec { name, addr, exec: false, body: Body::Bits(bytes) }
        }

        /// `.text`, filled with `ret`.
        fn text() -> Sec {
            Sec { name: ".text", addr: TEXT, exec: true, body: Body::Bits(vec![0xc3; 0x1000]) }
        }

        /// A 64-bit little-endian x86-64 ET_DYN ELF holding `secs`, then
        /// its section name table and section headers; no segments.
        fn elf(secs: &[Sec]) -> Vec<u8> {
            let mut data = vec![0u8; 0x40];
            for s in secs {
                if let Body::Bits(b) = &s.body {
                    let off = (s.addr - VA) as usize;
                    if data.len() < off + b.len() {
                        data.resize(off + b.len(), 0);
                    }
                    data[off..off + b.len()].copy_from_slice(b);
                }
            }
            let mut names = vec![0u8];
            let mut name_at = Vec::new();
            for n in secs.iter().map(|s| s.name).chain([".shstrtab"]) {
                name_at.push(names.len() as u32);
                names.extend(n.as_bytes());
                names.push(0);
            }
            let names_off = data.len() as u64;
            data.extend(&names);
            data.resize(data.len().next_multiple_of(8), 0);
            let shoff = data.len() as u64;
            data.extend([0u8; 64]);
            for (s, &name) in secs.iter().zip(&name_at) {
                let (ty, off, size) = match &s.body {
                    Body::Bits(b) => (1, s.addr - VA, b.len() as u64),
                    Body::NoBits(n) => (8, 0, *n),
                };
                let flags = if s.exec { 2 | 4 } else { 2 | 1 };
                data.extend(shdr(name, ty, flags, s.addr, off, size));
            }
            let strtab = name_at[secs.len()];
            data.extend(shdr(strtab, 3, 0, 0, names_off, names.len() as u64));
            let shnum = secs.len() as u16 + 2;
            ehdr(&mut data, shoff, shnum);
            data
        }

        /// A 64-byte ELF64 section header.
        fn shdr(name: u32, ty: u32, flags: u64, addr: u64, off: u64, size: u64) -> Vec<u8> {
            let mut h = Vec::with_capacity(64);
            h.extend(name.to_le_bytes());
            h.extend(ty.to_le_bytes());
            h.extend(flags.to_le_bytes());
            h.extend(addr.to_le_bytes());
            h.extend(off.to_le_bytes());
            h.extend(size.to_le_bytes());
            h.extend([0u8; 8]);
            h.extend(8u64.to_le_bytes());
            h.extend(0u64.to_le_bytes());
            h
        }

        /// Fill in the ELF header: section headers at `shoff`, `shnum` of
        /// them, the name table last.
        fn ehdr(d: &mut [u8], shoff: u64, shnum: u16) {
            d[..8].copy_from_slice(b"\x7fELF\x02\x01\x01\x00");
            d[16..18].copy_from_slice(&3u16.to_le_bytes());
            d[18..20].copy_from_slice(&62u16.to_le_bytes());
            d[20..24].copy_from_slice(&1u32.to_le_bytes());
            d[40..48].copy_from_slice(&shoff.to_le_bytes());
            d[52..54].copy_from_slice(&64u16.to_le_bytes());
            d[54..56].copy_from_slice(&56u16.to_le_bytes());
            d[58..60].copy_from_slice(&64u16.to_le_bytes());
            d[60..62].copy_from_slice(&shnum.to_le_bytes());
            d[62..64].copy_from_slice(&(shnum - 1).to_le_bytes());
        }

        /// A version 16 ReadyToRun header with section rows
        /// `(id, flags, start, end)`.
        fn header(rows: &[(u32, u32, u64, u64)]) -> Vec<u8> {
            let mut b = Vec::new();
            b.extend(0x0052_5452u32.to_le_bytes());
            b.extend([16, 0, 0, 0, 0, 0, 0, 0]);
            b.extend((rows.len() as u16).to_le_bytes());
            b.extend([24, 1]);
            for &(id, flags, start, end) in rows {
                b.extend(id.to_le_bytes());
                b.extend(flags.to_le_bytes());
                b.extend(start.to_le_bytes());
                b.extend(end.to_le_bytes());
            }
            b
        }

        /// RELPTR32 bytes at `loc` designating `target`.
        fn rel(loc: u64, target: u64) -> [u8; 4] {
            (target.wrapping_sub(loc) as i32).to_le_bytes()
        }

        /// `.data`: `header` at `DATA`, then `arrays` at `ARRAYS`.
        fn data_with(header: Vec<u8>, arrays: Vec<u8>) -> Sec {
            let mut b = header;
            b.resize((ARRAYS - DATA) as usize, 0);
            b.extend(arrays);
            data_sec(".data", DATA, b)
        }

        /// `__modules` holding the pointers `slots`.
        fn modules(slots: &[u64]) -> Sec {
            data_sec("__modules", MODULES, slots.iter().flat_map(|s| s.to_le_bytes()).collect())
        }

        /// `n` RELPTR32s from `at` on, each designating .text.
        fn code_relptrs(at: u64, n: u64) -> Vec<u8> {
            (0..n).flat_map(|i| rel(at + 4 * i, TEXT)).collect()
        }

        /// Run `f` on another thread; panic if it takes over 10 seconds.
        fn quickly<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
            let (tx, rx) = mpsc::channel();
            std::thread::spawn(move || {
                let _ = tx.send(f());
            });
            rx.recv_timeout(Duration::from_secs(10)).expect("returns within 10 seconds")
        }

        /// The model of `data`, computed under `quickly`.
        fn model(data: Vec<u8>) -> Result<Vec<RelPtr>, ModelError> {
            quickly(move || nativeaot_refs(&data))
        }

        /// True if `r` is a refusal (not a model, not "no header").
        fn refused(r: &Result<Vec<RelPtr>, ModelError>) -> bool {
            matches!(r, Err(ModelError::Malformed(_)))
        }

        /// A well-formed image: one module initializer into .text.
        #[test]
        fn models_a_well_formed_image() {
            let rows = [(213, 1, ARRAYS, ARRAYS + 4)];
            let d = elf(&[text(), modules(&[DATA]), data_with(header(&rows), code_relptrs(ARRAYS, 1))]);
            let refs = model(d).expect("modelled");
            assert_eq!(refs.len(), 1);
            assert_eq!((refs[0].location, refs[0].target), (ARRAYS, TEXT));
        }

        /// A NOBITS `__modules` of 2^60 bytes: its contents are unknown,
        /// so the model is refused, without walking its slots.
        #[test]
        fn refuses_a_huge_nobits_modules() {
            let m = Sec { name: "__modules", addr: NOBITS, exec: false, body: Body::NoBits(1 << 60) };
            let rows = [(213, 1, ARRAYS, ARRAYS + 4)];
            let d = elf(&[text(), m, data_with(header(&rows), code_relptrs(ARRAYS, 1))]);
            assert!(refused(&model(d)));
        }

        /// Two `__modules` slots naming one header: it is read once.
        #[test]
        fn reads_a_duplicate_header_once() {
            let rows = [(213, 1, ARRAYS, ARRAYS + 8)];
            let d = elf(&[text(), modules(&[DATA, DATA]), data_with(header(&rows), code_relptrs(ARRAYS, 2))]);
            let headers = quickly(move || {
                let img = Image::parse(&d).expect("parses");
                read_headers(&img).map(|h| h.len())
            });
            assert_eq!(headers.ok(), Some(1));
        }

        /// Rows whose ranges overlap are refused.
        #[test]
        fn refuses_overlapping_rows() {
            let rows = [(213, 1, ARRAYS, ARRAYS + 8), (308, 1, ARRAYS + 4, ARRAYS + 12)];
            let d = elf(&[text(), modules(&[DATA]), data_with(header(&rows), code_relptrs(ARRAYS, 3))]);
            assert!(refused(&model(d)));
        }

        /// A section id listed twice is refused.
        #[test]
        fn refuses_a_repeated_section_id() {
            let rows = [(213, 1, ARRAYS, ARRAYS + 4), (213, 1, ARRAYS + 4, ARRAYS + 8)];
            let d = elf(&[text(), modules(&[DATA]), data_with(header(&rows), code_relptrs(ARRAYS, 2))]);
            assert!(refused(&model(d)));
        }

        /// A RELPTR32 array row without an end pointer has no known
        /// extent: refused, not read as empty.
        #[test]
        fn refuses_an_array_row_without_end() {
            let rows = [(213, 0, ARRAYS, 0)];
            let d = elf(&[text(), modules(&[DATA]), data_with(header(&rows), code_relptrs(ARRAYS, 1))]);
            assert!(refused(&model(d)));
        }

        /// Dehydrated data rebuilt into a 2^40-byte NOBITS section by 16
        /// zero fills of 16 MiB each: far more than the file could
        /// describe, refused before any of it is allocated.
        #[test]
        fn refuses_a_giant_rebuild() {
            let hyd = Sec { name: ".hydrated", addr: NOBITS, exec: false, body: Body::NoBits(1 << 40) };
            let mut stream = rel(ARRAYS, NOBITS).to_vec();
            for _ in 0..16 {
                stream.extend([(31 << 3) | CMD_ZERO_FILL, 0xff, 0xff, 0xff]);
            }
            let end = ARRAYS + stream.len() as u64;
            let rows = [(207, 1, ARRAYS, end), (204, 0, DATA, 0)];
            let d = elf(&[text(), modules(&[DATA]), data_with(header(&rows), stream), hyd]);
            assert!(refused(&model(d)));
        }

        /// NativeFormat: a first byte ending in five ones is invalid; one
        /// ending in 01111 takes the next four bytes.
        #[test]
        fn rejects_the_invalid_unsigned_prefix() {
            let bytes = vec![0x1f, 1, 2, 3, 4, 0x0f, 1, 2, 3, 4];
            let d = elf(&[text(), data_sec(".data", DATA, bytes)]);
            let img = Image::parse(&d).expect("parses");
            let mut p = DATA;
            assert_eq!(read_unsigned(&img, &mut p), None);
            let mut p = DATA + 5;
            assert_eq!(read_unsigned(&img, &mut p), Some(0x0403_0201));
            assert_eq!(p, DATA + 10);
        }

        /// `__modules` slots that name no ReadyToRun header are counted,
        /// so the caller can note them; an empty one counts none.
        #[test]
        fn counts_slots_naming_no_header() {
            let d = elf(&[text(), modules(&[TEXT, 0]), data_sec(".data", DATA, vec![0; 16])]);
            assert_eq!(model(d), Err(ModelError::NoHeader(1)));
            let d = elf(&[text(), modules(&[0, 0])]);
            assert_eq!(model(d), Err(ModelError::NoHeader(0)));
        }

        /// A target inside an outer function, past the end of a function
        /// nested in it, maps to the outer one.
        #[test]
        fn maps_targets_in_nested_ranges() {
            let mut funcs = FuncMap::new();
            let f = |addr, size| crate::types::FuncInfo { addr, size, is_global: false };
            funcs.insert("outer".into(), f(0x100, 0x100));
            funcs.insert("inner".into(), f(0x120, 0x10));
            assert_eq!(containing_funcs(&funcs, &[0x150]), vec!["outer".to_string()]);
        }

        // ---- Compaction ------------------------------------------------

        /// A dispatch map (counts, then 6-byte instance and 8-byte static
        /// entries) whose implementation slots are `impls` and `statics`.
        fn dispatch_map(impls: &[u16], defaults: &[u16], statics: &[u16]) -> Vec<u8> {
            let mut b = Vec::new();
            for n in [impls.len(), defaults.len(), statics.len(), 0] {
                b.extend((n as u16).to_le_bytes());
            }
            for &s in impls.iter().chain(defaults) {
                b.extend([0, 0, 0, 0]);
                b.extend(s.to_le_bytes());
            }
            for &s in statics {
                b.extend([0, 0, 0, 0]);
                b.extend(s.to_le_bytes());
                b.extend([0, 0]);
            }
            b
        }

        /// Slots at or above the vtable slot count name sealed slots; the
        /// highest one used (here 7 - 5 = 2, so three slots) counts, in
        /// any entry kind; special slots and vtable slots do not.
        #[test]
        fn counts_sealed_slots_a_dispatch_map_uses() {
            let map = dispatch_map(&[3, 6], &[7], &[5, 0xffff]);
            let len = map.len() as u64;
            let d = elf(&[text(), data_sec(".data", DATA, map)]);
            let img = Image::parse(&d).expect("parses");
            let m = read_dispatch_map(&img, DATA).expect("read");
            assert_eq!((m.start, m.end, m.highest), (DATA, DATA + len, Some(7)));
            assert_eq!((m.used(5), m.used(8)), (3, 0));
            let short = dispatch_map(&[3, 6, 9], &[], &[]);
            let d = elf(&[text(), data_sec(".data", DATA, short[..14].to_vec())]);
            let img = Image::parse(&d).expect("parses");
            assert!(read_dispatch_map(&img, DATA).is_err());
        }

        /// Bytes of one rebuilt MethodTable with a dispatch map and a
        /// sealed vtable, no vtable slots (40 bytes): flags and base
        /// size, related type, slot counts and hash, then the type
        /// manager, writable data, dispatch map and sealed vtable fields.
        const MT_SIZE: u64 = 40;

        /// `n` rebuilt MethodTables at `base` naming the type manager
        /// indirection `tmi`, the dispatch map `map(i)` and the sealed
        /// vtable `sealed`.
        fn method_tables(base: u64, n: u64, tmi: u64, map: impl Fn(u64) -> u64, sealed: u64) -> Hydrated {
            let mut bytes = vec![0u8; (n * MT_SIZE) as usize];
            let mut writes = Vec::with_capacity(4 * n as usize);
            for i in 0..n {
                let m = base + i * MT_SIZE;
                let o = (i * MT_SIZE) as usize;
                bytes[o..o + 4].copy_from_slice(&(MT_HAS_DISPATCH_MAP | MT_HAS_SEALED_VTABLE).to_le_bytes());
                writes.push((m + 24, 4, tmi));
                writes.push((m + 28, 4, NOBITS));
                writes.push((m + 32, 4, map(i)));
                writes.push((m + 36, 4, sealed));
            }
            Hydrated { base, bytes, writes }
        }

        /// 100,000 MethodTables naming one dispatch map of 131,070
        /// entries: the map is read once, not once per type (which
        /// would take about 10^10 reads).
        #[test]
        fn reads_a_shared_dispatch_map_once() {
            let mut map = vec![0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0];
            for i in 0..131_070u32 {
                map.extend([0, 0, 0, 0]);
                map.extend(((i % 3) as u16).to_le_bytes());
            }
            let d = elf(&[text(), data_sec(".data", DATA, map)]);
            let sealed = quickly(move || {
                let img = Image::parse(&d).expect("parses");
                let hyd = method_tables(NOBITS, 100_000, DATA - 8, |_| DATA, TEXT);
                let mut parsed = Vec::new();
                sealed_vtables(&img, &hyd, DATA - 8, &mut parsed).map(|s| (s, parsed))
            });
            let (sealed, parsed) = sealed.expect("modelled");
            assert_eq!(sealed.into_iter().collect::<Vec<_>>(), vec![(TEXT, 3)]);
            assert_eq!(parsed, vec![(DATA, DATA + 8 + 6 * 131_070)]);
        }

        /// Dispatch maps two bytes apart, each claiming 514 entries: their
        /// extents overlap, so the model is refused without reading them
        /// all.
        #[test]
        fn refuses_overlapping_dispatch_maps() {
            let d = elf(&[text(), data_sec(".data", DATA, vec![1; 12_000])]);
            let r = quickly(move || {
                let img = Image::parse(&d).expect("parses");
                let hyd = method_tables(NOBITS, 1000, DATA - 8, |i| DATA + 2 * i, TEXT);
                sealed_vtables(&img, &hyd, DATA - 8, &mut Vec::new())
            });
            assert_eq!(r, Err(malformed("dispatch maps overlap")));
        }

        /// Spans merge when they overlap or touch; a range overlaps a
        /// span when they share a byte.
        #[test]
        fn merges_and_searches_spans() {
            let s = merged([(10, 20), (0, 4), (15, 30), (30, 32), (40, 40)].into_iter());
            assert_eq!(s, vec![(0, 4), (10, 32)]);
            assert!(overlaps(&s, 2, 6) && overlaps(&s, 28, 40) && !overlaps(&s, 4, 10));
            assert!(in_spans(&s, 31) && !in_spans(&s, 32) && !in_spans(&s, 5));
        }

        /// REL, RELR and Android packed relocation tags are foreign;
        /// RELA tags are not.
        #[test]
        fn recognises_foreign_relocation_tags() {
            assert!([17, 18, 19, 35, 36, 37, 0x6000_000f, 0x6000_0011].iter().all(|&t| foreign_reloc_tag(t)));
            assert!(![7, 8, 9, 0x6fff_fff9].iter().any(|&t| foreign_reloc_tag(t)));
        }

        /// Patch sites that overlap are refused: a RELPTR32 inside a
        /// pointer slot, or a jump table entry over a RELPTR32.
        #[test]
        fn refuses_overlapping_patch_sites() {
            let field = |location| RelField { location, offset: 0, target: TEXT };
            let slot = PtrSlot { location: DATA, offset: 0, target: TEXT };
            let entry = |location| TableEntry { location, offset: 0, target: TEXT };
            let plan = R2rPlan { relptrs: vec![field(DATA + 8)], slots: vec![slot], ..R2rPlan::default() };
            assert_eq!(plan.site_overlap(&[entry(DATA + 12)]), None);
            let why = plan.site_overlap(&[entry(DATA + 10)]);
            assert!(why.is_some_and(|w| w.contains("RELPTR32 at 0x404008 overlaps jump table entry")));
            let plan = R2rPlan { relptrs: vec![field(DATA + 4)], ..plan };
            assert!(plan.site_overlap(&[]).is_some_and(|w| w.contains("pointer slot")));
        }

        /// A stray word blocks compaction when its ends move apart or its
        /// target is removed, unless a jump table entry accounts for it.
        #[test]
        fn blocks_on_stray_words_that_move_apart() {
            let (ts, te) = (TEXT, TEXT + 0x1000);
            let ivs = [(TEXT + 0x100, TEXT + 0x180)];
            let plan = |stray| R2rPlan { stray, ..R2rPlan::default() };
            assert_eq!(plan(vec![(DATA, TEXT + 0x80)]).stray_conflict(&[], &ivs, ts, te), None);
            let moved = plan(vec![(DATA, TEXT + 0x200)]);
            let why = moved.stray_conflict(&[], &ivs, ts, te);
            assert!(why.is_some_and(|w| w.starts_with("1 data words") && w.contains("0x404000")));
            let entry = TableEntry { location: DATA - 2, offset: 0, target: TEXT };
            assert_eq!(moved.stray_conflict(&[entry], &ivs, ts, te), None);
            let removed = plan(vec![(TEXT - 0x10, TEXT + 0x100)]);
            assert!(removed.stray_conflict(&[], &ivs, ts, te).is_some());
        }

        /// Stray words: a self-relative word in data designating a
        /// function start; not when it designates no start, overlaps a
        /// listed field, or lies in an unscanned section.
        #[test]
        fn finds_stray_words() {
            let mut b = vec![0u8; 0x40];
            b[0x10..0x14].copy_from_slice(&rel(ARRAYS + 0x10, TEXT + 0x20));
            b[0x20..0x24].copy_from_slice(&rel(ARRAYS + 0x20, TEXT + 0x30));
            b[0x30..0x34].copy_from_slice(&rel(ARRAYS + 0x30, TEXT + 0x21));
            let rows = [(213, 1, ARRAYS, ARRAYS + 4)];
            let mut arrays = code_relptrs(ARRAYS, 1);
            arrays.extend(&b[4..]);
            let eh = data_sec(".eh_frame", VA + 0x6000, rel(VA + 0x6000, TEXT + 0x20).to_vec());
            let d = elf(&[text(), modules(&[DATA]), data_with(header(&rows), arrays), eh]);
            let img = Image::parse(&d).expect("parses");
            let model = refs_of(&img).expect("modelled");
            let starts = [TEXT, TEXT + 0x20, TEXT + 0x30];
            let found = stray_words(&img, &model, &[], &starts, TEXT, TEXT + 0x1000);
            assert_eq!(found, vec![(ARRAYS + 0x10, TEXT + 0x20), (ARRAYS + 0x20, TEXT + 0x30)]);
        }

        /// Two sealed vtables of 2 and 3 slots into .text, bounded by
        /// each other and the end of `.data`.
        fn two_vtables() -> Vec<u8> {
            let mut b = code_relptrs(DATA, 2);
            b.extend(code_relptrs(DATA + 8, 3));
            elf(&[text(), data_sec(".data", DATA, b)])
        }

        /// A vtable whose dispatch map uses every slot is confirmed; one
        /// whose map uses fewer is listed but unconfirmed; one whose map
        /// uses more than it holds is refused.
        #[test]
        fn bounds_sealed_vtables_by_their_dispatch_maps() {
            let d = two_vtables();
            let img = Image::parse(&d).expect("parses");
            let bounds: BTreeSet<u64> = [DATA, DATA + 8].into_iter().collect();
            let sealed: BTreeMap<u64, u64> = [(DATA, 2), (DATA + 8, 1)].into_iter().collect();
            let (mut out, mut unconfirmed) = (Vec::new(), Vec::new());
            sealed_slots(&img, &sealed, &bounds, &mut out, &mut unconfirmed).expect("modelled");
            assert_eq!(out.len(), 5);
            assert_eq!(unconfirmed, vec![(DATA + 8, DATA + 20)]);
            let over: BTreeMap<u64, u64> = [(DATA, 3)].into_iter().collect();
            let r = sealed_slots(&img, &over, &bounds, &mut Vec::new(), &mut Vec::new());
            assert!(matches!(r, Err(ModelError::Malformed(_))));
        }

        /// Compaction is refused only when an unconfirmed sealed vtable
        /// has a slot into .text.
        #[test]
        fn refuses_unconfirmed_sealed_slots_into_text() {
            let slot = |location, target| {
                RelPtr::new(location, target, RefKind::SealedVTableSlot, Owner::R2r(207))
            };
            let model = Model {
                refs: vec![slot(DATA, TEXT), slot(DATA + 8, NOBITS)],
                unconfirmed: vec![(DATA + 8, DATA + 12)],
                parsed: Vec::new(),
            };
            assert_eq!(sealed_conflict(&model, TEXT, TEXT + 0x1000), None);
            let model = Model { unconfirmed: vec![(DATA, DATA + 4)], ..model };
            let why = sealed_conflict(&model, TEXT, TEXT + 0x1000);
            assert!(why.is_some_and(|w| w.contains("points into .text")));
        }

        /// The layout must keep data together after .text: data before
        /// .text, an executable section not decoded, or a section over
        /// .text is refused; metadata before .text and decoded code are
        /// accepted.
        #[test]
        fn checks_the_section_layout() {
            let before = data_sec(".data", VA + 0x800, vec![0; 8]);
            let d = elf(&[text(), before]);
            let e = goblin::elf::Elf::parse(&d).expect("parses");
            let why = layout_conflict(&e, TEXT, TEXT + 0x1000, &[]);
            assert!(why.is_some_and(|w| w.contains("lies before .text")));
            let code = Sec { name: "__managedcode", addr: DATA, exec: true, body: Body::Bits(vec![0xc3; 16]) };
            let d = elf(&[text(), code]);
            let e = goblin::elf::Elf::parse(&d).expect("parses");
            let why = layout_conflict(&e, TEXT, TEXT + 0x1000, &[]);
            assert!(why.is_some_and(|w| w.contains("not decoded")));
            assert_eq!(layout_conflict(&e, TEXT, TEXT + 0x1000, &["__managedcode"]), None);
            let over = data_sec(".data", TEXT + 0x800, vec![0; 8]);
            let d = elf(&[text(), over]);
            let e = goblin::elf::Elf::parse(&d).expect("parses");
            let why = layout_conflict(&e, TEXT, TEXT + 0x1000, &[]);
            assert!(why.is_some_and(|w| w.contains("overlaps .text")));
        }

        /// Only position-independent x86-64 images qualify.
        #[test]
        fn requires_a_position_independent_x86_64_image() {
            let mut d = elf(&[text()]);
            let e = goblin::elf::Elf::parse(&d).expect("parses");
            assert_eq!(image_conflict(&e), None);
            d[16..18].copy_from_slice(&2u16.to_le_bytes());
            let e = goblin::elf::Elf::parse(&d).expect("parses");
            assert!(image_conflict(&e).is_some_and(|w| w.contains("position-independent")));
        }

        /// A well-formed image is planned: its RELPTR32 with its file
        /// offset; a version the model refuses is not.
        #[test]
        fn plans_a_well_formed_image_only() {
            let rows = [(213, 1, ARRAYS, ARRAYS + 4)];
            let d = elf(&[text(), modules(&[DATA]), data_with(header(&rows), code_relptrs(ARRAYS, 1))]);
            let plan = compaction_plan(&d, &[]).expect("planned");
            assert_eq!(plan.relptrs.len(), 1);
            assert_eq!(plan.relptrs[0].offset as u64, ARRAYS - VA);
            let mut hdr = header(&rows);
            hdr[4] = 15;
            let d = elf(&[text(), modules(&[DATA]), data_with(hdr, code_relptrs(ARRAYS, 1))]);
            let why = compaction_plan(&d, &[]).expect_err("refused");
            assert!(why.contains("not verified"));
        }
    }
}
