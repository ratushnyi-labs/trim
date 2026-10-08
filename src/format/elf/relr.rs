//! Opt-in RELA -> RELR packing of RELATIVE relocations (`--relr`).
//!
//! A position-independent ELF carries one 24-byte RELA entry per
//! R_*_RELATIVE relocation. RELR (DT_RELR) encodes the same relocations
//! with implicit addends as a list of 8-byte words, as lld, glibc and
//! musl define it: an even word is the address of a word to relocate,
//! an odd word is a bitmap whose bit `i` (1..=63) marks the word `i - 1`
//! places after the last one the previous entry covered.
//!
//! The packed table goes inside the old `.rela.dyn` byte range as
//! `[remaining RELA][RELR]`; each relocated word first gets its addend
//! written in place. `.dynamic` gains DT_RELR, DT_RELRSZ and DT_RELRENT
//! in free DT_NULL slots, and the RELA tags shrink, or go when no RELA
//! entry remains. When `.rela.dyn` ends its PT_LOAD segment, the freed
//! whole pages leave the file: everything after them moves down in the
//! file by a multiple of the segment alignment while every vaddr stays,
//! so `p_offset == p_vaddr (mod p_align)` still holds. Otherwise the
//! slack stays as zero padding.
//!
//! Whether DT_RELR is applied cannot be told from a stripped binary, so
//! the rewrite only runs when asked for. A dynamic PIE or shared library
//! needs a dynamic loader that applies it (glibc 2.36+, musl 1.2.4+). A
//! static-pie (or a dynamic loader itself) relocates itself with the
//! start code of the libc it was linked with, which may predate RELR:
//! such input is refused unless the caller asserts that its libc
//! applies DT_RELR (`--relr-static`). Only 64-bit little-endian x86-64
//! and AArch64 ELF is handled.

// ---- ELF constants -------------------------------------------------

const ET_DYN: u16 = 3;
const EM_X86_64: u16 = 62;
const EM_AARCH64: u16 = 183;
const R_X86_64_RELATIVE: u64 = 8;
const R_AARCH64_RELATIVE: u64 = 1027;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
/// e_phnum value meaning the real count is in section header 0.
const PN_XNUM: usize = 0xffff;
/// e_shstrndx value meaning the real index is in section header 0.
const SHN_XINDEX: usize = 0xffff;
const SHT_RELA: u32 = 4;
const SHT_NOBITS: u32 = 8;
const SHT_RELR: u32 = 19;
const SHF_ALLOC: u64 = 0x2;
const SHF_INFO_LINK: u64 = 0x40;
const DT_NULL: u64 = 0;
const DT_NEEDED: u64 = 1;
const DT_PLTRELSZ: u64 = 2;
const DT_STRTAB: u64 = 5;
const DT_RELA: u64 = 7;
const DT_RELASZ: u64 = 8;
const DT_RELAENT: u64 = 9;
const DT_REL: u64 = 17;
const DT_PLTREL: u64 = 20;
const DT_JMPREL: u64 = 23;
const DT_RELRSZ: u64 = 35;
const DT_RELR: u64 = 36;
const DT_RELRENT: u64 = 37;
const DT_RELACOUNT: u64 = 0x6fff_fff9;
const DT_FLAGS_1: u64 = 0x6fff_fffb;
const DT_VERNEED: u64 = 0x6fff_fffe;
const DT_VERNEEDNUM: u64 = 0x6fff_ffff;
/// DT_FLAGS_1 bit marking a position-independent executable.
const DF_1_PIE: u64 = 0x0800_0000;
/// Size of an Elf64_Verneed and of an Elf64_Vernaux entry.
const VERNEED_SIZE: usize = 16;
/// Upper bound on the Verneed and Vernaux entries walked in all
/// (guards against link loops and huge counts).
const MAX_VERSIONS: usize = 4096;
/// Longest DT_NEEDED name read, NUL included.
const MAX_NAME: usize = 4096;
/// Prefix glibc's loader matches on DT_NEEDED to demand the RELR version.
const GLIBC_SONAME: &[u8] = b"libc.so.";
/// The glibc symbol version an object using DT_RELR must depend on.
const GLIBC_RELR_VERSION: &[u8] = b"GLIBC_ABI_DT_RELR";
const EHDR_SIZE: usize = 64;
const PHDR_SIZE: usize = 56;
const SHDR_SIZE: usize = 64;
const DYN_SIZE: usize = 16;
const RELA_SIZE: usize = 24;
const REL_SIZE: usize = 16;
const SHN_LORESERVE: usize = 0xff00;

/// Size of a relocated word and of a RELR entry.
const WORD: u64 = 8;
/// Words a RELR bitmap entry covers (its low bit marks it a bitmap).
const BITMAP_BITS: u64 = 63;
/// Smallest unit that may leave the file.
const PAGE: u64 = 0x1000;
const RELA_NAME: &[u8] = b".rela.dyn\0";
const RELR_NAME: &[u8] = b".relr.dyn\0";

// ---- Parsed headers --------------------------------------------------

/// ELF header fields this pass reads or rewrites.
struct Ehdr {
    etype: u16,
    entry: u64,
    phoff: u64,
    shoff: u64,
    phnum: usize,
    shnum: usize,
    shstrndx: usize,
}

/// A program header and the file offset of its entry (`at`).
struct Phdr {
    at: usize,
    ptype: u32,
    offset: u64,
    vaddr: u64,
    filesz: u64,
    memsz: u64,
    align: u64,
}

/// A section header and the file offset of its entry (`at`).
struct Shdr {
    at: usize,
    name: u64,
    stype: u32,
    offset: u64,
    size: u64,
}

/// The header tables of a 64-bit little-endian ELF.
struct Elf {
    eh: Ehdr,
    phdrs: Vec<Phdr>,
    shdrs: Vec<Shdr>,
}

/// The `.dynamic` array: file offset, vaddr, slot count, and the
/// entries before the first DT_NULL.
struct Dynamic {
    off: usize,
    addr: u64,
    slots: usize,
    tags: Vec<(u64, u64)>,
}

/// The DT_RELA table: file offset, vaddr, byte size, the PT_LOAD index
/// holding it and its section header index (if the file has headers).
struct Table {
    off: usize,
    addr: u64,
    size: usize,
    seg: usize,
    sec: Option<usize>,
}

/// A RELATIVE relocation RELR can encode.
struct Packed {
    addr: u64,
    addend: u64,
    file_off: usize,
}

/// The RELA entries sorted into packed ones and kept ones.
struct Split {
    packed: Vec<Packed>,
    /// Raw entries that stay RELA, in their original order.
    keep: Vec<u8>,
    /// Leading RELATIVE entries of `keep` (the new DT_RELACOUNT).
    lead: u64,
}

/// A vaddr-preserving file drain: `len` bytes leave at file offset
/// `cut`; segment `seg` (holding `.rela.dyn`) now ends at `new_end`.
struct Drain {
    cut: u64,
    len: u64,
    seg: usize,
    new_end: u64,
}

/// What the RELR pass did, for the report on stderr.
pub struct Report {
    /// RELATIVE relocations moved to RELR.
    pub packed: usize,
    /// RELA relocations kept.
    pub kept: usize,
    /// RELR words written.
    pub words: usize,
    /// Relocated words whose in-place value was set to the addend.
    pub addends: usize,
    /// `.rela.dyn` size before and after, in bytes.
    pub rela_before: usize,
    pub rela_after: usize,
    /// File bytes removed.
    pub freed: u64,
    /// Why the slack stayed as padding (when nothing was freed).
    pub kept_why: Option<String>,
    /// How the RELR table got its section header.
    pub header: String,
}

impl Report {
    /// Print the report to stderr in the CLI's indented style.
    pub fn print(&self) {
        eprintln!(
            "  relr: packed {} RELATIVE relocations into {} RELR words \
             ({} bytes); {} relocations stay RELA",
            self.packed,
            self.words,
            self.words * WORD as usize,
            self.kept
        );
        eprintln!(
            "  relr: .rela.dyn {} -> {} bytes; {}",
            self.rela_before, self.rela_after, self.header
        );
        if self.addends > 0 {
            eprintln!("  relr: wrote {} addends in place", self.addends);
        }
        match &self.kept_why {
            Some(why) => eprintln!(
                "  relr: note: slack kept as padding ({}); 0 bytes freed",
                why
            ),
            None => eprintln!(
                "  relr: freed {} bytes ({} pages) after .rela.dyn; \
                 vaddrs unchanged",
                self.freed,
                self.freed / PAGE
            ),
        }
    }
}

// ---- Entry point ---------------------------------------------------

/// Pack the RELATIVE relocations of `data` into a RELR table. Returns
/// the rewritten image and a report, or why the input is refused (the
/// caller then keeps `data` as it is). A static-pie is refused unless
/// `allow_static` (the caller asserts that its libc applies DT_RELR).
pub fn pack_relative(
    data: &[u8],
    allow_static: bool,
) -> Result<(Vec<u8>, Report), String> {
    let rel = relative_type(data)?;
    let elf = parse(data)?;
    if elf.eh.etype != ET_DYN {
        return Err(format!(
            "not position-independent ({}, need ET_DYN)",
            etype_name(elf.eh.etype)
        ));
    }
    let dy = read_dynamic(data, &elf)?;
    check_glibc(data, &elf, &dy)?;
    let table = rela_table(data, &elf, &dy)?;
    if !allow_static && relocates_itself(&elf, &dy) {
        return Err(STATIC_PIE_REFUSAL.into());
    }
    let mut split = split_relocs(data, &elf, &table, rel)?;
    let offsets = sorted_offsets(&mut split.packed)?;
    check_targets(data, &elf, &dy, &table, &split, &offsets)?;
    let words = encode_relr(&offsets);
    if decode_relr(&words) != offsets {
        return Err("RELR encoding did not round-trip".into());
    }
    let tags = new_tags(&dy, &table, &split, words.len())?;
    rewrite(data, &elf, &dy, &table, &split, &words, &tags)
}

/// Why a self-relocating image is refused without `--relr-static`.
const STATIC_PIE_REFUSAL: &str = "static-pie (ET_DYN without PT_INTERP): \
    the start code of the libc it was linked with applies its relocations, \
    and only glibc 2.36+ and musl 1.2.4+ apply DT_RELR (older ones crash \
    at startup); pass --relr-static if its libc does";

/// True for an image that applies its own relocations: ET_DYN without
/// PT_INTERP, marked a PIE (DF_1_PIE) or with an entry point. That is a
/// static-pie, or a dynamic loader such as ld.so. A shared library
/// (entry 0, no DF_1_PIE) is relocated by the loader that maps it.
fn relocates_itself(elf: &Elf, dy: &Dynamic) -> bool {
    let interp = elf.phdrs.iter().any(|p| p.ptype == PT_INTERP);
    let pie = tag(dy, DT_FLAGS_1).map_or(false, |f| f & DF_1_PIE != 0);
    !interp && (pie || elf.eh.entry != 0)
}

/// Apply the planned rewrite to a copy of `data`: addends, tables,
/// `.dynamic`, section headers, then the file drain.
fn rewrite(
    data: &[u8],
    elf: &Elf,
    dy: &Dynamic,
    table: &Table,
    split: &Split,
    words: &[u64],
    tags: &[(u64, u64)],
) -> Result<(Vec<u8>, Report), String> {
    let mut out = data.to_vec();
    let addends = write_addends(&mut out, &split.packed)?;
    let new_end = write_tables(&mut out, table, &split.keep, words)?;
    write_dynamic(&mut out, dy, tags)?;
    let relr_size = words.len() as u64 * WORD;
    let mut header = update_rela_header(&mut out, elf, table, split, relr_size)?;
    let (freed, kept_why) = match plan_drain(data, elf, table, new_end) {
        Ok(dr) => {
            apply_drain(&mut out, elf, &dr)?;
            (dr.len, None)
        }
        Err(why) => (0, Some(why)),
    };
    if table.sec.is_some() && !split.keep.is_empty() {
        let at = split.keep.len() as u64;
        let off = table.off as u64 + at;
        header = match append_header(&mut out, table.addr + at, off, relr_size) {
            Ok(()) => "new .relr.dyn section header appended".into(),
            Err(why) => format!(
                "RELR table left inside the old .rela.dyn range \
                 without a section header ({})",
                why
            ),
        };
    }
    let report = Report {
        packed: split.packed.len(),
        kept: split.keep.len() / RELA_SIZE,
        words: words.len(),
        addends,
        rela_before: table.size,
        rela_after: split.keep.len(),
        freed,
        kept_why,
        header,
    };
    Ok((out, report))
}

// ---- Byte access -----------------------------------------------------

/// Read the `n`-byte little-endian value at `off`.
fn rd(d: &[u8], off: usize, n: usize) -> Result<u64, String> {
    let b = off
        .checked_add(n)
        .and_then(|e| d.get(off..e))
        .ok_or_else(|| format!("truncated ELF (read at {:#x})", off))?;
    Ok(b.iter().rev().fold(0u64, |v, &x| (v << 8) | u64::from(x)))
}

/// Write the low `n` bytes of `v` little-endian at `off`.
fn wr(d: &mut [u8], off: usize, n: usize, v: u64) -> Result<(), String> {
    let b = off
        .checked_add(n)
        .and_then(|e| d.get_mut(off..e))
        .ok_or_else(|| format!("write outside the file at {:#x}", off))?;
    b.copy_from_slice(&v.to_le_bytes()[..n]);
    Ok(())
}

/// Convert a file-derived value to `usize`.
fn us(v: u64) -> Result<usize, String> {
    usize::try_from(v).map_err(|_| format!("offset {:#x} out of range", v))
}

/// The bytes `[off, off + len)` of `d`.
fn span(d: &[u8], off: u64, len: u64) -> Result<&[u8], String> {
    let (o, l) = (us(off)?, us(len)?);
    o.checked_add(l)
        .and_then(|e| d.get(o..e))
        .ok_or_else(|| format!("range {:#x}+{:#x} outside the file", off, len))
}

// ---- Header parsing ------------------------------------------------

/// The R_*_RELATIVE type for the input's machine, or why it is refused:
/// only 64-bit little-endian x86-64 and AArch64 ELF is handled.
fn relative_type(d: &[u8]) -> Result<u64, String> {
    if d.len() < EHDR_SIZE || d.get(..4) != Some(b"\x7fELF".as_slice()) {
        return Err("not an ELF file".into());
    }
    let le = d[5] == 1;
    let machine = if le {
        u16::from_le_bytes([d[18], d[19]])
    } else {
        u16::from_be_bytes([d[18], d[19]])
    };
    let rel = match machine {
        EM_X86_64 => R_X86_64_RELATIVE,
        EM_AARCH64 => R_AARCH64_RELATIVE,
        m => {
            return Err(format!(
                "unsupported architecture {} (supported: x86-64, AArch64)",
                machine_name(m)
            ))
        }
    };
    if d[4] != 2 || !le {
        return Err("not a 64-bit little-endian ELF".into());
    }
    Ok(rel)
}

/// A readable name for an ELF e_machine value.
fn machine_name(m: u16) -> String {
    let name = match m {
        3 => "x86 (32-bit)",
        8 => "MIPS",
        20 => "PowerPC",
        21 => "PowerPC64",
        22 => "s390",
        40 => "ARM (32-bit)",
        243 => "RISC-V",
        258 => "LoongArch",
        _ => return format!("e_machine {}", m),
    };
    name.to_string()
}

/// A readable name for an ELF e_type value.
fn etype_name(t: u16) -> String {
    match t {
        1 => "ET_REL relocatable object".into(),
        2 => "ET_EXEC fixed-address executable".into(),
        4 => "ET_CORE core file".into(),
        _ => format!("e_type {}", t),
    }
}

/// Parse the ELF header and its program and section header tables.
fn parse(d: &[u8]) -> Result<Elf, String> {
    let eh = Ehdr {
        etype: rd(d, 16, 2)? as u16,
        entry: rd(d, 24, 8)?,
        phoff: rd(d, 32, 8)?,
        shoff: rd(d, 40, 8)?,
        phnum: rd(d, 56, 2)? as usize,
        shnum: rd(d, 60, 2)? as usize,
        shstrndx: rd(d, 62, 2)? as usize,
    };
    check_numbering(&eh)?;
    if eh.phnum > 0 && rd(d, 54, 2)? != PHDR_SIZE as u64 {
        return Err("unexpected program header size".into());
    }
    if eh.shnum > 0 && rd(d, 58, 2)? != SHDR_SIZE as u64 {
        return Err("unexpected section header size".into());
    }
    let phdrs = read_phdrs(d, &eh)?;
    let shdrs = read_shdrs(d, &eh)?;
    Ok(Elf { eh, phdrs, shdrs })
}

/// Refuse extended numbering: a section header table with e_shnum 0
/// (its real count is in section header 0), or an e_phnum or e_shstrndx
/// escape. The tables would not be read whole, so the drain and the
/// header updates would miss entries.
fn check_numbering(eh: &Ehdr) -> Result<(), String> {
    let extended = (eh.shnum == 0 && eh.shoff != 0)
        || eh.phnum == PN_XNUM
        || eh.shstrndx == SHN_XINDEX;
    if extended {
        return Err("extended section or segment numbering \
                    (e_shnum 0 with e_shoff set, PN_XNUM or SHN_XINDEX)"
            .into());
    }
    Ok(())
}

/// Read every program header.
fn read_phdrs(d: &[u8], eh: &Ehdr) -> Result<Vec<Phdr>, String> {
    let base = us(eh.phoff)?;
    (0..eh.phnum)
        .map(|i| {
            let at = base + i * PHDR_SIZE;
            Ok(Phdr {
                at,
                ptype: rd(d, at, 4)? as u32,
                offset: rd(d, at + 8, 8)?,
                vaddr: rd(d, at + 16, 8)?,
                filesz: rd(d, at + 32, 8)?,
                memsz: rd(d, at + 40, 8)?,
                align: rd(d, at + 48, 8)?,
            })
        })
        .collect()
}

/// Read every section header (none when the file has no section header
/// table; extended numbering was refused by `check_numbering`).
fn read_shdrs(d: &[u8], eh: &Ehdr) -> Result<Vec<Shdr>, String> {
    if eh.shnum == 0 {
        return Ok(Vec::new());
    }
    let base = us(eh.shoff)?;
    (0..eh.shnum)
        .map(|i| {
            let at = base + i * SHDR_SIZE;
            Ok(Shdr {
                at,
                name: rd(d, at, 4)?,
                stype: rd(d, at + 4, 4)? as u32,
                offset: rd(d, at + 24, 8)?,
                size: rd(d, at + 32, 8)?,
            })
        })
        .collect()
}

/// The name of section `i`, or `?` when it cannot be read.
fn sec_name(d: &[u8], elf: &Elf, i: usize) -> String {
    let name = || -> Option<String> {
        let st = elf.shdrs.get(elf.eh.shstrndx)?;
        let strs = span(d, st.offset, st.size).ok()?;
        let tail = strs.get(us(elf.shdrs.get(i)?.name).ok()?..)?;
        let end = tail.iter().position(|&b| b == 0)?;
        Some(String::from_utf8_lossy(&tail[..end]).into_owned())
    };
    name().unwrap_or_else(|| "?".into())
}

/// The PT_LOAD index and file offset holding `[addr, addr + len)` in
/// its file-backed part.
fn load_range(elf: &Elf, addr: u64, len: u64) -> Option<(usize, usize)> {
    let end = addr.checked_add(len)?;
    elf.phdrs
        .iter()
        .enumerate()
        .find(|(_, p)| {
            p.ptype == PT_LOAD
                && addr >= p.vaddr
                && end <= p.vaddr.saturating_add(p.filesz)
        })
        .and_then(|(i, p)| {
            let off = p.offset.checked_add(addr - p.vaddr)?;
            Some((i, usize::try_from(off).ok()?))
        })
}

// ---- Dynamic section and relocation table ----------------------------

/// Read the `.dynamic` array from PT_DYNAMIC.
fn read_dynamic(d: &[u8], elf: &Elf) -> Result<Dynamic, String> {
    let ph = elf
        .phdrs
        .iter()
        .find(|p| p.ptype == PT_DYNAMIC)
        .ok_or("no PT_DYNAMIC segment")?;
    let off = us(ph.offset)?;
    let slots = us(ph.filesz)? / DYN_SIZE;
    let mut tags = Vec::new();
    for i in 0..slots {
        let at = off + i * DYN_SIZE;
        let tag = rd(d, at, 8)?;
        if tag == DT_NULL {
            break;
        }
        tags.push((tag, rd(d, at + 8, 8)?));
    }
    Ok(Dynamic { off, addr: ph.vaddr, slots, tags })
}

/// The value of the first `t` entry in `.dynamic`.
fn tag(dy: &Dynamic, t: u64) -> Option<u64> {
    dy.tags.iter().find(|(k, _)| *k == t).map(|&(_, v)| v)
}

/// Refuse a glibc-linked dynamic object: glibc 2.36+ will not load an
/// object with DT_RELR whose DT_NEEDED names `libc.so.*` unless it has a
/// GLIBC_ABI_DT_RELR version dependency, which this pass does not add
/// (the same condition the loader checks).
fn check_glibc(d: &[u8], elf: &Elf, dy: &Dynamic) -> Result<(), String> {
    if tag(dy, DT_VERNEED).is_none() {
        return Ok(());
    }
    let strtab = tag(dy, DT_STRTAB).ok_or("DT_VERNEED without DT_STRTAB")?;
    let (_, str_off) =
        load_range(elf, strtab, 1).ok_or("DT_STRTAB outside the file")?;
    let lib = match glibc_needed(d, dy, str_off) {
        Some(lib) => lib,
        None => return Ok(()),
    };
    if needs_version(d, elf, dy, str_off, GLIBC_RELR_VERSION)? {
        return Ok(());
    }
    Err(format!(
        "linked against glibc ({}): its loader rejects DT_RELR without a \
         GLIBC_ABI_DT_RELR version dependency, which --relr does not add",
        lib
    ))
}

/// The first DT_NEEDED name starting with `libc.so.` (glibc's soname
/// prefix), read from the string table at file offset `str_off`.
fn glibc_needed(d: &[u8], dy: &Dynamic, str_off: usize) -> Option<String> {
    dy.tags
        .iter()
        .filter(|(k, _)| *k == DT_NEEDED)
        .find_map(|&(_, v)| {
            let name = cstr(d, str_off.checked_add(usize::try_from(v).ok()?)?)?;
            name.starts_with(GLIBC_SONAME)
                .then(|| String::from_utf8_lossy(name).into_owned())
        })
}

/// The NUL-terminated string at file offset `off`, if its NUL lies
/// within `MAX_NAME` bytes.
fn cstr(d: &[u8], off: usize) -> Option<&[u8]> {
    let tail = d.get(off..)?;
    let tail = &tail[..tail.len().min(MAX_NAME)];
    tail.get(..tail.iter().position(|&b| b == 0)?)
}

/// True if the string at file offset `off` is exactly `s`: compares
/// `s.len() + 1` bytes (the NUL included), never scanning further.
fn cstr_is(d: &[u8], off: usize, s: &[u8]) -> bool {
    let end = off.checked_add(s.len()).and_then(|e| e.checked_add(1));
    match end.and_then(|e| d.get(off..e)) {
        Some(b) => b[..s.len()] == *s && b[s.len()] == 0,
        None => false,
    }
}

/// `base + off`, or an error naming the overflow.
fn add(base: usize, off: usize) -> Result<usize, String> {
    base.checked_add(off)
        .ok_or_else(|| "version needs offset overflows".to_string())
}

/// True if a DT_VERNEED entry names the symbol version `version`. The
/// Verneed and Vernaux chains share one budget of `MAX_VERSIONS`
/// entries; a chain ends at a zero `vn_next` / `vna_next`.
fn needs_version(
    d: &[u8],
    elf: &Elf,
    dy: &Dynamic,
    str_off: usize,
    version: &[u8],
) -> Result<bool, String> {
    let addr = tag(dy, DT_VERNEED).ok_or("no DT_VERNEED")?;
    let count = tag(dy, DT_VERNEEDNUM).unwrap_or(0);
    let (_, mut at) = load_range(elf, addr, VERNEED_SIZE as u64)
        .ok_or("DT_VERNEED outside the file")?;
    let mut budget = MAX_VERSIONS;
    for _ in 0..count {
        spend(&mut budget)?;
        let cnt = rd(d, add(at, 2)?, 2)?;
        let mut aux = add(at, us(rd(d, add(at, 8)?, 4)?)?)?;
        for _ in 0..cnt {
            spend(&mut budget)?;
            let name = us(rd(d, add(aux, 8)?, 4)?)?;
            if cstr_is(d, add(str_off, name)?, version) {
                return Ok(true);
            }
            match us(rd(d, add(aux, 12)?, 4)?)? {
                0 => break,
                next => aux = add(aux, next)?,
            }
        }
        match us(rd(d, add(at, 12)?, 4)?)? {
            0 => break,
            next => at = add(at, next)?,
        }
    }
    Ok(false)
}

/// Take one entry from the version walk `budget`; refuse when spent.
fn spend(budget: &mut usize) -> Result<(), String> {
    *budget = budget.checked_sub(1).ok_or_else(|| {
        format!("DT_VERNEED holds more than {} entries", MAX_VERSIONS)
    })?;
    Ok(())
}

/// Locate the DT_RELA table, refusing layouts this pass does not handle.
fn rela_table(d: &[u8], elf: &Elf, dy: &Dynamic) -> Result<Table, String> {
    if tag(dy, DT_RELR).is_some() {
        return Err("already has DT_RELR".into());
    }
    if tag(dy, DT_REL).is_some() {
        return Err("has DT_REL relocations (only RELA is handled)".into());
    }
    let addr = tag(dy, DT_RELA).ok_or("no DT_RELA relocations")?;
    let size = us(tag(dy, DT_RELASZ).unwrap_or(0))?;
    if tag(dy, DT_RELAENT) != Some(RELA_SIZE as u64) {
        return Err("DT_RELAENT is not 24".into());
    }
    if size == 0 || size % RELA_SIZE != 0 || addr % WORD != 0 {
        return Err("malformed DT_RELA/DT_RELASZ".into());
    }
    if jmprel_overlaps(dy, addr, size as u64) {
        return Err("the PLT relocations (DT_JMPREL) lie inside the \
                    DT_RELA table, which is rewritten"
            .into());
    }
    let (seg, off) = load_range(elf, addr, size as u64)
        .ok_or("DT_RELA lies outside the file-backed segments")?;
    if off as u64 % WORD != 0 {
        return Err("DT_RELA table is not word-aligned in the file".into());
    }
    let sec = rela_section(d, elf, addr, off, size)?;
    Ok(Table { off, addr, size, seg, sec })
}

/// True if the DT_JMPREL table `[DT_JMPREL, + DT_PLTRELSZ)` shares a
/// byte with the DT_RELA table `[addr, addr + size)`. Some linkers count
/// the PLT relocations in DT_RELASZ; rewriting the table in place would
/// then destroy them.
fn jmprel_overlaps(dy: &Dynamic, addr: u64, size: u64) -> bool {
    match (tag(dy, DT_JMPREL), tag(dy, DT_PLTRELSZ)) {
        (Some(j), Some(n)) if n > 0 => {
            j < addr.saturating_add(size) && addr < j.saturating_add(n)
        }
        _ => false,
    }
}

/// The section header matching the DT_RELA table exactly, if the file
/// has section headers.
fn rela_section(
    d: &[u8],
    elf: &Elf,
    addr: u64,
    off: usize,
    size: usize,
) -> Result<Option<usize>, String> {
    if elf.shdrs.is_empty() {
        return Ok(None);
    }
    let found = elf.shdrs.iter().enumerate().position(|(i, s)| {
        s.stype == SHT_RELA
            && s.offset == off as u64
            && s.size == size as u64
            && rd(d, elf.shdrs[i].at + 16, 8).ok() == Some(addr)
    });
    found
        .map(Some)
        .ok_or_else(|| "no RELA section header matches DT_RELA/DT_RELASZ".into())
}

/// Sort the DT_RELA entries into those RELR can encode and those that
/// stay RELA.
fn split_relocs(
    d: &[u8],
    elf: &Elf,
    t: &Table,
    rel: u64,
) -> Result<Split, String> {
    let mut split = Split { packed: Vec::new(), keep: Vec::new(), lead: 0 };
    let mut leading = true;
    for i in 0..t.size / RELA_SIZE {
        let at = t.off + i * RELA_SIZE;
        let raw = span(d, at as u64, RELA_SIZE as u64)?;
        let (r_off, info) = (rd(raw, 0, 8)?, rd(raw, 8, 8)?);
        if let Some(file_off) = packable(elf, r_off, info, rel) {
            let addend = rd(raw, 16, 8)?;
            split.packed.push(Packed { addr: r_off, addend, file_off });
            continue;
        }
        leading &= info & 0xffff_ffff == rel;
        split.lead += u64::from(leading);
        split.keep.extend_from_slice(raw);
    }
    if split.packed.is_empty() {
        return Err("no RELATIVE relocations RELR can encode".into());
    }
    Ok(split)
}

/// File offset of the word a relocation patches if RELR can encode it:
/// a RELATIVE type with no symbol on a word-aligned, file-backed word.
fn packable(elf: &Elf, r_off: u64, info: u64, rel: u64) -> Option<usize> {
    if info & 0xffff_ffff != rel || info >> 32 != 0 || r_off % WORD != 0 {
        return None;
    }
    load_range(elf, r_off, WORD).map(|(_, off)| off)
}

/// Sort the packed relocations by address and drop exact duplicates;
/// returns their addresses. Two relocations of one word with different
/// addends are refused.
fn sorted_offsets(packed: &mut Vec<Packed>) -> Result<Vec<u64>, String> {
    packed.sort_by_key(|p| p.addr);
    if packed
        .windows(2)
        .any(|w| w[0].addr == w[1].addr && w[0].addend != w[1].addend)
    {
        return Err("two RELATIVE relocations of one word disagree".into());
    }
    packed.dedup_by_key(|p| p.addr);
    Ok(packed.iter().map(|p| p.addr).collect())
}

/// Refuse when a packed word overlaps a relocation kept in RELA or
/// DT_JMPREL, the relocation table or `.dynamic`: those are rewritten
/// here or patched by other relocations.
fn check_targets(
    d: &[u8],
    elf: &Elf,
    dy: &Dynamic,
    t: &Table,
    split: &Split,
    offsets: &[u64],
) -> Result<(), String> {
    let mut others = rela_offsets(&split.keep, RELA_SIZE)?;
    others.extend(jmprel_offsets(d, elf, dy)?);
    if others.iter().any(|&r| overlaps(offsets, r, WORD)) {
        return Err("a RELATIVE word is also patched by another relocation".into());
    }
    let dyn_size = (dy.slots * DYN_SIZE) as u64;
    if overlaps(offsets, t.addr, t.size as u64) || overlaps(offsets, dy.addr, dyn_size)
    {
        return Err("a RELATIVE word lies in .rela.dyn or .dynamic".into());
    }
    Ok(())
}

/// The r_offset of each `entsize`-byte relocation entry in `raw`.
fn rela_offsets(raw: &[u8], entsize: usize) -> Result<Vec<u64>, String> {
    raw.chunks(entsize).map(|e| rd(e, 0, 8)).collect()
}

/// The r_offset of each DT_JMPREL (PLT) relocation.
fn jmprel_offsets(d: &[u8], elf: &Elf, dy: &Dynamic) -> Result<Vec<u64>, String> {
    let (addr, size) = match (tag(dy, DT_JMPREL), tag(dy, DT_PLTRELSZ)) {
        (Some(a), Some(s)) if s > 0 => (a, s),
        _ => return Ok(Vec::new()),
    };
    let entsize = if tag(dy, DT_PLTREL) == Some(DT_RELA) { RELA_SIZE } else { REL_SIZE };
    let (_, off) = load_range(elf, addr, size).ok_or("DT_JMPREL outside the file")?;
    rela_offsets(span(d, off as u64, size)?, entsize)
}

/// True if some word in sorted `offsets` overlaps `[lo, lo + len)`.
fn overlaps(offsets: &[u64], lo: u64, len: u64) -> bool {
    let i = offsets.partition_point(|&a| a.saturating_add(WORD) <= lo);
    offsets.get(i).map_or(false, |&a| a < lo.saturating_add(len))
}

// ---- RELR encoding ---------------------------------------------------

/// Encode sorted, unique, word-aligned addresses as RELR words: an
/// address word, then bitmap words for the 63 words after it, each
/// bitmap covering the next 63 (the lld algorithm).
fn encode_relr(offsets: &[u64]) -> Vec<u64> {
    let mut words = Vec::new();
    let mut i = 0;
    while i < offsets.len() {
        words.push(offsets[i]);
        let mut base = offsets[i] + WORD;
        i += 1;
        loop {
            let mut bitmap = 0u64;
            while let Some(d) = offsets.get(i).and_then(|&a| a.checked_sub(base)) {
                if d >= BITMAP_BITS * WORD {
                    break;
                }
                bitmap |= 1 << (d / WORD);
                i += 1;
            }
            if bitmap == 0 {
                break;
            }
            words.push((bitmap << 1) | 1);
            base += BITMAP_BITS * WORD;
        }
    }
    words
}

/// Decode RELR words back into the addresses they relocate.
fn decode_relr(words: &[u64]) -> Vec<u64> {
    let mut out = Vec::new();
    let mut next = 0u64;
    for &w in words {
        if w & 1 == 0 {
            out.push(w);
            next = w.wrapping_add(WORD);
            continue;
        }
        for bit in 0..BITMAP_BITS {
            if (w >> (bit + 1)) & 1 == 1 {
                out.push(next.wrapping_add(bit * WORD));
            }
        }
        next = next.wrapping_add(BITMAP_BITS * WORD);
    }
    out
}

// ---- Planning --------------------------------------------------------

/// The new `.dynamic` entries: RELA tags resized (or dropped when no
/// RELA entry remains), then DT_RELR, DT_RELRSZ and DT_RELRENT. Refused
/// when they and the terminating DT_NULL do not fit the array.
fn new_tags(
    dy: &Dynamic,
    t: &Table,
    split: &Split,
    words: usize,
) -> Result<Vec<(u64, u64)>, String> {
    let keep = split.keep.len() as u64;
    let mut tags = Vec::new();
    for &(k, v) in &dy.tags {
        match k {
            DT_RELA | DT_RELASZ | DT_RELAENT | DT_RELACOUNT if keep == 0 => {}
            DT_RELASZ => tags.push((k, keep)),
            DT_RELACOUNT => tags.push((k, split.lead)),
            _ => tags.push((k, v)),
        }
    }
    tags.push((DT_RELR, t.addr + keep));
    tags.push((DT_RELRSZ, words as u64 * WORD));
    tags.push((DT_RELRENT, WORD));
    if tags.len() + 1 > dy.slots {
        return Err(format!(
            "no room in .dynamic: {} entries and DT_NULL needed, {} slots",
            tags.len(),
            dy.slots
        ));
    }
    Ok(tags)
}

/// Plan the drain of the freed bytes: only when `.rela.dyn` ends its
/// PT_LOAD segment (so nothing else in it moves), nothing else lies in
/// the freed range, and at least one aligned page is free. Returns why
/// not otherwise.
fn plan_drain(d: &[u8], elf: &Elf, t: &Table, new_end: u64) -> Result<Drain, String> {
    let seg = elf.phdrs.get(t.seg).ok_or("segment vanished")?;
    let old_end = (t.off + t.size) as u64;
    if seg.offset.saturating_add(seg.filesz) != old_end {
        return Err(match follower(d, elf, t, old_end) {
            Some(n) => format!("{} follows .rela.dyn in its segment", n),
            None => "its segment continues after .rela.dyn".into(),
        });
    }
    if seg.memsz != seg.filesz {
        return Err("its segment has a zero-filled tail".into());
    }
    let end = content_end(elf);
    if d.len() as u64 > end {
        return Err(format!(
            "{} bytes of overlay data follow the last section, segment \
             and header table",
            d.len() as u64 - end
        ));
    }
    let next = next_content(elf, old_end, d.len() as u64);
    if let Some(n) = straddler(d, elf, t, new_end, next) {
        return Err(format!("{} lies in the freed range", n));
    }
    let align = shift_align(elf, next);
    let len = (next - new_end) / align * align;
    if len == 0 {
        return Err(format!("less than one {}-byte page is free", align));
    }
    Ok(Drain { cut: next - len, len, seg: t.seg, new_end })
}

/// File offset where the content the headers describe ends: the end of
/// the last section with file bytes, segment, header table or the ELF
/// header. Bytes after it are overlay data (an appended payload or
/// signature) that something may locate by its file offset.
fn content_end(elf: &Elf) -> u64 {
    let secs = elf
        .shdrs
        .iter()
        .filter(|s| s.stype != SHT_NOBITS)
        .map(|s| s.offset.saturating_add(s.size));
    let segs = elf.phdrs.iter().map(|p| p.offset.saturating_add(p.filesz));
    let tabs = [
        elf.eh.phoff.saturating_add((elf.eh.phnum * PHDR_SIZE) as u64),
        elf.eh.shoff.saturating_add((elf.eh.shnum * SHDR_SIZE) as u64),
    ];
    secs.chain(segs)
        .chain(tabs)
        .fold(EHDR_SIZE as u64, u64::max)
}

/// The name of the first section after `.rela.dyn` inside its segment.
fn follower(d: &[u8], elf: &Elf, t: &Table, old_end: u64) -> Option<String> {
    let seg = elf.phdrs.get(t.seg)?;
    let seg_end = seg.offset.saturating_add(seg.filesz);
    elf.shdrs
        .iter()
        .enumerate()
        .filter(|(_, s)| s.size > 0 && s.offset >= old_end && s.offset < seg_end)
        .min_by_key(|(_, s)| s.offset)
        .map(|(i, _)| sec_name(d, elf, i))
}

/// The file offset of the first content at or after `from`: a section
/// or segment start, a header table, or the end of the file.
fn next_content(elf: &Elf, from: u64, file_len: u64) -> u64 {
    let secs = elf
        .shdrs
        .iter()
        .filter(|s| s.stype != SHT_NOBITS && s.size > 0)
        .map(|s| s.offset);
    let segs = elf.phdrs.iter().filter(|p| p.filesz > 0).map(|p| p.offset);
    let tabs = [
        (elf.eh.shnum > 0).then_some(elf.eh.shoff),
        (elf.eh.phnum > 0).then_some(elf.eh.phoff),
    ];
    secs.chain(segs)
        .chain(tabs.into_iter().flatten())
        .filter(|&o| o >= from)
        .fold(file_len, u64::min)
}

/// The first section, segment or header table (other than `.rela.dyn`
/// and its segment) with file bytes inside `[lo, hi)`.
fn straddler(d: &[u8], elf: &Elf, t: &Table, lo: u64, hi: u64) -> Option<String> {
    let hit = |off: u64, len: u64| len > 0 && off < hi && off.saturating_add(len) > lo;
    for (i, s) in elf.shdrs.iter().enumerate() {
        if Some(i) != t.sec && s.stype != SHT_NOBITS && hit(s.offset, s.size) {
            return Some(sec_name(d, elf, i));
        }
    }
    for (i, p) in elf.phdrs.iter().enumerate() {
        if i != t.seg && hit(p.offset, p.filesz) {
            return Some(format!("program header {} (type {:#x})", i, p.ptype));
        }
    }
    let ph_len = (elf.eh.phnum * PHDR_SIZE) as u64;
    let sh_len = (elf.eh.shnum * SHDR_SIZE) as u64;
    if hit(elf.eh.phoff, ph_len) {
        return Some("the program header table".into());
    }
    if hit(elf.eh.shoff, sh_len) {
        return Some("the section header table".into());
    }
    None
}

/// The unit the drain must be a multiple of: the largest alignment of
/// any segment that moves, and at least one page.
fn shift_align(elf: &Elf, from: u64) -> u64 {
    elf.phdrs
        .iter()
        .filter(|p| p.filesz > 0 && p.offset >= from)
        .map(|p| p.align)
        .fold(PAGE, u64::max)
}

// ---- Rewriting -------------------------------------------------------

/// Write each packed relocation's addend into its word where the word
/// holds anything else (RELR uses the in-place value as the addend).
/// Returns how many words changed.
fn write_addends(out: &mut [u8], packed: &[Packed]) -> Result<usize, String> {
    let mut changed = 0;
    for p in packed {
        if rd(out, p.file_off, 8)? != p.addend {
            wr(out, p.file_off, 8, p.addend)?;
            changed += 1;
        }
    }
    Ok(changed)
}

/// Write `[kept RELA][RELR]` at the start of the old table and zero the
/// rest of it. Returns the file offset where the new tables end.
fn write_tables(
    out: &mut [u8],
    t: &Table,
    keep: &[u8],
    words: &[u64],
) -> Result<u64, String> {
    let relr_off = t.off + keep.len();
    let new_end = relr_off + words.len() * WORD as usize;
    let old_end = t.off + t.size;
    if new_end > old_end {
        return Err("RELR table does not fit the old .rela.dyn".into());
    }
    out.get_mut(t.off..relr_off)
        .ok_or("relocation table outside the file")?
        .copy_from_slice(keep);
    for (i, &w) in words.iter().enumerate() {
        wr(out, relr_off + i * WORD as usize, 8, w)?;
    }
    out.get_mut(new_end..old_end)
        .ok_or("relocation table outside the file")?
        .fill(0);
    Ok(new_end as u64)
}

/// Write the new `.dynamic` entries, padding every other slot with
/// DT_NULL.
fn write_dynamic(out: &mut [u8], dy: &Dynamic, tags: &[(u64, u64)]) -> Result<(), String> {
    for i in 0..dy.slots {
        let (k, v) = tags.get(i).copied().unwrap_or((DT_NULL, 0));
        wr(out, dy.off + i * DYN_SIZE, 8, k)?;
        wr(out, dy.off + i * DYN_SIZE + 8, 8, v)?;
    }
    Ok(())
}

/// Update the `.rela.dyn` section header: shrink it to the kept RELA
/// entries, or, when none remain, turn it into the `.relr.dyn` header.
/// Returns how the RELR table got its header (so far).
fn update_rela_header(
    out: &mut [u8],
    elf: &Elf,
    t: &Table,
    split: &Split,
    relr_size: u64,
) -> Result<String, String> {
    let sec = match t.sec.and_then(|i| elf.shdrs.get(i).map(|s| (i, s))) {
        Some(s) => s,
        None => return Ok("no section headers".into()),
    };
    if !split.keep.is_empty() {
        wr(out, sec.1.at + 32, 8, split.keep.len() as u64)?;
        return Ok("pending".into());
    }
    let at = sec.1.at;
    let flags = rd(out, at + 8, 8)? & !SHF_INFO_LINK;
    wr(out, at + 4, 4, u64::from(SHT_RELR))?;
    wr(out, at + 8, 8, flags | SHF_ALLOC)?;
    wr(out, at + 32, 8, relr_size)?;
    wr(out, at + 40, 4, 0)?;
    wr(out, at + 44, 4, 0)?;
    wr(out, at + 48, 8, WORD)?;
    wr(out, at + 56, 8, WORD)?;
    Ok(if rename_header(out, elf, sec.0)? {
        "its section header now describes .relr.dyn".into()
    } else {
        "its section header now describes the RELR table (name kept)".into()
    })
}

/// Name section `sec` `.relr.dyn`: point it at an existing string, or
/// overwrite its `.rela.dyn` string (same length) when no other section
/// name shares those bytes. Returns false if neither is possible.
fn rename_header(out: &mut [u8], elf: &Elf, sec: usize) -> Result<bool, String> {
    let st = match elf.shdrs.get(elf.eh.shstrndx) {
        Some(s) => s,
        None => return Ok(false),
    };
    let strs = span(out, st.offset, st.size)?;
    let at = elf.shdrs.get(sec).ok_or("section vanished")?.at;
    if let Some(p) = find_string(strs, RELR_NAME) {
        wr(out, at, 4, p as u64)?;
        return Ok(true);
    }
    let name = us(elf.shdrs[sec].name)?;
    if strs.get(name..name + RELA_NAME.len()) != Some(RELA_NAME) {
        return Ok(false);
    }
    if name_shared(strs, elf, sec, name) {
        return Ok(false);
    }
    let base = us(st.offset)? + name;
    let dst = out
        .get_mut(base..base + RELR_NAME.len())
        .ok_or("section name outside the file")?;
    dst.copy_from_slice(RELR_NAME);
    Ok(true)
}

/// True if a section other than `sec` has a name whose bytes overlap
/// the `.rela.dyn` string at `name` (string tables share suffixes).
fn name_shared(strs: &[u8], elf: &Elf, sec: usize, name: usize) -> bool {
    let end = name + RELA_NAME.len();
    elf.shdrs.iter().enumerate().any(|(j, s)| {
        let start = match usize::try_from(s.name) {
            Ok(v) if j != sec => v,
            _ => return false,
        };
        let len = strs
            .get(start..)
            .and_then(|t| t.iter().position(|&b| b == 0))
            .unwrap_or(0);
        start < end && start + len >= name
    })
}

/// Offset of `needle` (a NUL-terminated name) inside a string table.
fn find_string(strs: &[u8], needle: &[u8]) -> Option<usize> {
    strs.windows(needle.len()).position(|w| w == needle)
}

/// Remove the planned bytes: segments, sections and header tables
/// after them move down in the file by `len`; vaddrs stay. The segment
/// holding `.rela.dyn` now ends with the new tables.
fn apply_drain(out: &mut Vec<u8>, elf: &Elf, dr: &Drain) -> Result<(), String> {
    let next = dr.cut + dr.len;
    for (i, p) in elf.phdrs.iter().enumerate() {
        if i == dr.seg {
            let size = dr.new_end - p.offset;
            wr(out, p.at + 32, 8, size)?;
            wr(out, p.at + 40, 8, size)?;
        } else if p.offset >= next {
            wr(out, p.at + 8, 8, p.offset - dr.len)?;
        }
    }
    for s in &elf.shdrs {
        if s.offset >= next {
            wr(out, s.at + 24, 8, s.offset - dr.len)?;
        }
    }
    if elf.eh.shnum > 0 && elf.eh.shoff >= next {
        wr(out, 40, 8, elf.eh.shoff - dr.len)?;
    }
    if elf.eh.phoff >= next {
        wr(out, 32, 8, elf.eh.phoff - dr.len)?;
    }
    let (cut, end) = (us(dr.cut)?, us(next)?);
    if end > out.len() {
        return Err("drain past the end of the file".into());
    }
    out.drain(cut..end);
    Ok(())
}

/// Append a `.relr.dyn` section header for the RELR table at vaddr
/// `addr`, file offset `off`. The section header table must end the
/// file; `.shstrtab` gains the name when it lacks it, in place if it
/// sits right before the table, else as a copy at the end.
fn append_header(out: &mut Vec<u8>, addr: u64, off: u64, size: u64) -> Result<(), String> {
    let elf = parse(out)?;
    let n = elf.shdrs.len();
    if n == 0 || n + 1 >= SHN_LORESERVE {
        return Err("section header count cannot grow".into());
    }
    let shoff = us(elf.eh.shoff)?;
    let table = span(out, elf.eh.shoff, (n * SHDR_SIZE) as u64)?.to_vec();
    if shoff + table.len() != out.len() {
        return Err("the section header table does not end the file".into());
    }
    let st = elf.shdrs.get(elf.eh.shstrndx).ok_or("no section name table")?;
    let strs = span(out, st.offset, st.size)?.to_vec();
    out.truncate(shoff);
    let (name, st_off, st_size) = place_name(out, st, &strs)?;
    out.resize(out.len().next_multiple_of(WORD as usize), 0);
    let new_shoff = out.len();
    out.extend_from_slice(&table);
    out.extend_from_slice(&[0u8; SHDR_SIZE]);
    let st_at = new_shoff + elf.eh.shstrndx * SHDR_SIZE;
    wr(out, st_at + 24, 8, st_off)?;
    wr(out, st_at + 32, 8, st_size)?;
    let entry = [
        (0, 4, name),
        (4, 4, u64::from(SHT_RELR)),
        (8, 8, SHF_ALLOC),
        (16, 8, addr),
        (24, 8, off),
        (32, 8, size),
        (48, 8, WORD),
        (56, 8, WORD),
    ];
    let at = new_shoff + n * SHDR_SIZE;
    for (field, width, value) in entry {
        wr(out, at + field, width, value)?;
    }
    wr(out, 40, 8, new_shoff as u64)?;
    wr(out, 60, 2, (n + 1) as u64)
}

/// Find or add the `.relr.dyn` name for `append_header`. `out` ends
/// where the section header table began; `strs` is the old `.shstrtab`.
/// Returns (name offset, table file offset, table size).
fn place_name(out: &mut Vec<u8>, st: &Shdr, strs: &[u8]) -> Result<(u64, u64, u64), String> {
    if let Some(p) = find_string(strs, RELR_NAME) {
        return Ok((p as u64, st.offset, st.size));
    }
    let end = us(st.offset)? + strs.len();
    let grown = (strs.len() + RELR_NAME.len()) as u64;
    let tail_free = out.get(end..).map_or(false, |t| t.iter().all(|&b| b == 0));
    if tail_free {
        out.truncate(end);
        out.extend_from_slice(RELR_NAME);
        return Ok((strs.len() as u64, st.offset, grown));
    }
    let new_off = out.len() as u64;
    out.extend_from_slice(strs);
    out.extend_from_slice(RELR_NAME);
    Ok((strs.len() as u64, new_off, grown))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A dense run, a gap of more than 63 words, and a lone word encode
    /// to address and bitmap words that decode back exactly.
    #[test]
    fn relr_round_trip() {
        let mut offs: Vec<u64> = (0..100).map(|i| 0x1000 + i * 8).collect();
        offs.push(0x1000 + 100 * 8 + 70 * 8);
        offs.push(0x9000);
        let words = encode_relr(&offs);
        assert_eq!(words[0], 0x1000);
        assert_eq!(words[1], u64::MAX);
        assert_eq!(decode_relr(&words), offs);
    }

    /// Words exactly 63 apart share a bitmap; 64 apart need a new one.
    #[test]
    fn relr_bitmap_edges() {
        let offs = [0x2000, 0x2000 + 8 * 63, 0x2000 + 8 * 64];
        let words = encode_relr(&offs);
        assert_eq!(words, vec![0x2000, (1 << 62 << 1) | 1, 0b11]);
        assert_eq!(decode_relr(&words), offs);
    }

    /// An ELF header with `entry`, `phnum` program headers and the given
    /// section header fields.
    fn ehdr(entry: u64, phnum: usize, shoff: u64, shnum: usize, strndx: usize) -> Ehdr {
        Ehdr { etype: ET_DYN, entry, phoff: 64, shoff, phnum, shnum, shstrndx: strndx }
    }

    /// A program header of type `ptype` mapping `[0, size)` at vaddr 0.
    fn phdr(ptype: u32, size: u64) -> Phdr {
        Phdr {
            at: 64, ptype, offset: 0, vaddr: 0, filesz: size, memsz: size, align: PAGE,
        }
    }

    /// A `.dynamic` holding `tags`.
    fn dynamic(tags: Vec<(u64, u64)>) -> Dynamic {
        Dynamic { off: 0, addr: 0, slots: tags.len() + 1, tags }
    }

    /// A static-pie (DF_1_PIE) or a dynamic loader (entry point) without
    /// PT_INTERP relocates itself; a shared library (entry 0, no
    /// DF_1_PIE) and a dynamic PIE (PT_INTERP) do not.
    #[test]
    fn tells_self_relocating_images() {
        let elf = |entry, interp: bool| {
            let mut phdrs = vec![phdr(PT_LOAD, 0x1000)];
            if interp {
                phdrs.push(phdr(PT_INTERP, 0x1c));
            }
            Elf { eh: ehdr(entry, phdrs.len(), 0, 0, 0), phdrs, shdrs: Vec::new() }
        };
        let pie = dynamic(vec![(DT_FLAGS_1, DF_1_PIE | 1)]);
        let plain = dynamic(vec![(DT_FLAGS_1, 1)]);
        assert!(relocates_itself(&elf(0x1050, false), &pie));
        assert!(relocates_itself(&elf(0, false), &pie));
        assert!(relocates_itself(&elf(0x1050, false), &plain));
        assert!(!relocates_itself(&elf(0, false), &plain));
        assert!(!relocates_itself(&elf(0x1050, true), &pie));
    }

    /// Extended section or segment numbering is refused.
    #[test]
    fn refuses_extended_numbering() {
        assert!(check_numbering(&ehdr(0, 1, 0x2000, 0, 0)).is_err());
        assert!(check_numbering(&ehdr(0, PN_XNUM, 0, 0, 0)).is_err());
        assert!(check_numbering(&ehdr(0, 1, 0x2000, 3, SHN_XINDEX)).is_err());
        assert!(check_numbering(&ehdr(0, 1, 0x2000, 3, 2)).is_ok());
        assert!(check_numbering(&ehdr(0, 1, 0, 0, 0)).is_ok());
    }

    /// A DT_JMPREL table inside (or overlapping) DT_RELA is detected.
    #[test]
    fn detects_jmprel_inside_rela() {
        let dy = |j, n| dynamic(vec![(DT_JMPREL, j), (DT_PLTRELSZ, n)]);
        assert!(jmprel_overlaps(&dy(0x1048, 0x30), 0x1000, 0x90));
        assert!(jmprel_overlaps(&dy(0xff0, 0x18), 0x1000, 0x90));
        assert!(!jmprel_overlaps(&dy(0x1090, 0x30), 0x1000, 0x90));
        assert!(!jmprel_overlaps(&dy(0x1048, 0), 0x1000, 0x90));
    }

    /// The string compare reads at most the string and its NUL.
    #[test]
    fn compares_strings_within_bounds() {
        let d = b"GLIBC_ABI_DT_RELR\0GLIBC_ABI_DT_RELRX\0GLIBC";
        assert!(cstr_is(d, 0, GLIBC_RELR_VERSION));
        assert!(!cstr_is(d, 18, GLIBC_RELR_VERSION));
        assert!(!cstr_is(d, 37, b"GLIBC"));
        assert!(!cstr_is(d, usize::MAX, b"G"));
        assert_eq!(cstr(d, 37), None);
    }

    /// An image whose DT_VERNEED chain holds `entries` Verneed entries
    /// from 0x100; only the last has a Vernaux (right after it), naming
    /// `version`, which the string table at 0x40 starts with.
    fn verneed_image(entries: usize, version: &[u8]) -> (Vec<u8>, Elf, Dynamic) {
        let base = 0x100;
        let mut d = vec![0u8; base + (entries + 1) * VERNEED_SIZE];
        d[0x40..0x40 + version.len()].copy_from_slice(version);
        for i in 0..entries {
            let at = base + i * VERNEED_SIZE;
            let last = i + 1 == entries;
            d[at + 2] = u8::from(last); // vn_cnt
            d[at + 8] = if last { VERNEED_SIZE as u8 } else { 0 }; // vn_aux
            d[at + 12] = if last { 0 } else { VERNEED_SIZE as u8 }; // vn_next
        }
        let phdrs = vec![phdr(PT_LOAD, d.len() as u64)];
        let elf = Elf { eh: ehdr(0, 1, 0, 0, 0), phdrs, shdrs: Vec::new() };
        let tags = vec![(DT_VERNEED, base as u64), (DT_VERNEEDNUM, entries as u64)];
        (d, elf, dynamic(tags))
    }

    /// The version walk finds a version at the end of its chain, and
    /// refuses a chain longer than the shared budget.
    #[test]
    fn walks_version_needs_within_budget() {
        let (d, elf, dy) = verneed_image(3, GLIBC_RELR_VERSION);
        assert_eq!(needs_version(&d, &elf, &dy, 0x40, GLIBC_RELR_VERSION), Ok(true));
        assert_eq!(needs_version(&d, &elf, &dy, 0x40, b"GLIBC_2.2.5"), Ok(false));
        let (d, elf, dy) = verneed_image(MAX_VERSIONS + 1, GLIBC_RELR_VERSION);
        assert!(needs_version(&d, &elf, &dy, 0x40, GLIBC_RELR_VERSION).is_err());
    }
}
