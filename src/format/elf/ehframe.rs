//! `.eh_frame` / `.eh_frame_hdr` patching after dead code compaction.
//!
//! Every FDE names the code it describes through an encoded `pc_begin`
//! pointer (usually pc-relative), and `.eh_frame_hdr` holds a sorted
//! binary-search table of `(initial_location, fde_address)` pairs. When
//! .text is compacted, code moves by the per-interval shift while
//! everything after .text moves by the page-aligned shrink, so these
//! pointers go stale and C++ exceptions, backtraces and .NET NativeAOT
//! unwinding crash. This module re-points `pc_begin`, `pc_range`, CFA
//! advance deltas, personality and LSDA pointers; neutralises the FDEs
//! of removed functions (`pc_range = 0`); and rebuilds the
//! `.eh_frame_hdr` table without them. Like every ELF patcher it works
//! on ORIGINAL offsets and vaddrs, before `compact_text` drains the file.
//! Anything it cannot decode is left untouched rather than guessed at.

use crate::analysis::cfg::DeadBlock;
use crate::patch::relocs::{in_dead_range, shift_at, total_shift};
use crate::types::Section;
use std::collections::{HashMap, HashSet};

// ---- DW_EH_PE pointer encodings -----------------------------------

/// No value present.
const PE_OMIT: u8 = 0xff;
/// Value-format bits (low nibble).
const PE_FMT: u8 = 0x0f;
/// Application bits: how the stored value becomes an address.
const PE_APP: u8 = 0x70;
/// The value is the address of a slot holding the real pointer.
const PE_INDIRECT: u8 = 0x80;
/// Native-width absolute value (format and application).
const PE_ABSPTR: u8 = 0x00;
/// Variable-length unsigned value.
const PE_ULEB128: u8 = 0x01;
/// 2-byte unsigned value.
const PE_UDATA2: u8 = 0x02;
/// 4-byte unsigned value.
const PE_UDATA4: u8 = 0x03;
/// 8-byte unsigned value.
const PE_UDATA8: u8 = 0x04;
/// Variable-length signed value.
const PE_SLEB128: u8 = 0x09;
/// 2-byte signed value.
const PE_SDATA2: u8 = 0x0a;
/// 4-byte signed value.
const PE_SDATA4: u8 = 0x0b;
/// 8-byte signed value.
const PE_SDATA8: u8 = 0x0c;
/// Relative to the address of the field itself.
const PE_PCREL: u8 = 0x10;
/// Relative to a base (the .eh_frame_hdr start in the header).
const PE_DATAREL: u8 = 0x30;
/// Value preceded by padding to pointer alignment.
const PE_ALIGNED: u8 = 0x50;

// ---- Context --------------------------------------------------------

/// Address map plus ELF class and byte order shared by all steps.
struct Ctx<'a> {
    intervals: &'a [(u64, u64)],
    ts: u64,
    te: u64,
    is64: bool,
    be: bool,
}

impl<'a> Ctx<'a> {
    /// Build a context, reading class and byte order from `e_ident`.
    fn new(
        data: &[u8],
        intervals: &'a [(u64, u64)],
        ts: u64,
        te: u64,
    ) -> Self {
        Ctx {
            intervals,
            ts,
            te,
            is64: data.get(4) == Some(&2),
            be: data.get(5) == Some(&2),
        }
    }

    /// New vaddr of the byte at original vaddr `addr`.
    fn map(&self, addr: u64) -> u64 {
        let s = total_shift(addr, self.intervals, self.ts, self.te);
        addr.wrapping_sub(s)
    }

    /// New vaddr of an instruction boundary or exclusive code end: a
    /// boundary exactly at the .text end keeps the in-.text shift.
    fn map_end(&self, end: u64) -> u64 {
        if self.ts < end && end <= self.te {
            end - shift_at(end, self.intervals)
        } else {
            self.map(end)
        }
    }

    /// Truncate an address to the ELF class width.
    fn addr(&self, v: u64) -> u64 {
        if self.is64 { v } else { v & 0xffff_ffff }
    }
}

// ---- Byte and LEB128 helpers ----------------------------------------

/// Read an `n`-byte (1..=8) unsigned integer at `off`.
fn read_un(data: &[u8], off: usize, n: usize, be: bool) -> Option<u64> {
    let b = data.get(off..off.checked_add(n)?)?;
    let mut v = 0u64;
    for i in 0..n {
        let byte = if be { b[i] } else { b[n - 1 - i] };
        v = (v << 8) | byte as u64;
    }
    Some(v)
}

/// Write the low `n` bytes (1..=8) of `val` at `off`, if in bounds.
fn write_un(data: &mut [u8], off: usize, n: usize, val: u64, be: bool) {
    let end = match off.checked_add(n) {
        Some(e) if e <= data.len() => e,
        _ => return,
    };
    for (i, byte) in data[off..end].iter_mut().enumerate() {
        let sh = if be { 8 * (n - 1 - i) } else { 8 * i };
        *byte = (val >> sh) as u8;
    }
}

/// Decode a ULEB128 at `off` (not past `end`): (value, byte length).
fn read_uleb(data: &[u8], off: usize, end: usize) -> Option<(u64, usize)> {
    let mut val = 0u64;
    let mut i = off;
    while i < end && i - off < 10 {
        let b = *data.get(i)?;
        val |= ((b & 0x7f) as u64) << (7 * (i - off));
        i += 1;
        if b & 0x80 == 0 {
            return Some((val, i - off));
        }
    }
    None
}

/// Decode an SLEB128 at `off` (not past `end`): (value, byte length).
fn read_sleb(data: &[u8], off: usize, end: usize) -> Option<(i64, usize)> {
    let (val, n) = read_uleb(data, off, end)?;
    let bits = 7 * n as u32;
    let last = *data.get(off + n - 1)?;
    if bits < 64 && last & 0x40 != 0 {
        return Some(((val | (!0u64 << bits)) as i64, n));
    }
    Some((val as i64, n))
}

/// Byte length of the LEB128 at `off` (signedness does not matter).
fn leb_len(data: &[u8], off: usize, end: usize) -> Option<usize> {
    read_uleb(data, off, end).map(|(_, n)| n)
}

// ---- Encoded values ---------------------------------------------------

/// Byte width of a fixed-size value format; None for LEB128/unknown.
fn fixed_width(fmt: u8, is64: bool) -> Option<usize> {
    match fmt {
        PE_ABSPTR => Some(if is64 { 8 } else { 4 }),
        PE_UDATA2 | PE_SDATA2 => Some(2),
        PE_UDATA4 | PE_SDATA4 => Some(4),
        PE_UDATA8 | PE_SDATA8 => Some(8),
        _ => None,
    }
}

/// Value a reader gets back from the low `width` bytes of `v`.
fn extend(fmt: u8, v: u64, width: usize) -> u64 {
    match fmt {
        PE_SDATA2 => v as u16 as i16 as i64 as u64,
        PE_SDATA4 => v as u32 as i32 as i64 as u64,
        _ if width < 8 => v & ((1u64 << (8 * width)) - 1),
        _ => v,
    }
}

/// Decode a value of format `fmt` at `off`: (value, byte length).
fn read_value(
    data: &[u8],
    off: usize,
    end: usize,
    fmt: u8,
    cx: &Ctx,
) -> Option<(u64, usize)> {
    match fmt {
        PE_ULEB128 => read_uleb(data, off, end),
        PE_SLEB128 => {
            read_sleb(data, off, end).map(|(v, n)| (v as u64, n))
        }
        _ => {
            let w = fixed_width(fmt, cx.is64)?;
            if off.checked_add(w)? > end {
                return None;
            }
            let v = read_un(data, off, w, cx.be)?;
            Some((extend(fmt, v, w), w))
        }
    }
}

/// A DW_EH_PE-encoded field as found in the original file.
#[derive(Clone, Copy)]
struct EncPtr {
    /// File offset of the field.
    off: usize,
    /// Original vaddr of the field.
    vaddr: u64,
    /// DW_EH_PE encoding byte.
    enc: u8,
    /// Encoded length in bytes.
    len: usize,
    /// Stored value, sign-extended for the signed formats.
    raw: u64,
}

/// Original vaddr of file offset `off` inside section `sec`.
fn vaddr_of(sec: &Section, off: usize) -> u64 {
    sec.vaddr.wrapping_add((off as u64).wrapping_sub(sec.offset))
}

/// Read the field encoded as `enc` at `off` (bounded by `end`).
fn read_enc(
    data: &[u8],
    off: usize,
    end: usize,
    sec: &Section,
    enc: u8,
    cx: &Ctx,
) -> Option<EncPtr> {
    if enc == PE_OMIT || enc & PE_APP == PE_ALIGNED {
        return None;
    }
    let (raw, len) = read_value(data, off, end, enc & PE_FMT, cx)?;
    let vaddr = vaddr_of(sec, off);
    Some(EncPtr { off, vaddr, enc, len, raw })
}

/// Address designated by `raw` stored with `enc` in a field at `field`
/// (the slot address when DW_EH_PE_indirect is set). As in libgcc, a
/// zero value stays null whatever the application.
fn apply(
    enc: u8,
    raw: u64,
    field: u64,
    base: Option<u64>,
    cx: &Ctx,
) -> Option<u64> {
    if raw == 0 {
        return Some(0);
    }
    let a = match enc & PE_APP {
        PE_ABSPTR => raw,
        PE_PCREL => field.wrapping_add(raw),
        PE_DATAREL => base?.wrapping_add(raw),
        _ => return None,
    };
    Some(cx.addr(a))
}

/// Value to store in `slot` so that, once the slot sits at its new
/// vaddr (`new_base` for datarel), it designates `target`. Verified by
/// decoding it back; None if it does not fit the slot's format.
fn encode(
    slot: &EncPtr,
    target: u64,
    new_base: Option<u64>,
    cx: &Ctx,
) -> Option<u64> {
    let field = cx.map(slot.vaddr);
    let target = cx.addr(target);
    let raw = match slot.enc & PE_APP {
        PE_ABSPTR => target,
        PE_PCREL => target.wrapping_sub(field),
        PE_DATAREL => target.wrapping_sub(new_base?),
        _ => return None,
    };
    let fmt = slot.enc & PE_FMT;
    let stored = match fixed_width(fmt, cx.is64) {
        Some(w) if w == slot.len => extend(fmt, raw, w),
        // LEB128 fields cannot be resized in place.
        None if raw == slot.raw => raw,
        _ => return None,
    };
    let back = apply(slot.enc, stored, field, new_base, cx)?;
    (back == target).then_some(stored)
}

// ---- Planned stores ---------------------------------------------------

/// A planned in-place store: (file offset, byte width, value).
type Store = (usize, usize, u64);

/// Plan re-pointing `slot` at `target`; adds a store only when the
/// bytes change. False if the new value cannot be encoded.
fn plan_ptr(
    st: &mut Vec<Store>,
    slot: &EncPtr,
    target: u64,
    new_base: Option<u64>,
    cx: &Ctx,
) -> bool {
    match encode(slot, target, new_base, cx) {
        Some(v) if v == slot.raw => true,
        Some(v) => {
            st.push((slot.off, slot.len, v));
            true
        }
        None => false,
    }
}

/// Plan storing plain value `v` (no application) into `slot`.
fn plan_value(st: &mut Vec<Store>, slot: &EncPtr, v: u64, cx: &Ctx) -> bool {
    if v == slot.raw {
        return true;
    }
    let fmt = slot.enc & PE_FMT;
    match fixed_width(fmt, cx.is64) {
        Some(w) if w == slot.len && extend(fmt, v, w) == v => {
            st.push((slot.off, w, v));
            true
        }
        _ => false,
    }
}

/// Plan re-pointing a stand-alone pointer at its target's new address;
/// `base` is the (old, new) datarel base, if any. Null stays null.
fn plan_target(
    st: &mut Vec<Store>,
    p: &EncPtr,
    base: Option<(u64, u64)>,
    cx: &Ctx,
) -> bool {
    let old_base = base.map(|b| b.0);
    match apply(p.enc, p.raw, p.vaddr, old_base, cx) {
        Some(0) => true,
        Some(t) => plan_ptr(st, p, cx.map(t), base.map(|b| b.1), cx),
        None => false,
    }
}

/// Apply planned stores.
fn commit(data: &mut [u8], st: &[Store], be: bool) {
    for &(off, len, v) in st {
        write_un(data, off, len, v, be);
    }
}

// ---- .eh_frame parsing ------------------------------------------------

/// Fields of a CIE needed to decode and patch its FDEs.
#[derive(Clone, Copy)]
struct Cie {
    /// Encoding of FDE pc_begin / pc_range ('R'; absptr by default).
    fde_enc: u8,
    /// Encoding of the FDE LSDA pointer ('L'; omitted by default).
    lsda_enc: u8,
    /// FDEs carry augmentation data with a length prefix ('z').
    has_aug: bool,
    /// Code alignment factor scaling CFA advance deltas.
    code_align: u64,
}

/// An FDE's decoded fields, at original offsets.
struct Fde {
    /// Original vaddr of the record (what .eh_frame_hdr points at).
    rec_vaddr: u64,
    /// The pc_begin field.
    pc_begin: EncPtr,
    /// Original start address of the described code.
    begin: u64,
    /// The pc_range field (value format only, no application).
    pc_range: EncPtr,
    /// The LSDA pointer field, if the CIE declares one.
    lsda: Option<EncPtr>,
    /// File offset of the first CFA instruction.
    cfa: usize,
    /// File offset just past the record.
    end: usize,
    /// The CIE this FDE belongs to.
    cie: Cie,
}

/// A parsed .eh_frame item that may need patching.
enum Record {
    /// A CIE's personality routine pointer.
    Personality(EncPtr),
    /// A frame description entry.
    Fde(Fde),
}

/// Header of one .eh_frame record.
struct RecHdr {
    /// File offset of the CIE id / CIE pointer field.
    id_off: usize,
    /// CIE id (0) or CIE pointer (distance back to the CIE).
    id: u64,
    /// File offset just past the record.
    end: usize,
}

/// Parse the record header at `p`: (extended) length, CIE id/pointer.
/// None at the zero terminator or on a length running past `limit`.
/// The id stays 4 bytes after an extended length, as in the LSB.
fn rec_header(data: &[u8], p: usize, limit: usize, be: bool) -> Option<RecHdr> {
    let len = read_un(data, p, 4, be)?;
    if len == 0 {
        return None;
    }
    let (len, id_off) = if len == 0xffff_ffff {
        (read_un(data, p + 4, 8, be)?, p + 12)
    } else {
        (len, p + 4)
    };
    let end = id_off.checked_add(usize::try_from(len).ok()?)?;
    if len < 4 || end > limit {
        return None;
    }
    let id = read_un(data, id_off, 4, be)?;
    Some(RecHdr { id_off, id, end })
}

/// Byte at `q` if it lies before `end`.
fn byte_at(data: &[u8], q: usize, end: usize) -> Option<u8> {
    if q < end { data.get(q).copied() } else { None }
}

/// Parse a CIE body at `p` (just past the CIE id). Returns the CIE and
/// its personality field; None if it uses anything not understood.
fn parse_cie(
    data: &[u8],
    p: usize,
    end: usize,
    sec: &Section,
    cx: &Ctx,
) -> Option<(Cie, Option<EncPtr>)> {
    let version = byte_at(data, p, end)?;
    if !matches!(version, 1 | 3 | 4) {
        return None;
    }
    let aug_off = p + 1;
    let nul = data.get(aug_off..end)?.iter().position(|&b| b == 0)?;
    let aug = &data[aug_off..aug_off + nul];
    let mut q = aug_off + nul + 1;
    if aug.starts_with(b"eh") {
        q += if cx.is64 { 8 } else { 4 };
    }
    if version == 4 {
        q += 2; // address_size, segment_selector_size
    }
    let (code_align, n) = read_uleb(data, q, end)?;
    q += n;
    q += leb_len(data, q, end)?; // data alignment factor
    q += if version == 1 { 1 } else { leb_len(data, q, end)? };
    let mut cie = Cie {
        fde_enc: PE_ABSPTR,
        lsda_enc: PE_OMIT,
        has_aug: false,
        code_align,
    };
    match aug.first() {
        None => Some((cie, None)),
        Some(b'z') => {
            cie.has_aug = true;
            let pers = parse_aug(data, q, end, &aug[1..], sec, &mut cie, cx)?;
            Some((cie, pers))
        }
        _ if aug == b"eh" => Some((cie, None)),
        _ => None,
    }
}

/// Walk 'z' augmentation data for the letters `chars` (after the 'z'),
/// filling the CIE encodings. Returns the personality field, if any.
fn parse_aug(
    data: &[u8],
    q: usize,
    end: usize,
    chars: &[u8],
    sec: &Section,
    cie: &mut Cie,
    cx: &Ctx,
) -> Option<Option<EncPtr>> {
    let (len, n) = read_uleb(data, q, end)?;
    let mut q = q + n;
    let aend = q.checked_add(usize::try_from(len).ok()?)?;
    if aend > end {
        return None;
    }
    let mut pers = None;
    for (i, &c) in chars.iter().enumerate() {
        match c {
            b'R' => cie.fde_enc = byte_at(data, q, aend)?,
            b'L' => cie.lsda_enc = byte_at(data, q, aend)?,
            b'P' => {
                let enc = byte_at(data, q, aend)?;
                let p = read_enc(data, q + 1, aend, sec, enc, cx)?;
                q += p.len;
                pers = Some(p);
            }
            b'S' | b'B' | b'G' => continue,
            // Unknown letter: the rest is skippable only if nothing we
            // need comes after it.
            _ if chars[i..].iter().any(|c| b"RLP".contains(c)) => {
                return None;
            }
            _ => break,
        }
        q += 1;
    }
    Some(pers)
}

/// Parse an FDE body at `p` (just past the CIE pointer); `rec` is the
/// record's file offset.
fn parse_fde(
    data: &[u8],
    rec: usize,
    p: usize,
    end: usize,
    sec: &Section,
    cie: Cie,
    cx: &Ctx,
) -> Option<Fde> {
    if cie.fde_enc & PE_INDIRECT != 0 {
        return None;
    }
    let pc_begin = read_enc(data, p, end, sec, cie.fde_enc, cx)?;
    let begin =
        apply(cie.fde_enc, pc_begin.raw, pc_begin.vaddr, None, cx)?;
    let mut q = p + pc_begin.len;
    let pc_range = read_enc(data, q, end, sec, cie.fde_enc & PE_FMT, cx)?;
    q += pc_range.len;
    let mut lsda = None;
    if cie.has_aug {
        let (len, n) = read_uleb(data, q, end)?;
        q += n;
        let aend = q.checked_add(usize::try_from(len).ok()?)?;
        if aend > end {
            return None;
        }
        if cie.lsda_enc != PE_OMIT {
            lsda = Some(read_enc(data, q, aend, sec, cie.lsda_enc, cx)?);
        }
        q = aend;
    }
    let rec_vaddr = vaddr_of(sec, rec);
    Some(Fde {
        rec_vaddr, pc_begin, begin, pc_range, lsda, cfa: q, end, cie,
    })
}

/// Parse every record of `.eh_frame` section `sec` up to the zero
/// terminator. Stops at a malformed length; records it cannot decode
/// are skipped (and so left untouched).
fn parse_eh_frame(data: &[u8], sec: &Section, cx: &Ctx) -> Vec<Record> {
    let start = sec.offset as usize;
    let limit = start.saturating_add(sec.size as usize).min(data.len());
    let mut cies: HashMap<usize, Option<Cie>> = HashMap::new();
    let mut out = Vec::new();
    let mut p = start;
    while p + 4 <= limit {
        let h = match rec_header(data, p, limit, cx.be) {
            Some(h) => h,
            None => break,
        };
        if h.id == 0 {
            let parsed = parse_cie(data, h.id_off + 4, h.end, sec, cx);
            if let Some((_, Some(pers))) = parsed {
                out.push(Record::Personality(pers));
            }
            cies.insert(p, parsed.map(|(c, _)| c));
        } else if let Some(cie) =
            cie_for(data, &h, start, limit, sec, cx, &mut cies)
        {
            let body = h.id_off + 4;
            if let Some(f) = parse_fde(data, p, body, h.end, sec, cie, cx) {
                out.push(Record::Fde(f));
            }
        }
        p = h.end;
    }
    out
}

/// The CIE an FDE's CIE pointer designates, parsed on first use.
fn cie_for(
    data: &[u8],
    h: &RecHdr,
    start: usize,
    limit: usize,
    sec: &Section,
    cx: &Ctx,
    cies: &mut HashMap<usize, Option<Cie>>,
) -> Option<Cie> {
    let at = h.id_off.checked_sub(usize::try_from(h.id).ok()?)?;
    if at < start {
        return None;
    }
    if let Some(c) = cies.get(&at) {
        return *c;
    }
    let c = rec_header(data, at, limit, cx.be)
        .filter(|ch| ch.id == 0)
        .and_then(|ch| parse_cie(data, ch.id_off + 4, ch.end, sec, cx))
        .map(|(c, _)| c);
    cies.insert(at, c);
    c
}

// ---- .eh_frame patching -----------------------------------------------

/// Patch .eh_frame and .eh_frame_hdr for the compaction described by
/// `intervals`. Runs before `compact_text`, on original offsets.
pub fn patch_eh_frame(
    data: &mut [u8],
    sections: &[Section],
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
) {
    if intervals.is_empty() {
        return;
    }
    let cx = Ctx::new(data, intervals, ts, te);
    let mut fdes = FdeSets::default();
    if let Some(sec) = sections.iter().find(|s| s.name == ".eh_frame") {
        for rec in parse_eh_frame(data, sec, &cx) {
            match rec {
                Record::Personality(p) => {
                    let mut st = Vec::new();
                    if plan_target(&mut st, &p, None, &cx) {
                        commit(data, &st, cx.be);
                    }
                }
                Record::Fde(f) => {
                    if f.begin != 0 && !fde_dead(&f, &cx) {
                        fdes.live.insert(f.rec_vaddr);
                    }
                    if patch_fde(data, &f, &cx) {
                        fdes.gone.insert(f.rec_vaddr);
                    }
                }
            }
        }
    }
    if let Some(sec) = sections.iter().find(|s| s.name == ".eh_frame_hdr") {
        patch_hdr(data, sec, &fdes, &cx);
    }
}

/// Record addresses of the FDEs `patch_eh_frame` decoded, by fate.
#[derive(Default)]
struct FdeSets {
    /// FDEs neutralised (their code was removed).
    gone: HashSet<u64>,
    /// FDEs describing code that stays.
    live: HashSet<u64>,
}

impl FdeSets {
    /// True if the search-table row `(loc, fde)` stays: its FDE was not
    /// neutralised, and it describes live code or its code is not in a
    /// removed range (rows of FDEs that were not decoded).
    fn keeps(&self, loc: u64, fde: u64, cx: &Ctx) -> bool {
        !self.gone.contains(&fde)
            && (self.live.contains(&fde) || !in_dead_range(loc, cx.intervals))
    }
}

/// True if the whole code range of `f` lies in one removed interval.
/// Its start alone is not enough: absorbing the padding next to a
/// removed function can swallow the leading NOPs of a live one.
fn fde_dead(f: &Fde, cx: &Ctx) -> bool {
    let end = f.begin.saturating_add(f.pc_range.raw);
    cx.intervals
        .iter()
        .any(|&(s, e)| s <= f.begin && f.begin < e && end <= e)
}

/// Patch one FDE: a removed function gets `pc_range = 0` (its pc_begin
/// still mapped consistently); a live one gets its new start, length,
/// LSDA and CFA row spacing. All-or-nothing: nothing is written unless
/// every field can be encoded (`unwind_safe_intervals` keeps whole the
/// live functions whose CFA program cannot be re-spaced). Returns true
/// when the FDE was neutralised.
fn patch_fde(data: &mut [u8], f: &Fde, cx: &Ctx) -> bool {
    if f.begin == 0 {
        return false; // discarded by the linker
    }
    let dead = fde_dead(f, cx);
    let mut st = Vec::new();
    let body = if dead {
        plan_value(&mut st, &f.pc_range, 0, cx)
    } else {
        plan_shrink(data, f, cx).map(|s| st.extend(s)).is_some()
    };
    let ok = body
        && plan_ptr(&mut st, &f.pc_begin, cx.map(f.begin), None, cx)
        && f.lsda.map_or(true, |l| plan_target(&mut st, &l, None, cx));
    if ok {
        commit(data, &st, cx.be);
    }
    ok && dead
}

/// Stores giving a live FDE its new `pc_range` and re-spaced CFA
/// program; empty when its code keeps its length (it only moves).
/// None if either cannot be encoded.
fn plan_shrink(data: &[u8], f: &Fde, cx: &Ctx) -> Option<Vec<Store>> {
    let old_range = f.pc_range.raw;
    let end = f.begin.wrapping_add(old_range);
    let new_range =
        cx.map_end(end).wrapping_sub(cx.map(f.begin)).min(old_range);
    if new_range == old_range {
        return Some(Vec::new());
    }
    let mut st = Vec::new();
    if !plan_value(&mut st, &f.pc_range, new_range, cx) {
        return None;
    }
    st.extend(plan_cfa(data, f, cx)?);
    Some(st)
}

/// The compaction `intervals` narrowed so that every live function's
/// FDE can follow it. A live function whose range would shrink while
/// its new `pc_range` or re-spaced CFA program cannot be encoded
/// (DW_CFA_set_loc, an unknown opcode, a shift that is not a multiple of
/// the code alignment factor) keeps all its bytes: its range is cut out
/// of the intervals, so its dead blocks stay and it moves as a whole,
/// needing only a new `pc_begin`. The pieces left keep a multiple of
/// `align` bytes. Repeats until no such FDE is left; each round makes at
/// least one more FDE whole, so it ends.
pub fn unwind_safe_intervals(
    data: &[u8],
    sections: &[Section],
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
    align: u64,
) -> Vec<(u64, u64)> {
    let fdes = code_fdes(data, sections);
    let mut ivs = intervals.to_vec();
    for _ in 0..=fdes.len() {
        let stuck = stuck_ranges(data, &fdes, &Ctx::new(data, &ivs, ts, te));
        if stuck.is_empty() {
            break;
        }
        for r in stuck {
            ivs = cut_range(&ivs, r, align.max(1));
        }
    }
    ivs
}

/// The decodable FDEs of `.eh_frame` that describe code (pc_begin not 0).
fn code_fdes(data: &[u8], sections: &[Section]) -> Vec<Fde> {
    let sec = match sections.iter().find(|s| s.name == ".eh_frame") {
        Some(s) => s,
        None => return Vec::new(),
    };
    let cx = Ctx::new(data, &[], 0, 0);
    parse_eh_frame(data, sec, &cx)
        .into_iter()
        .filter_map(|r| match r {
            Record::Fde(f) if f.begin != 0 => Some(f),
            _ => None,
        })
        .collect()
}

/// Code ranges `[begin, end)` of the live FDEs among `fdes` that could
/// not follow the compaction described by `cx`.
fn stuck_ranges(data: &[u8], fdes: &[Fde], cx: &Ctx) -> Vec<(u64, u64)> {
    fdes.iter()
        .filter(|f| !fde_dead(f, cx) && plan_shrink(data, f, cx).is_none())
        .map(|f| (f.begin, f.begin.saturating_add(f.pc_range.raw)))
        .collect()
}

/// Remove `[lo, hi)` from the sorted `intervals`. A piece left on either
/// side is shortened to a multiple of `align` bytes from the end it
/// keeps, so it removes less, never more.
fn cut_range(intervals: &[(u64, u64)], (lo, hi): (u64, u64), align: u64) -> Vec<(u64, u64)> {
    let mut out = Vec::with_capacity(intervals.len() + 1);
    for &(s, e) in intervals {
        if e <= lo || s >= hi {
            out.push((s, e));
            continue;
        }
        if s < lo {
            out.push((s, s + (lo - s) / align * align));
        }
        if hi < e {
            out.push((e - (e - hi) / align * align, e));
        }
    }
    out.retain(|&(s, e)| s < e);
    out
}

/// Re-space the CFA advance instructions of a live function that lost
/// internal dead blocks, so every row still starts at its instruction.
/// None (program left as is) on an opcode it does not understand.
fn plan_cfa(data: &[u8], f: &Fde, cx: &Ctx) -> Option<Vec<Store>> {
    let caf = f.cie.code_align;
    if caf == 0 {
        return None;
    }
    let mut st = Vec::new();
    let (mut p, mut loc) = (f.cfa, f.begin);
    while p < f.end {
        let op = *data.get(p)?;
        let width = match op {
            0x40..=0x7f => 0,
            0x02 => 1,
            0x03 => 2,
            0x04 => 4,
            0x1d => 8, // DW_CFA_MIPS_advance_loc8
            _ => {
                p = skip_cfa_op(data, p, f.end)?;
                continue;
            }
        };
        if p + 1 + width > f.end {
            return None;
        }
        let delta = if width == 0 {
            (op & 0x3f) as u64
        } else {
            read_un(data, p + 1, width, cx.be)?
        };
        let next = loc.checked_add(delta.checked_mul(caf)?)?;
        let moved = cx.map_end(next).checked_sub(cx.map_end(loc))?;
        let nd = moved / caf;
        if moved % caf != 0 || nd > delta {
            return None;
        }
        if nd != delta {
            st.push(if width == 0 {
                (p, 1, 0x40 | nd)
            } else {
                (p + 1, width, nd)
            });
        }
        loc = next;
        p += 1 + width;
    }
    Some(st)
}

/// Offset just past the non-advance CFA instruction at `p`; None for
/// DW_CFA_set_loc and unknown opcodes.
fn skip_cfa_op(data: &[u8], p: usize, end: usize) -> Option<usize> {
    let op = *data.get(p)?;
    // Operand kinds: L = LEB128, B = LEB128 length + block.
    let operands: &[u8] = match op {
        0x80..=0xbf => b"L",
        0xc0..=0xff | 0x00 | 0x0a | 0x0b | 0x2c | 0x2d => b"",
        0x06 | 0x07 | 0x08 | 0x0d | 0x0e | 0x13 | 0x2e => b"L",
        0x05 | 0x09 | 0x0c | 0x11 | 0x12 | 0x14 | 0x15 | 0x2f => b"LL",
        0x0f => b"B",
        0x10 | 0x16 => b"LB",
        _ => return None,
    };
    let mut q = p + 1;
    for &k in operands {
        if k == b'B' {
            let (n, k) = read_uleb(data, q, end)?;
            q = q.checked_add(k)?.checked_add(usize::try_from(n).ok()?)?;
        } else {
            q += leb_len(data, q, end)?;
        }
    }
    (q <= end).then_some(q)
}

// ---- .eh_frame_hdr ----------------------------------------------------

/// One search-table row: (initial location, FDE address), as addresses.
type Row = (u64, u64);

/// Patch .eh_frame_hdr: re-point eh_frame_ptr, then rebuild the search
/// table without the rows of removed code (see `FdeSets::keeps`),
/// re-sorted by new initial location. Datarel values are relative to
/// the start of .eh_frame_hdr.
fn patch_hdr(data: &mut [u8], sec: &Section, fdes: &FdeSets, cx: &Ctx) {
    let start = sec.offset as usize;
    let end = start.saturating_add(sec.size as usize).min(data.len());
    let h = match data.get(start..start + 4) {
        Some(h) if start + 4 <= end && h[0] == 1 => [h[1], h[2], h[3]],
        _ => return,
    };
    let (ptr_enc, cnt_enc, tbl_enc) = (h[0], h[1], h[2]);
    let base = (sec.vaddr, cx.map(sec.vaddr));
    let mut q = start + 4;
    if ptr_enc != PE_OMIT {
        let ep = match read_enc(data, q, end, sec, ptr_enc, cx) {
            Some(p) => p,
            None => return,
        };
        q += ep.len;
        let mut st = Vec::new();
        if plan_target(&mut st, &ep, Some(base), cx) {
            commit(data, &st, cx.be);
        }
    }
    if cnt_enc == PE_OMIT || cnt_enc & (PE_APP | PE_INDIRECT) != 0 {
        return;
    }
    let cnt = match read_enc(data, q, end, sec, cnt_enc, cx) {
        Some(c) => c,
        None => return,
    };
    let tbl = q + cnt.len;
    let rows =
        match read_table(data, sec, tbl, end, cnt.raw, tbl_enc, base.0, cx) {
            Some(r) => r,
            None => return,
        };
    let st = plan_table(&rows, &cnt, tbl, tbl_enc, sec, fdes, base.1, cx);
    if let Some(st) = st {
        commit(data, &st, cx.be);
    }
}

/// Decode `count` search-table rows at `off`; None if any row (or the
/// table encoding) cannot be decoded.
fn read_table(
    data: &[u8],
    sec: &Section,
    off: usize,
    end: usize,
    count: u64,
    enc: u8,
    base: u64,
    cx: &Ctx,
) -> Option<Vec<Row>> {
    if enc == PE_OMIT || enc & PE_INDIRECT != 0 {
        return None;
    }
    let w = fixed_width(enc & PE_FMT, cx.is64)?;
    let n = usize::try_from(count).ok()?;
    if n.checked_mul(2 * w)? > end.checked_sub(off)? {
        return None;
    }
    (0..n)
        .map(|i| {
            let at = off + 2 * w * i;
            let a = read_enc(data, at, end, sec, enc, cx)?;
            let b = read_enc(data, at + w, end, sec, enc, cx)?;
            let loc = apply(enc, a.raw, a.vaddr, Some(base), cx)?;
            let fde = apply(enc, b.raw, b.vaddr, Some(base), cx)?;
            Some((loc, fde))
        })
        .collect()
}

/// Plan the rebuilt table: drop rows of removed code, map the rest,
/// sort, store them from `off`, zero the vacated tail and store the new
/// count. None (table left as is) if any value cannot be encoded.
fn plan_table(
    rows: &[Row],
    cnt: &EncPtr,
    off: usize,
    enc: u8,
    sec: &Section,
    fdes: &FdeSets,
    new_base: u64,
    cx: &Ctx,
) -> Option<Vec<Store>> {
    let w = fixed_width(enc & PE_FMT, cx.is64)?;
    let mut kept: Vec<Row> = rows
        .iter()
        .filter(|&&(loc, fde)| fdes.keeps(loc, fde, cx))
        .map(|&(loc, fde)| (cx.map(loc), cx.map(fde)))
        .collect();
    kept.sort_unstable();
    let mut st = Vec::new();
    for (i, &(loc, fde)) in kept.iter().enumerate() {
        for (k, target) in [(0, loc), (w, fde)] {
            let at = off + 2 * w * i + k;
            let slot = EncPtr {
                off: at, vaddr: vaddr_of(sec, at), enc, len: w, raw: 0,
            };
            st.push((at, w, encode(&slot, target, Some(new_base), cx)?));
        }
    }
    for i in kept.len()..rows.len() {
        st.push((off + 2 * w * i, w, 0));
        st.push((off + 2 * w * i + w, w, 0));
    }
    plan_value(&mut st, cnt, kept.len() as u64, cx).then_some(st)
}

// ---- Read-only accessors ------------------------------------------------

/// Code ranges `(pc_begin, pc_range)` of the FDEs in `.eh_frame`, in
/// record order. FDEs the linker discarded (`pc_begin` 0), FDEs that
/// describe no code (`pc_range` 0, e.g. neutralised by an earlier trim
/// run) and records the parser cannot decode are left out.
pub fn fde_ranges(data: &[u8], sections: &[Section]) -> Vec<(u64, u64)> {
    let sec = match sections.iter().find(|s| s.name == ".eh_frame") {
        Some(s) => s,
        None => return Vec::new(),
    };
    let cx = Ctx::new(data, &[], 0, 0);
    parse_eh_frame(data, sec, &cx)
        .into_iter()
        .filter_map(|r| match r {
            Record::Fde(f) if f.begin != 0 && f.pc_range.raw != 0 => {
                Some((f.begin, f.pc_range.raw))
            }
            _ => None,
        })
        .collect()
}

/// Code addresses of the personality routines named by the CIEs of
/// `.eh_frame`. The unwinder calls them through these pointers only.
pub fn personality_targets(data: &[u8], sections: &[Section]) -> Vec<u64> {
    let sec = match sections.iter().find(|s| s.name == ".eh_frame") {
        Some(s) => s,
        None => return Vec::new(),
    };
    let cx = Ctx::new(data, &[], 0, 0);
    parse_eh_frame(data, sec, &cx)
        .into_iter()
        .filter_map(|r| match r {
            Record::Personality(p) => {
                personality_target(data, sections, &p, &cx)
            }
            _ => None,
        })
        .collect()
}

/// LSDA addresses named by the FDEs of `.eh_frame`, as
/// `(pc_begin, lsda)` in record order. FDEs the linker discarded
/// (`pc_begin` 0) and FDEs without an LSDA or with a null one are left
/// out. `Err(pc_begin)` for the first FDE whose LSDA pointer cannot be
/// located: DW_EH_PE_indirect (the LSDA address sits in a slot) or an
/// application that does not resolve without a base. Callers needing
/// every LSDA must then give up rather than miss it.
pub fn fde_lsdas(data: &[u8], sections: &[Section]) -> Result<Vec<(u64, u64)>, u64> {
    let sec = match sections.iter().find(|s| s.name == ".eh_frame") {
        Some(s) => s,
        None => return Ok(Vec::new()),
    };
    let cx = Ctx::new(data, &[], 0, 0);
    let mut out = Vec::new();
    for r in parse_eh_frame(data, sec, &cx) {
        let f = match r {
            Record::Fde(f) if f.begin != 0 => f,
            _ => continue,
        };
        let Some(l) = f.lsda else { continue };
        if l.enc & PE_INDIRECT != 0 && l.raw != 0 {
            return Err(f.begin);
        }
        match apply(l.enc, l.raw, l.vaddr, None, &cx) {
            Some(0) => {}
            Some(a) => out.push((f.begin, a)),
            None => return Err(f.begin),
        }
    }
    Ok(out)
}

/// Address designated by personality field `p`. A DW_EH_PE_indirect
/// pointer designates a slot: its in-place value is returned (None when
/// the slot is null or outside the file).
fn personality_target(
    data: &[u8],
    sections: &[Section],
    p: &EncPtr,
    cx: &Ctx,
) -> Option<u64> {
    let a = apply(p.enc, p.raw, p.vaddr, None, cx).filter(|&a| a != 0)?;
    if p.enc & PE_INDIRECT == 0 {
        return Some(a);
    }
    let off = crate::types::vaddr_to_offset(a, sections)?;
    let width = if cx.is64 { 8 } else { 4 };
    read_un(data, usize::try_from(off).ok()?, width, cx.be).filter(|&v| v != 0)
}

// ---- Dead-block filter -------------------------------------------------

/// Drop dead blocks lying in functions whose FDE has an LSDA. Their
/// landing pads are entered only by the unwinder, so the CFG sees them
/// as unreachable, and their call-site tables hold function-relative
/// offsets that compaction does not rewrite.
pub fn retain_unwindable_blocks(
    data: &[u8],
    sections: &[Section],
    blocks: &[DeadBlock],
) -> Vec<DeadBlock> {
    if blocks.is_empty() {
        return Vec::new();
    }
    let ranges = lsda_ranges(data, sections);
    blocks
        .iter()
        .filter(|b| !overlaps(&ranges, b.addr, b.addr + b.size))
        .cloned()
        .collect()
}

/// Sorted, merged code ranges of FDEs that carry a non-null LSDA.
fn lsda_ranges(data: &[u8], sections: &[Section]) -> Vec<(u64, u64)> {
    let sec = match sections.iter().find(|s| s.name == ".eh_frame") {
        Some(s) => s,
        None => return Vec::new(),
    };
    let cx = Ctx::new(data, &[], 0, 0);
    let mut v: Vec<(u64, u64)> = parse_eh_frame(data, sec, &cx)
        .into_iter()
        .filter_map(|r| match r {
            Record::Fde(f)
                if f.begin != 0 && f.lsda.map_or(false, |l| l.raw != 0) =>
            {
                Some((f.begin, f.begin.saturating_add(f.pc_range.raw)))
            }
            _ => None,
        })
        .collect();
    v.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(v.len());
    for (s, e) in v {
        match merged.last_mut() {
            Some(last) if s <= last.1 => last.1 = last.1.max(e),
            _ => merged.push((s, e)),
        }
    }
    merged
}

/// True if `[lo, hi)` overlaps any of the sorted, disjoint `ranges`.
fn overlaps(ranges: &[(u64, u64)], lo: u64, hi: u64) -> bool {
    let i = ranges.partition_point(|r| r.0 < hi);
    i > 0 && ranges[i - 1].1 > lo
}

#[cfg(test)]
mod tests {
    use super::*;

    /// File offset of the test `.eh_frame_hdr` and `.eh_frame`; every
    /// file offset `o` of the test image has vaddr `VA + o`.
    const HDR_OFF: usize = 0x40;
    const EH_OFF: usize = 0x100;
    const VA: u64 = 0x2000;
    /// .text bounds of the test image (unwind tables lie after it).
    const TS: u64 = 0x800;
    const TE: u64 = 0x1800;
    /// 'zR' augmentation data: FDE pointers are pc-relative sdata4.
    const ZR: &[u8] = &[0x1b];
    /// CFA program: two rows, at begin + 4 and begin + 0x14.
    const TWO_ROWS: &[u8] = &[0x44, 0x0e, 0x10, 0x50, 0x0e, 0x08];

    /// A little-endian ELF64 image under construction: `e_ident`, room
    /// for `.eh_frame_hdr`, then `.eh_frame` records from `EH_OFF`.
    struct Img {
        data: Vec<u8>,
    }

    impl Img {
        /// An empty image.
        fn new() -> Self {
            let mut data = vec![0u8; EH_OFF];
            data[..6].copy_from_slice(b"\x7fELF\x02\x01");
            Img { data }
        }

        /// Append a record holding `id` and `body`; returns its offset.
        fn record(&mut self, id: u32, body: &[u8]) -> usize {
            let at = self.data.len();
            let len = u32::try_from(body.len() + 4).expect("small record");
            self.data.extend(len.to_le_bytes());
            self.data.extend(id.to_le_bytes());
            self.data.extend(body);
            at
        }

        /// A version 1 CIE with augmentation `aug`, code alignment
        /// factor `caf`, data alignment -8, return column 16 and
        /// augmentation data `aug_data` (for a 'z' augmentation).
        fn cie(&mut self, aug: &[u8], caf: u8, aug_data: &[u8]) -> usize {
            let mut b = vec![1];
            b.extend(aug);
            b.extend([0, caf, 0x78, 16]);
            if aug.first() == Some(&b'z') {
                b.push(aug_data.len() as u8);
                b.extend(aug_data);
            }
            b.extend([0x0c, 7, 8]); // DW_CFA_def_cfa r7, 8
            self.record(0, &b)
        }

        /// An FDE of the 'z' CIE at `cie` storing `raw` as its sdata4
        /// pc_begin, then `range`, augmentation data `aug` and the CFA
        /// program `cfa`.
        fn fde_raw(
            &mut self,
            cie: usize,
            raw: u32,
            range: u32,
            aug: &[u8],
            cfa: &[u8],
        ) -> usize {
            let at = self.data.len();
            let mut b = Vec::new();
            b.extend(raw.to_le_bytes());
            b.extend(range.to_le_bytes());
            b.push(aug.len() as u8);
            b.extend(aug);
            b.extend(cfa);
            let id = u32::try_from(at + 4 - cie).expect("CIE before FDE");
            self.record(id, &b)
        }

        /// An FDE describing `[begin, begin + range)` (pc-relative).
        fn fde(&mut self, cie: usize, begin: u64, range: u32, cfa: &[u8]) -> usize {
            let raw = begin.wrapping_sub(self.next_field()) as u32;
            self.fde_raw(cie, raw, range, &[], cfa)
        }

        /// Vaddr of the pc_begin field of the next record.
        fn next_field(&self) -> u64 {
            VA + self.data.len() as u64 + 8
        }

        /// Close `.eh_frame` with its zero terminator.
        fn finish(mut self) -> (Vec<u8>, Vec<Section>) {
            self.data.extend([0; 4]);
            let size = (self.data.len() - EH_OFF) as u64;
            (self.data, vec![section(".eh_frame", EH_OFF, size)])
        }
    }

    /// A section at file offset `off` (vaddr `VA + off`).
    fn section(name: &str, off: usize, size: u64) -> Section {
        let vaddr = VA + off as u64;
        Section { name: name.into(), size, vaddr, offset: off as u64, align: 4 }
    }

    /// Little-endian u32 at `off`.
    fn u32_at(d: &[u8], off: usize) -> u32 {
        u32::from_le_bytes(d[off..off + 4].try_into().expect("4 bytes"))
    }

    /// Store `v` little-endian at `off`.
    fn put_u32(d: &mut [u8], off: usize, v: u32) {
        d[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }

    /// Vaddr designated by the sdata4 value at `off`, relative to `base`.
    fn rel_at(d: &[u8], off: usize, base: u64) -> u64 {
        base.wrapping_add(u32_at(d, off) as i32 as i64 as u64)
    }

    /// Code start the FDE at `rec` designates.
    fn begin_of(d: &[u8], rec: usize) -> u64 {
        rel_at(d, rec + 8, VA + rec as u64 + 8)
    }

    /// The pc_range of the FDE at `rec`.
    fn range_of(d: &[u8], rec: usize) -> u32 {
        u32_at(d, rec + 12)
    }

    /// Fill in an `.eh_frame_hdr` (pc-relative eh_frame_ptr, udata4
    /// count, datarel sdata4 table) indexing the FDEs `rows`, given as
    /// `(initial location, record offset)`.
    fn add_hdr(d: &mut [u8], secs: &mut Vec<Section>, rows: &[(u64, usize)]) {
        let base = VA + HDR_OFF as u64;
        d[HDR_OFF..HDR_OFF + 4].copy_from_slice(&[1, 0x1b, 0x03, 0x3b]);
        let ptr = (VA + EH_OFF as u64).wrapping_sub(base + 4);
        put_u32(d, HDR_OFF + 4, ptr as u32);
        put_u32(d, HDR_OFF + 8, rows.len() as u32);
        for (i, &(loc, rec)) in rows.iter().enumerate() {
            let at = HDR_OFF + 12 + 8 * i;
            put_u32(d, at, loc.wrapping_sub(base) as u32);
            put_u32(d, at + 4, (VA + rec as u64).wrapping_sub(base) as u32);
        }
        let size = 12 + 8 * rows.len() as u64;
        secs.push(section(".eh_frame_hdr", HDR_OFF, size));
    }

    /// The search-table rows of the test `.eh_frame_hdr`, as addresses.
    fn hdr_rows(d: &[u8]) -> Vec<(u64, u64)> {
        let base = VA + HDR_OFF as u64;
        let n = u32_at(d, HDR_OFF + 8) as usize;
        (0..n)
            .map(|i| {
                let at = HDR_OFF + 12 + 8 * i;
                (rel_at(d, at, base), rel_at(d, at + 4, base))
            })
            .collect()
    }

    // ---- Parser ----------------------------------------------------------

    /// A 'zR' CIE and its FDEs decode to their code ranges.
    #[test]
    fn parses_fde_ranges() {
        let mut img = Img::new();
        let c = img.cie(b"zR", 1, ZR);
        img.fde(c, 0x1000, 0x40, &[]);
        img.fde(c, 0x1040, 0x20, &[]);
        let (d, secs) = img.finish();
        assert_eq!(fde_ranges(&d, &secs), vec![(0x1000, 0x40), (0x1040, 0x20)]);
    }

    /// FDEs the linker discarded (pc_begin 0) or that describe no code
    /// (pc_range 0) are left out.
    #[test]
    fn skips_discarded_and_empty_fdes() {
        let mut img = Img::new();
        let c = img.cie(b"zR", 1, ZR);
        img.fde_raw(c, 0, 0x40, &[], &[]);
        img.fde(c, 0x1100, 0, &[]);
        img.fde(c, 0x1200, 0x10, &[]);
        let (d, secs) = img.finish();
        assert_eq!(fde_ranges(&d, &secs), vec![(0x1200, 0x10)]);
    }

    /// Parsing stops at a record whose length runs past the section; the
    /// records before it are kept.
    #[test]
    fn stops_at_an_overlong_record() {
        let mut img = Img::new();
        let c = img.cie(b"zR", 1, ZR);
        img.fde(c, 0x1000, 0x40, &[]);
        let bad = img.fde(c, 0x1040, 0x20, &[]);
        img.fde(c, 0x1060, 0x20, &[]);
        let (mut d, secs) = img.finish();
        put_u32(&mut d, bad, 0x1000);
        assert_eq!(fde_ranges(&d, &secs), vec![(0x1000, 0x40)]);
    }

    /// A 64-bit extended length (0xffffffff, then 8 bytes) is followed.
    #[test]
    fn follows_an_extended_length() {
        let mut img = Img::new();
        let c = img.cie(b"zR", 1, ZR);
        let at = img.data.len();
        let id = u32::try_from(at + 12 - c).expect("small offset");
        let field = VA + at as u64 + 16;
        let mut body = Vec::new();
        body.extend(id.to_le_bytes());
        body.extend((0x1300u64.wrapping_sub(field) as u32).to_le_bytes());
        body.extend(0x30u32.to_le_bytes());
        body.push(0);
        img.data.extend(0xffff_ffffu32.to_le_bytes());
        img.data.extend((body.len() as u64).to_le_bytes());
        img.data.extend(body);
        let (d, secs) = img.finish();
        assert_eq!(fde_ranges(&d, &secs), vec![(0x1300, 0x30)]);
    }

    /// An FDE whose CIE has an unknown augmentation letter before one it
    /// needs, or whose CIE pointer leaves the section, is skipped.
    #[test]
    fn skips_fdes_without_a_usable_cie() {
        let mut img = Img::new();
        let bad_cie = img.cie(b"zXR", 1, &[0, 0x1b]);
        img.fde(bad_cie, 0x1000, 0x40, &[]);
        let c = img.cie(b"zR", 1, ZR);
        let stray = img.fde(c, 0x1100, 0x40, &[]);
        img.fde(c, 0x1200, 0x40, &[]);
        let (mut d, secs) = img.finish();
        put_u32(&mut d, stray + 4, (stray + 4 - EH_OFF + 8) as u32);
        assert_eq!(fde_ranges(&d, &secs), vec![(0x1200, 0x40)]);
    }

    /// 'zPLR': the personality pointer and each FDE's LSDA decode.
    #[test]
    fn parses_personality_and_lsda() {
        let mut img = Img::new();
        let mut aug = vec![0x00];
        aug.extend(0x1500u64.to_le_bytes());
        aug.extend([0x1b, 0x1b]);
        let c = img.cie(b"zPLR", 1, &aug);
        let raw = 0x1000u64.wrapping_sub(img.next_field()) as u32;
        img.fde_raw(c, raw, 0x40, &0x10u32.to_le_bytes(), &[]);
        img.fde_raw(c, 0, 0x20, &0u32.to_le_bytes(), &[]);
        let (d, secs) = img.finish();
        assert_eq!(personality_targets(&d, &secs), vec![0x1500]);
        assert_eq!(lsda_ranges(&d, &secs), vec![(0x1000, 0x1040)]);
    }

    /// An image with one 'zRL' FDE at 0x1000 whose LSDA field, encoded
    /// as `lsda_enc`, holds 0x10; returns it with the field's vaddr.
    fn lsda_image(lsda_enc: u8) -> (Vec<u8>, Vec<Section>, u64) {
        let mut img = Img::new();
        let c = img.cie(b"zRL", 1, &[0x1b, lsda_enc]);
        let raw = 0x1000u64.wrapping_sub(img.next_field()) as u32;
        // pc_begin, pc_range and the augmentation length come first.
        let field = img.next_field() + 9;
        img.fde_raw(c, raw, 0x40, &0x10u32.to_le_bytes(), &[]);
        let (d, secs) = img.finish();
        (d, secs, field)
    }

    /// A pc-relative LSDA is listed; an indirect one (its address sits
    /// in a slot) or one that does not resolve without a base (datarel)
    /// is refused with the FDE's pc_begin.
    #[test]
    fn lists_lsdas_and_refuses_unlocatable_ones() {
        let (d, secs, field) = lsda_image(0x1b);
        assert_eq!(fde_lsdas(&d, &secs), Ok(vec![(0x1000, field + 0x10)]));
        let (d, secs, _) = lsda_image(0x9b);
        assert_eq!(fde_lsdas(&d, &secs), Err(0x1000));
        let (d, secs, _) = lsda_image(0x3b);
        assert_eq!(fde_lsdas(&d, &secs), Err(0x1000));
    }

    // ---- Patching --------------------------------------------------------

    /// A live function that lost 8 internal bytes gets the shorter range,
    /// and its CFA advance across the hole shrinks by 8.
    #[test]
    fn respaces_the_cfa_of_a_shrunk_function() {
        let mut img = Img::new();
        let c = img.cie(b"zR", 1, ZR);
        let f = img.fde(c, 0x1000, 0x40, TWO_ROWS);
        let (mut d, secs) = img.finish();
        patch_eh_frame(&mut d, &secs, &[(0x1008, 0x1010)], TS, TE);
        assert_eq!(begin_of(&d, f), 0x1000);
        assert_eq!(range_of(&d, f), 0x38);
        assert_eq!(&d[f + 17..f + 23], &[0x44, 0x0e, 0x10, 0x48, 0x0e, 0x08]);
    }

    /// A function wholly inside a removed range is neutralised and its
    /// search-table row dropped; the next one moves down.
    #[test]
    fn neutralises_a_removed_function() {
        let mut img = Img::new();
        let c = img.cie(b"zR", 1, ZR);
        let f = img.fde(c, 0x1000, 0x40, TWO_ROWS);
        let g = img.fde(c, 0x1080, 0x20, &[]);
        let (mut d, mut secs) = img.finish();
        add_hdr(&mut d, &mut secs, &[(0x1000, f), (0x1080, g)]);
        patch_eh_frame(&mut d, &secs, &[(0x1000, 0x1040)], TS, TE);
        assert_eq!(range_of(&d, f), 0);
        assert_eq!(begin_of(&d, g), 0x1040);
        assert_eq!(hdr_rows(&d), vec![(0x1040, VA + g as u64)]);
    }

    /// Padding absorbed next to a removed function swallowed the first
    /// bytes of a live one: its FDE and search-table row stay, re-pointed
    /// at its new start with the shorter range.
    #[test]
    fn keeps_a_live_function_whose_start_was_absorbed() {
        let mut img = Img::new();
        let c = img.cie(b"zR", 1, ZR);
        let dead = img.fde(c, 0x1000, 0x40, &[]);
        let live = img.fde(c, 0x1040, 0x20, TWO_ROWS);
        let (mut d, mut secs) = img.finish();
        add_hdr(&mut d, &mut secs, &[(0x1000, dead), (0x1040, live)]);
        patch_eh_frame(&mut d, &secs, &[(0x1000, 0x1044)], TS, TE);
        assert_eq!(range_of(&d, dead), 0);
        assert_eq!(begin_of(&d, live), 0x1000);
        assert_eq!(range_of(&d, live), 0x1c);
        let cfa = &d[live + 17..live + 23];
        assert_eq!(cfa, &[0x40, 0x0e, 0x10, 0x50, 0x0e, 0x08]);
        assert_eq!(hdr_rows(&d), vec![(0x1000, VA + live as u64)]);
    }

    /// A shrunk function whose CFA program cannot be re-spaced (it uses
    /// DW_CFA_set_loc) is left untouched: no half-patched FDE.
    #[test]
    fn leaves_an_unrespaceable_fde_untouched() {
        let (mut d, secs, f) = set_loc_image();
        let before = d.clone();
        patch_eh_frame(&mut d, &secs, &[(0x1008, 0x1010)], TS, TE);
        assert_eq!(range_of(&d, f), 0x40);
        assert_eq!(d, before);
    }

    /// One function at 0x1000..0x1040 whose CFA program uses
    /// DW_CFA_set_loc; also returns the offset of its FDE.
    fn set_loc_image() -> (Vec<u8>, Vec<Section>, usize) {
        let mut img = Img::new();
        let c = img.cie(b"zR", 1, ZR);
        let mut cfa = vec![0x44, 0x01];
        cfa.extend(0x1014u64.to_le_bytes());
        cfa.extend([0x0e, 0x10]);
        let f = img.fde(c, 0x1000, 0x40, &cfa);
        let (d, secs) = img.finish();
        (d, secs, f)
    }

    /// Intervals narrowed to what the unwind tables can follow.
    mod clip {
        use super::*;

        /// A dead block inside a function whose CFA program cannot be
        /// re-spaced is kept; intervals elsewhere are not touched.
        #[test]
        fn keeps_blocks_of_unrespaceable_functions() {
            let (d, secs, _) = set_loc_image();
            let ivs = [(0x1008, 0x1010), (0x1100, 0x1110)];
            let got = unwind_safe_intervals(&d, &secs, &ivs, TS, TE, 1);
            assert_eq!(got, vec![(0x1100, 0x1110)]);
        }

        /// Padding absorbed into such a function is cut back to its start.
        #[test]
        fn cuts_absorbed_padding_back() {
            let (d, secs, _) = set_loc_image();
            let ivs = [(0xff0, 0x1008)];
            let got = unwind_safe_intervals(&d, &secs, &ivs, TS, TE, 1);
            assert_eq!(got, vec![(0xff0, 0x1000)]);
        }

        /// A removed function and a re-spaceable one keep their intervals.
        #[test]
        fn keeps_intervals_the_tables_can_follow() {
            let mut img = Img::new();
            let c = img.cie(b"zR", 1, ZR);
            img.fde(c, 0x1000, 0x40, TWO_ROWS);
            img.fde(c, 0x1040, 0x20, &[0x01]);
            let (d, secs) = img.finish();
            let ivs = [(0x1008, 0x1010), (0x1040, 0x1060)];
            let got = unwind_safe_intervals(&d, &secs, &ivs, TS, TE, 1);
            assert_eq!(got, ivs.to_vec());
        }

        /// A shift that is not a multiple of the code alignment factor
        /// cannot be expressed in CFA advances: the function stays whole.
        #[test]
        fn keeps_functions_whose_shift_breaks_alignment() {
            let mut img = Img::new();
            let c = img.cie(b"zR", 4, ZR);
            img.fde(c, 0x1000, 0x40, &[0x41, 0x0e, 0x10, 0x44]);
            let (d, secs) = img.finish();
            let ivs = [(0x1008, 0x100a)];
            let got = unwind_safe_intervals(&d, &secs, &ivs, TS, TE, 2);
            assert!(got.is_empty());
        }

        /// Pieces left by a cut keep a multiple of the alignment, counted
        /// from the end they keep.
        #[test]
        fn cut_range_keeps_alignment() {
            let ivs = [(0x100, 0x200), (0x300, 0x310)];
            let got = cut_range(&ivs, (0x10e, 0x1f2), 4);
            assert_eq!(got, vec![(0x100, 0x10c), (0x1f4, 0x200), (0x300, 0x310)]);
            assert!(cut_range(&ivs, (0, 0x1000), 4).is_empty());
        }
    }
}
