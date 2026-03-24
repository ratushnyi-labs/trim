//! Shared types used across the entire `trim` codebase.
//!
//! Defines the core data structures for representing CPU architectures,
//! decoded instructions, function metadata, binary sections, and
//! utility functions for pointer I/O. These types form the common
//! interface between the format parsers, architecture decoders,
//! analysis engine, and patching layer.

use std::collections::{HashMap, HashSet};

/// CPU architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    X86_64,
    X86_32,
    Aarch64,
    Arm32,
    RiscV64,
    RiscV32,
    Mips32,
    Mips64,
    S390x,
    LoongArch64,
}

/// Byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endian {
    Little,
    Big,
}

/// Information about a discovered function.
#[derive(Debug, Clone)]
pub struct FuncInfo {
    pub addr: u64,
    pub size: u64,
    pub is_global: bool,
}

/// Instruction flow control type for CFG construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowType {
    Normal,
    Call,
    UnconditionalBranch,
    ConditionalBranch,
    Return,
    Halt,
    IndirectBranch,
    IndirectCall,
}

/// A decoded instruction with metadata.
#[derive(Debug, Clone)]
pub struct DecodedInstr {
    pub addr: u64,
    pub raw: Vec<u8>,
    pub len: usize,
    pub targets: Vec<u64>,
    pub pc_rel_target: Option<u64>,
    pub is_call: bool,
    pub flow: FlowType,
}

/// A binary section descriptor.
#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub size: u64,
    pub vaddr: u64,
    pub offset: u64,
    pub align: u64,
}

/// Function map: name -> FuncInfo.
pub type FuncMap = HashMap<String, FuncInfo>;

/// Call/reference graph: name -> set of callee names.
pub type RefGraph = HashMap<String, HashSet<String>>;

/// Convert a virtual address to a file offset using section info.
pub fn vaddr_to_offset(
    vaddr: u64,
    sections: &[Section],
) -> Option<u64> {
    for s in sections {
        if s.vaddr <= vaddr && vaddr < s.vaddr + s.size {
            return Some(s.offset + (vaddr - s.vaddr));
        }
    }
    None
}

/// Read a pointer from data at the given offset.
pub fn read_ptr(
    data: &[u8],
    off: usize,
    is64: bool,
    endian: Endian,
) -> u64 {
    if is64 {
        let b: [u8; 8] =
            data[off..off + 8].try_into().unwrap_or([0; 8]);
        match endian {
            Endian::Little => u64::from_le_bytes(b),
            Endian::Big => u64::from_be_bytes(b),
        }
    } else {
        let b: [u8; 4] =
            data[off..off + 4].try_into().unwrap_or([0; 4]);
        match endian {
            Endian::Little => u32::from_le_bytes(b) as u64,
            Endian::Big => u32::from_be_bytes(b) as u64,
        }
    }
}

/// Write a pointer to data at the given offset.
pub fn write_ptr(
    data: &mut [u8],
    off: usize,
    val: u64,
    is64: bool,
    endian: Endian,
) {
    if is64 {
        let b = match endian {
            Endian::Little => val.to_le_bytes(),
            Endian::Big => val.to_be_bytes(),
        };
        data[off..off + 8].copy_from_slice(&b);
    } else {
        let b = match endian {
            Endian::Little => (val as u32).to_le_bytes(),
            Endian::Big => (val as u32).to_be_bytes(),
        };
        data[off..off + 4].copy_from_slice(&b);
    }
}
