use std::collections::{HashMap, HashSet};

/// Information about a discovered function.
#[derive(Debug, Clone)]
pub struct FuncInfo {
    pub addr: u64,
    pub size: u64,
    pub is_global: bool,
}

/// A decoded instruction with metadata.
#[derive(Debug, Clone)]
pub struct DecodedInstr {
    pub addr: u64,
    pub raw: Vec<u8>,
    pub len: usize,
    pub targets: Vec<u64>,
    pub rip_target: Option<u64>,
    pub is_call: bool,
}

/// An ELF section descriptor.
#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub size: u64,
    pub vaddr: u64,
    pub offset: u64,
}

/// Function map: name -> FuncInfo.
pub type FuncMap = HashMap<String, FuncInfo>;

/// Call/reference graph: name -> set of callee names.
pub type RefGraph = HashMap<String, HashSet<String>>;
