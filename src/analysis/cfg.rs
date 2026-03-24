//! Control flow graph construction and dead-block detection.
//!
//! Builds intra-procedural CFGs from decoded instructions, performs
//! BFS reachability from the entry block, and identifies unreachable
//! basic blocks as dead code. Also detects dead code after calls to
//! known noreturn functions (e.g., `exit`, `abort`).

use crate::analysis::noreturn::NORETURN_FUNCS;
use crate::types::{DecodedInstr, FlowType, FuncInfo, FuncMap};
use std::collections::{HashMap, HashSet, VecDeque};

/// Import thunk address to symbol name (PLT/IAT/stubs).
pub type ImportNames = HashMap<u64, String>;

/// A basic block within a function.
#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub id: usize,
    pub start_addr: u64,
    pub end_addr: u64,
    pub successors: Vec<usize>,
    pub predecessors: Vec<usize>,
}

/// CFG for a single function.
#[derive(Debug)]
pub struct FuncCfg {
    pub func_name: String,
    pub func_addr: u64,
    pub func_size: u64,
    pub blocks: Vec<BasicBlock>,
    pub entry_block: usize,
}

/// Dead block region within a live function.
#[derive(Debug, Clone)]
pub struct DeadBlock {
    pub func_name: String,
    pub addr: u64,
    pub size: u64,
}

/// Build CFGs for all functions and find dead blocks.
pub fn find_dead_blocks(
    funcs: &FuncMap,
    instrs: &[DecodedInstr],
    live_funcs: &HashSet<String>,
    import_names: &ImportNames,
) -> Vec<DeadBlock> {
    let mut all_dead = Vec::new();
    for (name, fi) in funcs {
        if !should_analyze(name, fi, live_funcs) {
            continue;
        }
        let dead = find_dead_in_func(
            name, fi, instrs, funcs, import_names,
        );
        all_dead.extend(dead);
    }
    all_dead
}

/// Check if a function should be analyzed for dead blocks.
fn should_analyze(
    name: &str,
    fi: &FuncInfo,
    live_funcs: &HashSet<String>,
) -> bool {
    live_funcs.contains(name)
        && fi.size >= 16
        && !name.starts_with("sub_")
}

/// Find dead blocks within a single function's instruction range.
fn find_dead_in_func(
    name: &str,
    fi: &FuncInfo,
    instrs: &[DecodedInstr],
    funcs: &FuncMap,
    import_names: &ImportNames,
) -> Vec<DeadBlock> {
    let func_end = fi.addr + fi.size;
    let func_instrs: Vec<&DecodedInstr> = instrs
        .iter()
        .filter(|i| i.addr >= fi.addr && i.addr < func_end)
        .collect();
    if func_instrs.is_empty() {
        return Vec::new();
    }
    let branch_targets =
        collect_branch_targets(&func_instrs, fi.addr, func_end);
    find_post_noreturn_dead(
        name,
        &func_instrs,
        funcs,
        import_names,
        &branch_targets,
        func_end,
    )
}

/// Collect all intra-function branch targets.
fn collect_branch_targets(
    instrs: &[&DecodedInstr],
    func_start: u64,
    func_end: u64,
) -> HashSet<u64> {
    let mut targets = HashSet::new();
    for instr in instrs {
        if instr.is_call {
            continue;
        }
        for &tgt in &instr.targets {
            if tgt >= func_start && tgt < func_end {
                targets.insert(tgt);
            }
        }
    }
    targets
}

/// Find dead code after noreturn calls and unconditional
/// branches, only if no branch targets the dead region.
fn find_post_noreturn_dead(
    name: &str,
    instrs: &[&DecodedInstr],
    funcs: &FuncMap,
    import_names: &ImportNames,
    branch_targets: &HashSet<u64>,
    func_end: u64,
) -> Vec<DeadBlock> {
    let mut dead = Vec::new();
    let n = instrs.len();
    let mut i = 0;
    while i < n {
        if is_dead_start(instrs[i], funcs, import_names) {
            let region = scan_dead_region(
                instrs, i, func_end, branch_targets,
            );
            if let Some(db) = region {
                dead.push(DeadBlock {
                    func_name: name.to_string(),
                    addr: db.0,
                    size: db.1,
                });
            }
        }
        i += 1;
    }
    dead
}

/// Check if instruction marks a dead-start point.
/// Only noreturn calls are guaranteed safe — code after
/// return/jump may be reachable via branches we don't
/// fully track in optimized system functions.
fn is_dead_start(
    instr: &DecodedInstr,
    funcs: &FuncMap,
    import_names: &ImportNames,
) -> bool {
    match instr.flow {
        FlowType::Call => {
            is_noreturn_call(instr, funcs, import_names)
        }
        _ => false,
    }
}

/// Scan forward from a dead-start to find the dead region.
fn scan_dead_region(
    instrs: &[&DecodedInstr],
    start_idx: usize,
    func_end: u64,
    branch_targets: &HashSet<u64>,
) -> Option<(u64, u64)> {
    let start_instr = instrs[start_idx];
    let dead_start =
        start_instr.addr + start_instr.len as u64;
    if dead_start >= func_end {
        return None;
    }
    let dead_end = find_dead_end(
        instrs, start_idx, func_end, branch_targets,
    );
    let size = dead_end - dead_start;
    if size >= 2 {
        Some((dead_start, size))
    } else {
        None
    }
}

/// Find where the dead region ends (a branch target or func end).
fn find_dead_end(
    instrs: &[&DecodedInstr],
    start_idx: usize,
    func_end: u64,
    branch_targets: &HashSet<u64>,
) -> u64 {
    for j in (start_idx + 1)..instrs.len() {
        let addr = instrs[j].addr;
        if addr >= func_end {
            break;
        }
        if branch_targets.contains(&addr) {
            return addr;
        }
    }
    func_end
}

/// Check if a call targets a known noreturn function.
fn is_noreturn_call(
    instr: &DecodedInstr,
    funcs: &FuncMap,
    import_names: &ImportNames,
) -> bool {
    for &tgt in &instr.targets {
        if let Some(name) = import_names.get(&tgt) {
            if NORETURN_FUNCS.contains(name.as_str()) {
                return true;
            }
        }
        for (name, fi) in funcs {
            if fi.addr == tgt
                && NORETURN_FUNCS.contains(name.as_str())
            {
                return true;
            }
        }
    }
    false
}

/// Full CFG-based dead block detection (Phase A extended).
/// More aggressive but requires safe preconditions.
pub fn find_dead_blocks_cfg(
    funcs: &FuncMap,
    instrs: &[DecodedInstr],
    live_funcs: &HashSet<String>,
) -> Vec<DeadBlock> {
    let mut all_dead = Vec::new();
    for (name, fi) in funcs {
        if !should_analyze_cfg(name, fi, live_funcs, instrs) {
            continue;
        }
        let cfg = build_func_cfg(name, fi, instrs, funcs);
        let dead = find_unreachable_blocks(&cfg);
        all_dead.extend(dead);
    }
    all_dead
}

/// Check if a function is safe for full CFG-based analysis (no indirect branches).
fn should_analyze_cfg(
    name: &str,
    fi: &FuncInfo,
    live_funcs: &HashSet<String>,
    instrs: &[DecodedInstr],
) -> bool {
    if !should_analyze(name, fi, live_funcs) {
        return false;
    }
    let func_end = fi.addr + fi.size;
    let fi_instrs: Vec<&DecodedInstr> = instrs
        .iter()
        .filter(|i| i.addr >= fi.addr && i.addr < func_end)
        .collect();
    is_safe_for_cfg(&fi_instrs)
}

/// A function is safe for CFG analysis if it has no indirect branches
/// and contains at least one return or halt instruction.
fn is_safe_for_cfg(instrs: &[&DecodedInstr]) -> bool {
    let has_indirect = instrs.iter().any(|i| {
        matches!(
            i.flow,
            FlowType::IndirectBranch | FlowType::IndirectCall
        )
    });
    if has_indirect {
        return false;
    }
    instrs.iter().any(|i| {
        matches!(i.flow, FlowType::Return | FlowType::Halt)
    })
}

/// Build a complete CFG for a single function from its decoded instructions.
pub fn build_func_cfg(
    name: &str,
    fi: &FuncInfo,
    instrs: &[DecodedInstr],
    funcs: &FuncMap,
) -> FuncCfg {
    let func_end = fi.addr + fi.size;
    let fi_instrs: Vec<&DecodedInstr> = instrs
        .iter()
        .filter(|i| i.addr >= fi.addr && i.addr < func_end)
        .collect();
    let starts =
        find_block_starts(&fi_instrs, fi.addr, func_end);
    let mut blocks = create_blocks(&starts, func_end);
    add_edges(
        &mut blocks, &fi_instrs, fi.addr, func_end, funcs,
    );
    fill_predecessors(&mut blocks);
    let entry = find_entry_block(&blocks, fi.addr);
    FuncCfg {
        func_name: name.to_string(),
        func_addr: fi.addr,
        func_size: fi.size,
        blocks,
        entry_block: entry,
    }
}

/// Identify basic block start addresses from branch targets and terminators.
fn find_block_starts(
    instrs: &[&DecodedInstr],
    func_start: u64,
    func_end: u64,
) -> Vec<u64> {
    let mut starts: HashSet<u64> = HashSet::new();
    starts.insert(func_start);
    for instr in instrs {
        if is_block_terminator(instr.flow) {
            let next = instr.addr + instr.len as u64;
            if next < func_end {
                starts.insert(next);
            }
        }
        if !instr.is_call {
            for &tgt in &instr.targets {
                if tgt >= func_start && tgt < func_end {
                    starts.insert(tgt);
                }
            }
        }
    }
    let mut sorted: Vec<u64> = starts.into_iter().collect();
    sorted.sort();
    sorted
}

/// Any non-Normal flow type terminates a basic block.
fn is_block_terminator(flow: FlowType) -> bool {
    !matches!(flow, FlowType::Normal)
}

/// Create BasicBlock structs from sorted start addresses.
fn create_blocks(
    starts: &[u64],
    func_end: u64,
) -> Vec<BasicBlock> {
    starts
        .iter()
        .enumerate()
        .map(|(id, &start)| {
            let end = starts
                .get(id + 1)
                .copied()
                .unwrap_or(func_end);
            BasicBlock {
                id,
                start_addr: start,
                end_addr: end,
                successors: Vec::new(),
                predecessors: Vec::new(),
            }
        })
        .collect()
}

/// Add successor edges to each block based on the terminating instruction.
fn add_edges(
    blocks: &mut [BasicBlock],
    instrs: &[&DecodedInstr],
    _func_start: u64,
    _func_end: u64,
    funcs: &FuncMap,
) {
    let empty = ImportNames::new();
    let addr_to_block: HashMap<u64, usize> =
        blocks.iter().map(|b| (b.start_addr, b.id)).collect();
    let n = blocks.len();
    for bid in 0..n {
        let last = find_last_instr(
            instrs,
            blocks[bid].start_addr,
            blocks[bid].end_addr,
        );
        let edges = match last {
            Some(i) => compute_edges(
                i, bid, n, funcs, &empty, &addr_to_block,
            ),
            None => fallthrough_edge(bid, n),
        };
        blocks[bid].successors = edges;
    }
}

/// Find the last instruction within a block's address range.
fn find_last_instr<'a>(
    instrs: &[&'a DecodedInstr],
    start: u64,
    end: u64,
) -> Option<&'a DecodedInstr> {
    instrs
        .iter()
        .rev()
        .find(|i| i.addr >= start && i.addr < end)
        .copied()
}

/// Compute successor block IDs based on the last instruction's flow type.
fn compute_edges(
    last: &DecodedInstr,
    bid: usize,
    n: usize,
    funcs: &FuncMap,
    import_names: &ImportNames,
    addr_to_block: &HashMap<u64, usize>,
) -> Vec<usize> {
    match last.flow {
        FlowType::Normal | FlowType::IndirectCall => {
            fallthrough_edge(bid, n)
        }
        FlowType::Call => {
            if is_noreturn_call(last, funcs, import_names) {
                Vec::new()
            } else {
                fallthrough_edge(bid, n)
            }
        }
        FlowType::UnconditionalBranch => {
            resolve_targets(last, addr_to_block)
        }
        FlowType::ConditionalBranch => {
            let mut e = fallthrough_edge(bid, n);
            for &tgt in &last.targets {
                if let Some(&t) = addr_to_block.get(&tgt) {
                    if !e.contains(&t) {
                        e.push(t);
                    }
                }
            }
            e
        }
        FlowType::Return | FlowType::Halt => Vec::new(),
        FlowType::IndirectBranch => (0..n).collect(),
    }
}

/// Return the fallthrough successor (next block) if it exists.
fn fallthrough_edge(bid: usize, n: usize) -> Vec<usize> {
    if bid + 1 < n { vec![bid + 1] } else { Vec::new() }
}

/// Map branch target addresses to block IDs.
fn resolve_targets(
    last: &DecodedInstr,
    addr_to_block: &HashMap<u64, usize>,
) -> Vec<usize> {
    last.targets
        .iter()
        .filter_map(|t| addr_to_block.get(t).copied())
        .collect()
}

/// Populate predecessor lists from successor edges.
fn fill_predecessors(blocks: &mut [BasicBlock]) {
    let n = blocks.len();
    let mut preds: Vec<Vec<usize>> = vec![Vec::new(); n];
    for b in blocks.iter() {
        for &s in &b.successors {
            if s < n {
                preds[s].push(b.id);
            }
        }
    }
    for (i, p) in preds.into_iter().enumerate() {
        blocks[i].predecessors = p;
    }
}

/// Collect blocks not reachable from the entry via BFS.
fn find_unreachable_blocks(cfg: &FuncCfg) -> Vec<DeadBlock> {
    if cfg.blocks.is_empty() {
        return Vec::new();
    }
    let reachable = bfs_reachable(cfg);
    cfg.blocks
        .iter()
        .filter(|b| !reachable.contains(&b.id))
        .filter(|b| b.end_addr - b.start_addr >= 2)
        .map(|b| DeadBlock {
            func_name: cfg.func_name.clone(),
            addr: b.start_addr,
            size: b.end_addr - b.start_addr,
        })
        .collect()
}

/// BFS from entry block, returning all reachable block IDs.
fn bfs_reachable(cfg: &FuncCfg) -> HashSet<usize> {
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    queue.push_back(cfg.entry_block);
    while let Some(bid) = queue.pop_front() {
        if !visited.insert(bid) {
            continue;
        }
        if bid < cfg.blocks.len() {
            for &succ in &cfg.blocks[bid].successors {
                if !visited.contains(&succ) {
                    queue.push_back(succ);
                }
            }
        }
    }
    visited
}

/// Find the block whose start address matches the function entry.
fn find_entry_block(
    blocks: &[BasicBlock],
    addr: u64,
) -> usize {
    blocks
        .iter()
        .find(|b| b.start_addr == addr)
        .map(|b| b.id)
        .unwrap_or(0)
}
