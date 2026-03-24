pub mod bytecode;
pub mod classfile;

use crate::analysis::cfg::DeadBlock;
use crate::types::{FuncInfo, FuncMap, Section};
use classfile::{cp_utf8, parse_classfile, ClassFile};
use std::collections::{HashMap, HashSet, VecDeque};

/// Analyze a Java .class file for dead methods.
pub fn analyze_java(
    data: &[u8],
) -> (FuncMap, HashMap<String, (u64, u64)>, Vec<Section>) {
    let cf = match parse_classfile(data) {
        Some(c) => c,
        None => return empty(),
    };
    let funcs = build_func_map(&cf);
    if funcs.is_empty() {
        return empty();
    }
    let dead = find_dead_methods(data, &cf, &funcs);
    (funcs, dead, Vec::new())
}

/// Rebuild .class file, omitting dead method entries entirely.
/// Returns (func_count, func_saved, block_count, block_saved).
pub fn reassemble_java(
    data: &mut Vec<u8>,
    dead: &HashMap<String, (u64, u64)>,
    dead_blocks: &[DeadBlock],
) -> (usize, u64, usize, u64) {
    let cf = match parse_classfile(data) {
        Some(c) => c,
        None => return (0, 0, 0, 0),
    };
    // Step 1: Group dead blocks by method (file-offset based)
    let blk_count = dead_blocks.len();
    let blk_saved: u64 =
        dead_blocks.iter().map(|b| b.size).sum();
    // Map dead blocks to method indices
    let mut method_dead_blocks: HashMap<usize, Vec<(usize, usize)>> =
        HashMap::new();
    for db in dead_blocks {
        let db_s = db.addr as usize;
        let db_e = db_s + db.size as usize;
        for (idx, m) in cf.methods.iter().enumerate() {
            if let Some(co) = m.code_offset {
                let ce = co + m.code_length;
                if db_s >= co && db_e <= ce {
                    method_dead_blocks
                        .entry(idx)
                        .or_default()
                        .push((db_s, db_e));
                    break;
                }
            }
        }
    }
    if dead.is_empty() && method_dead_blocks.is_empty() {
        return (0, 0, 0, 0);
    }
    // Step 2: Rebuild class file without dead methods,
    //         compacting dead branches in live methods
    let pool = &cf.constant_pool;
    let dead_indices: HashSet<usize> = cf
        .methods
        .iter()
        .enumerate()
        .filter(|(_, m)| {
            let name = cp_utf8(pool, m.name_index);
            dead.contains_key(name)
        })
        .map(|(i, _)| i)
        .collect();
    let live_methods: Vec<(usize, &classfile::MethodInfo)> =
        cf.methods
            .iter()
            .enumerate()
            .filter(|(i, _)| !dead_indices.contains(i))
            .collect();
    let new_count = live_methods.len() as u16;
    let fc = dead_indices.len();
    // Build new method bytes from live methods
    let mut method_bytes = Vec::new();
    for &(idx, m) in &live_methods {
        if let Some(ranges) = method_dead_blocks.get(&idx) {
            if let Some(compacted) =
                bytecode::compact_method_code(
                    data, m, ranges, pool,
                )
            {
                method_bytes.extend_from_slice(&compacted);
                continue;
            }
            // Compaction failed: nop-fill in original data
            for &(s, e) in ranges {
                if e <= data.len() {
                    data[s..e].fill(0x00);
                }
            }
        }
        method_bytes.extend_from_slice(
            &data[m.raw_offset..m.raw_offset + m.raw_size],
        );
    }
    // Reconstruct: [before_methods_count] [new_count] [live_method_bytes] [after_methods]
    let mco = cf.methods_count_offset;
    // The original methods span from methods_count to after all methods
    let orig_methods_start = mco; // methods_count u16
    let orig_methods_end = if let Some(last) =
        cf.methods.last()
    {
        last.raw_offset + last.raw_size
    } else {
        mco + 2
    };
    let mut new_data = Vec::with_capacity(data.len());
    new_data.extend_from_slice(&data[..orig_methods_start]);
    // Write new methods_count (big-endian u16)
    new_data.push((new_count >> 8) as u8);
    new_data.push((new_count & 0xFF) as u8);
    new_data.extend_from_slice(&method_bytes);
    new_data.extend_from_slice(&data[orig_methods_end..]);
    let saved = data.len().saturating_sub(new_data.len()) as u64;
    data.clear();
    data.extend_from_slice(&new_data);
    (fc, saved, blk_count, blk_saved)
}

/// Find dead branches within live Java methods.
pub fn find_java_dead_blocks(
    data: &[u8],
    dead_funcs: &HashMap<String, (u64, u64)>,
) -> Vec<DeadBlock> {
    let cf = match parse_classfile(data) {
        Some(c) => c,
        None => return Vec::new(),
    };
    let live = bfs_live(data, &cf);
    let pool = &cf.constant_pool;
    let dead_indices: HashSet<usize> = cf
        .methods
        .iter()
        .enumerate()
        .filter(|(_, m)| {
            let name = cp_utf8(pool, m.name_index);
            dead_funcs.contains_key(name)
        })
        .map(|(i, _)| i)
        .collect();
    let live_set: HashSet<usize> = live
        .difference(&dead_indices)
        .copied()
        .collect();
    bytecode::find_dead_branches(data, &cf, &live_set)
}

fn build_func_map(cf: &ClassFile) -> FuncMap {
    let pool = &cf.constant_pool;
    let mut funcs = FuncMap::new();
    for m in &cf.methods {
        let name =
            cp_utf8(pool, m.name_index).to_string();
        if name.is_empty() {
            continue;
        }
        let is_public =
            (m.access_flags & 0x0001) != 0
                || (m.access_flags & 0x0004) != 0; // public or protected
        funcs.insert(
            name,
            FuncInfo {
                addr: m.raw_offset as u64,
                size: m.raw_size as u64,
                is_global: is_public,
            },
        );
    }
    funcs
}

fn find_dead_methods(
    data: &[u8],
    cf: &ClassFile,
    _funcs: &FuncMap,
) -> HashMap<String, (u64, u64)> {
    let live = bfs_live(data, cf);
    let pool = &cf.constant_pool;
    let mut dead = HashMap::new();
    for (i, m) in cf.methods.iter().enumerate() {
        if live.contains(&i) {
            continue;
        }
        let name =
            cp_utf8(pool, m.name_index).to_string();
        if name.is_empty() {
            continue;
        }
        dead.insert(
            name,
            (m.raw_offset as u64, m.raw_size as u64),
        );
    }
    dead
}

fn bfs_live(data: &[u8], cf: &ClassFile) -> HashSet<usize> {
    let pool = &cf.constant_pool;
    // Roots: main, <init>, <clinit>, all public/protected methods
    let roots: HashSet<usize> = cf
        .methods
        .iter()
        .enumerate()
        .filter(|(_, m)| {
            let name = cp_utf8(pool, m.name_index);
            name == "main"
                || name == "<init>"
                || name == "<clinit>"
                || (m.access_flags & 0x0001) != 0
                || (m.access_flags & 0x0004) != 0
        })
        .map(|(i, _)| i)
        .collect();
    // Build call graph by scanning bytecode
    let mut graph: HashMap<usize, HashSet<usize>> =
        HashMap::new();
    for (idx, m) in cf.methods.iter().enumerate() {
        if let Some(co) = m.code_offset {
            let callees =
                bytecode::scan_bytecode_calls(
                    data, cf, co, m.code_length,
                );
            graph.insert(idx, callees);
        }
    }
    // BFS from roots
    let mut visited = HashSet::new();
    let mut queue: VecDeque<usize> =
        roots.into_iter().collect();
    while let Some(idx) = queue.pop_front() {
        if !visited.insert(idx) {
            continue;
        }
        if let Some(callees) = graph.get(&idx) {
            for &c in callees {
                if !visited.contains(&c) {
                    queue.push_back(c);
                }
            }
        }
    }
    visited
}

fn empty() -> (
    FuncMap,
    HashMap<String, (u64, u64)>,
    Vec<Section>,
) {
    (FuncMap::new(), HashMap::new(), Vec::new())
}
