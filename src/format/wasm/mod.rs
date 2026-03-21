use crate::analysis::cfg::DeadBlock;
use crate::types::{FuncInfo, FuncMap, Section};
use std::collections::{HashMap, HashSet, VecDeque};

/// Analyze a WebAssembly module for dead functions.
/// Returns (funcs, dead, sections).
pub fn analyze_wasm(
    data: &[u8],
) -> (FuncMap, HashMap<String, (u64, u64)>, Vec<Section>) {
    let module = match parse_module(data) {
        Some(m) => m,
        None => return empty(),
    };
    let funcs = build_func_map(&module);
    if funcs.is_empty() {
        return empty();
    }
    let dead = find_dead_functions(&module, &funcs);
    (funcs, dead, Vec::new())
}

/// Physically compact dead Wasm functions to minimal bodies and
/// physically remove dead blocks within live functions.
/// Returns (func_count, func_saved, block_count, block_saved).
pub fn reassemble_wasm(
    data: &mut Vec<u8>,
    dead: &HashMap<String, (u64, u64)>,
    dead_blocks: &[DeadBlock],
) -> (usize, u64, usize, u64) {
    let blk_count = dead_blocks.len();
    let blk_saved: u64 =
        dead_blocks.iter().map(|b| b.size).sum();
    let (code_start, code_end) =
        match parse_code_section_bounds(data) {
            Some(b) => b,
            None => return (0, 0, 0, 0),
        };
    // Build per-function dead block ranges (absolute offsets)
    let block_ranges =
        build_block_ranges(data, code_start, code_end, dead_blocks);
    let dead_offsets: HashSet<usize> =
        dead.values().map(|&(off, _)| off as usize).collect();
    let new_code = rebuild_code_section(
        data,
        code_start,
        code_end,
        &dead_offsets,
        &block_ranges,
    );
    let saved = (code_end - code_start)
        .saturating_sub(new_code.len()) as u64;
    // Reconstruct module: [before_code][new_code][after_code]
    let mut new_data = Vec::with_capacity(
        code_start + new_code.len() + data.len() - code_end,
    );
    new_data.extend_from_slice(&data[..code_start]);
    new_data.extend_from_slice(&new_code);
    new_data.extend_from_slice(&data[code_end..]);
    data.clear();
    data.extend_from_slice(&new_data);
    let count = dead.len();
    (count, saved, blk_count, blk_saved)
}

/// Map dead blocks to their containing function bodies.
/// Returns a map: body_content_start → sorted Vec<(abs_start, abs_end)>.
fn build_block_ranges(
    data: &[u8],
    code_start: usize,
    _code_end: usize,
    dead_blocks: &[DeadBlock],
) -> HashMap<usize, Vec<(usize, usize)>> {
    if dead_blocks.is_empty() {
        return HashMap::new();
    }
    // Walk functions in Code section to get body ranges
    let mut funcs: Vec<(usize, usize)> = Vec::new(); // (body_content_start, body_end)
    let mut pos = code_start + 1; // skip 0x0A
    let (_section_size, new_pos) =
        read_leb128_u32(data, pos);
    pos = new_pos;
    let (num_funcs, new_pos) =
        read_leb128_u32(data, pos);
    pos = new_pos;
    for _ in 0..num_funcs {
        let (body_size, body_content_start) =
            read_leb128_u32(data, pos);
        let body_end =
            body_content_start + body_size as usize;
        funcs.push((body_content_start, body_end));
        pos = body_end;
    }
    // Assign each dead block to the function it falls in
    let mut result: HashMap<usize, Vec<(usize, usize)>> =
        HashMap::new();
    for db in dead_blocks {
        let db_start = db.addr as usize;
        let db_end = db_start + db.size as usize;
        for &(bcs, be) in &funcs {
            if db_start >= bcs && db_end <= be {
                result
                    .entry(bcs)
                    .or_default()
                    .push((db_start, db_end));
                break;
            }
        }
    }
    // Sort each function's dead ranges
    for ranges in result.values_mut() {
        ranges.sort_by_key(|&(s, _)| s);
    }
    result
}

struct WasmModule {
    functions: Vec<WasmFunc>,
    roots: HashSet<u32>,
    call_graph: HashMap<u32, Vec<u32>>,
}

struct WasmFunc {
    index: u32,
    name: String,
    body_offset: u64,
    body_size: u64,
}

fn parse_module(data: &[u8]) -> Option<WasmModule> {
    use wasmparser::{Parser, Payload};
    let parser = Parser::new(0);
    let mut num_imports = 0u32;
    let mut type_indices: Vec<u32> = Vec::new();
    let mut roots = HashSet::new();
    let mut call_graph: HashMap<u32, Vec<u32>> = HashMap::new();
    let mut functions: Vec<WasmFunc> = Vec::new();
    let mut func_names: HashMap<u32, String> = HashMap::new();
    let mut code_idx = 0u32;

    for payload in parser.parse_all(data) {
        let payload = match payload {
            Ok(p) => p,
            Err(_) => return None,
        };
        match payload {
            Payload::ImportSection(reader) => {
                for group in reader {
                    let group = match group {
                        Ok(g) => g,
                        Err(_) => return None,
                    };
                    for item in group.into_iter() {
                        let (_, import) = match item {
                            Ok(t) => t,
                            Err(_) => continue,
                        };
                        if matches!(
                            import.ty,
                            wasmparser::TypeRef::Func(_)
                        ) {
                            num_imports += 1;
                        }
                    }
                }
            }
            Payload::FunctionSection(reader) => {
                for entry in reader {
                    match entry {
                        Ok(idx) => type_indices.push(idx),
                        Err(_) => return None,
                    }
                }
            }
            Payload::ExportSection(reader) => {
                for export in reader {
                    let export = match export {
                        Ok(e) => e,
                        Err(_) => continue,
                    };
                    if matches!(
                        export.kind,
                        wasmparser::ExternalKind::Func
                    ) {
                        roots.insert(export.index);
                        func_names.insert(
                            export.index,
                            export.name.to_string(),
                        );
                    }
                }
            }
            Payload::StartSection { func, .. } => {
                roots.insert(func);
            }
            Payload::ElementSection(reader) => {
                parse_elements(reader, &mut roots);
            }
            Payload::CodeSectionEntry(body) => {
                let func_idx = num_imports + code_idx;
                let range = body.range();
                let body_offset = range.start as u64;
                let body_size =
                    (range.end - range.start) as u64;
                let name = func_names
                    .get(&func_idx)
                    .cloned()
                    .unwrap_or_else(|| {
                        format!("wasm_func_{}", func_idx)
                    });
                functions.push(WasmFunc {
                    index: func_idx,
                    name,
                    body_offset,
                    body_size,
                });
                let callees =
                    extract_calls(body, func_idx);
                call_graph.insert(func_idx, callees);
                code_idx += 1;
            }
            _ => {}
        }
    }
    Some(WasmModule {
        functions,
        roots,
        call_graph,
    })
}

fn parse_elements(
    reader: wasmparser::ElementSectionReader<'_>,
    roots: &mut HashSet<u32>,
) {
    for elem in reader {
        let elem = match elem {
            Ok(e) => e,
            Err(_) => continue,
        };
        match elem.items {
            wasmparser::ElementItems::Functions(r) => {
                for idx in r {
                    if let Ok(i) = idx {
                        roots.insert(i);
                    }
                }
            }
            wasmparser::ElementItems::Expressions(
                _,
                _,
            ) => {}
        }
    }
}

fn extract_calls(
    body: wasmparser::FunctionBody<'_>,
    _func_idx: u32,
) -> Vec<u32> {
    let mut callees = Vec::new();
    let mut reader = match body.get_operators_reader() {
        Ok(r) => r,
        Err(_) => return callees,
    };
    while !reader.eof() {
        match reader.read() {
            Ok(op) => match op {
                wasmparser::Operator::Call {
                    function_index,
                } => {
                    callees.push(function_index);
                }
                wasmparser::Operator::CallIndirect {
                    ..
                } => {}
                _ => {}
            },
            Err(_) => break,
        }
    }
    callees
}

fn build_func_map(module: &WasmModule) -> FuncMap {
    let mut funcs = FuncMap::new();
    for f in &module.functions {
        funcs.insert(
            f.name.clone(),
            FuncInfo {
                addr: f.body_offset,
                size: f.body_size,
                is_global: module.roots.contains(&f.index),
            },
        );
    }
    funcs
}

fn find_dead_functions(
    module: &WasmModule,
    _funcs: &FuncMap,
) -> HashMap<String, (u64, u64)> {
    let live = bfs_live(module);
    let mut dead = HashMap::new();
    for f in &module.functions {
        if !live.contains(&f.index) {
            dead.insert(
                f.name.clone(),
                (f.body_offset, f.body_size),
            );
        }
    }
    dead
}

fn bfs_live(module: &WasmModule) -> HashSet<u32> {
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    for &root in &module.roots {
        if !visited.contains(&root) {
            visited.insert(root);
            queue.push_back(root);
        }
    }
    while let Some(idx) = queue.pop_front() {
        if let Some(callees) = module.call_graph.get(&idx) {
            for &callee in callees {
                if !visited.contains(&callee) {
                    visited.insert(callee);
                    queue.push_back(callee);
                }
            }
        }
    }
    visited
}

/// Detect dead branches within live Wasm function bodies.
/// Finds unreachable code after `unreachable`, `return`, and
/// unconditional `br` opcodes until the next control boundary.
pub fn find_wasm_dead_blocks(
    data: &[u8],
    dead_funcs: &HashMap<String, (u64, u64)>,
) -> Vec<DeadBlock> {
    let module = match parse_module(data) {
        Some(m) => m,
        None => return Vec::new(),
    };
    let live = bfs_live(&module);
    let dead_func_indices: HashSet<u32> = module
        .functions
        .iter()
        .filter(|f| !live.contains(&f.index))
        .map(|f| f.index)
        .collect();
    let mut blocks = Vec::new();
    for f in &module.functions {
        if dead_func_indices.contains(&f.index) {
            continue;
        }
        if dead_funcs.contains_key(&f.name) {
            continue;
        }
        scan_wasm_body_dead(
            data, f, &mut blocks,
        );
    }
    blocks
}

fn scan_wasm_body_dead(
    data: &[u8],
    func: &WasmFunc,
    blocks: &mut Vec<DeadBlock>,
) {
    let start = func.body_offset as usize;
    let end = start + func.body_size as usize;
    if start >= data.len() || end > data.len() {
        return;
    }
    // Scan the raw bytes for patterns:
    // After unreachable (0x00) or return (0x0F) or br (0x0C),
    // until end (0x0B) or else (0x05) or a block boundary.
    let body = &data[start..end];
    let mut pos = 0usize;
    // Skip locals declaration
    pos = skip_locals(body, pos);
    let mut dead_start: Option<usize> = None;
    let mut depth = 0u32; // block nesting depth
    while pos < body.len() {
        let op = body[pos];
        // Track block nesting
        match op {
            0x02 | 0x03 | 0x04 => {
                // block, loop, if — increase depth
                if dead_start.is_some() {
                    // Inside dead region, just track depth
                    depth += 1;
                    pos = skip_block_type(body, pos + 1);
                    continue;
                }
                depth += 1;
                pos = skip_block_type(body, pos + 1);
                continue;
            }
            0x05 => {
                // else
                if dead_start.is_some() && depth == 0 {
                    // End of dead region at this boundary
                    let ds = dead_start.unwrap();
                    let dead_off = start + ds;
                    let dead_sz = pos - ds;
                    if dead_sz >= 2 {
                        blocks.push(DeadBlock {
                            func_name: func.name.clone(),
                            addr: dead_off as u64,
                            size: dead_sz as u64,
                        });
                    }
                    dead_start = None;
                } else if dead_start.is_some() && depth > 0 {
                    // else inside nested block in dead region
                }
                pos += 1;
                continue;
            }
            0x0B => {
                // end
                if dead_start.is_some() && depth == 0 {
                    let ds = dead_start.unwrap();
                    let dead_off = start + ds;
                    let dead_sz = pos - ds;
                    if dead_sz >= 2 {
                        blocks.push(DeadBlock {
                            func_name: func.name.clone(),
                            addr: dead_off as u64,
                            size: dead_sz as u64,
                        });
                    }
                    dead_start = None;
                } else if dead_start.is_some() && depth > 0 {
                    depth -= 1;
                } else if depth > 0 {
                    depth -= 1;
                }
                pos += 1;
                continue;
            }
            _ => {}
        }
        if dead_start.is_some() {
            pos = skip_wasm_instr(body, pos);
            continue;
        }
        // Check for dead-start triggers
        match op {
            0x00 => {
                // unreachable — code after is dead
                pos += 1;
                dead_start = Some(pos);
                continue;
            }
            0x0F => {
                // return — code after is dead
                pos += 1;
                dead_start = Some(pos);
                continue;
            }
            0x0C => {
                // br — unconditional branch, code after dead
                pos += 1;
                pos = skip_leb128(body, pos); // label index
                dead_start = Some(pos);
                continue;
            }
            _ => {
                pos = skip_wasm_instr(body, pos);
            }
        }
    }
}

fn skip_locals(body: &[u8], mut pos: usize) -> usize {
    if pos >= body.len() {
        return pos;
    }
    let (count, new_pos) = read_leb128_u32(body, pos);
    pos = new_pos;
    for _ in 0..count {
        let (_cnt, p) = read_leb128_u32(body, pos);
        pos = p;
        if pos < body.len() {
            pos += 1; // valtype
        }
    }
    pos
}

fn skip_block_type(body: &[u8], pos: usize) -> usize {
    if pos >= body.len() {
        return pos;
    }
    let b = body[pos];
    if b == 0x40 {
        // empty block type
        pos + 1
    } else if b >= 0x60 && b <= 0x7F {
        // valtype
        pos + 1
    } else {
        // s33 type index
        skip_leb128(body, pos)
    }
}

fn skip_wasm_instr(body: &[u8], pos: usize) -> usize {
    if pos >= body.len() {
        return body.len();
    }
    let op = body[pos];
    match op {
        // No operands
        0x00 | 0x01 | 0x0F | 0x1A | 0x1B | 0x45..=0xC4
        | 0xD1 => pos + 1,
        // Block-like: block type
        0x02 | 0x03 | 0x04 => skip_block_type(body, pos + 1),
        // br, br_if: label index (LEB128)
        0x0C | 0x0D => skip_leb128(body, pos + 1),
        // br_table: vec(label) + default
        0x0E => {
            let mut p = pos + 1;
            let (count, np) = read_leb128_u32(body, p);
            p = np;
            for _ in 0..=count {
                p = skip_leb128(body, p);
            }
            p
        }
        // call, local.get/set/tee, global.get/set
        0x10 | 0x20..=0x24 => skip_leb128(body, pos + 1),
        // call_indirect: type + table
        0x11 => {
            let p = skip_leb128(body, pos + 1);
            skip_leb128(body, p)
        }
        // memory instructions: align + offset
        0x28..=0x3E => {
            let p = skip_leb128(body, pos + 1);
            skip_leb128(body, p)
        }
        // memory.size, memory.grow
        0x3F | 0x40 => pos + 2,
        // i32.const
        0x41 => skip_leb128(body, pos + 1),
        // i64.const
        0x42 => skip_leb128(body, pos + 1),
        // f32.const
        0x43 => pos + 5,
        // f64.const
        0x44 => pos + 9,
        // else, end
        0x05 | 0x0B => pos + 1,
        // drop, select
        0xD0 => pos + 2, // ref.null
        // multi-byte prefix (0xFC, 0xFD, 0xFE)
        0xFC | 0xFD | 0xFE => {
            // Skip the sub-opcode LEB128
            skip_leb128(body, pos + 1)
        }
        _ => pos + 1,
    }
}

fn write_leb128_u32(val: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut v = val;
    loop {
        let mut byte = (v & 0x7F) as u8;
        v >>= 7;
        if v != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if v == 0 {
            break;
        }
    }
    buf
}

/// Find the byte range of the Code section (id 0x0A) in a Wasm module.
/// Returns (section_header_start, section_end) covering the entire section.
fn parse_code_section_bounds(
    data: &[u8],
) -> Option<(usize, usize)> {
    if data.len() < 8 || &data[0..4] != b"\x00asm" {
        return None;
    }
    let mut pos = 8; // skip magic + version
    while pos < data.len() {
        let section_id = data[pos];
        let header_start = pos;
        pos += 1;
        let (section_size, new_pos) =
            read_leb128_u32(data, pos);
        pos = new_pos;
        let section_end = pos + section_size as usize;
        if section_id == 0x0A {
            return Some((header_start, section_end));
        }
        pos = section_end;
    }
    None
}

/// Rebuild the Code section: dead functions get minimal bodies,
/// live functions with dead blocks get compacted bodies.
fn rebuild_code_section(
    data: &[u8],
    code_start: usize,
    code_end: usize,
    dead_offsets: &HashSet<usize>,
    block_ranges: &HashMap<usize, Vec<(usize, usize)>>,
) -> Vec<u8> {
    let mut pos = code_start + 1; // skip 0x0A
    let (_section_size, new_pos) =
        read_leb128_u32(data, pos);
    pos = new_pos;
    let (num_functions, new_pos) =
        read_leb128_u32(data, pos);
    pos = new_pos;
    let mut bodies = Vec::new();
    for _ in 0..num_functions {
        let entry_start = pos;
        let (body_size, bcs) =
            read_leb128_u32(data, pos);
        let entry_end = bcs + body_size as usize;
        if dead_offsets.contains(&bcs) {
            emit_dead_func(
                &mut bodies, data, entry_start,
                entry_end, code_end,
            );
        } else if let Some(ranges) = block_ranges.get(&bcs)
        {
            // Live function with dead blocks: compact
            let body = &data[bcs..entry_end.min(code_end)];
            let compacted = excise_ranges(body, bcs, ranges);
            let size_leb =
                write_leb128_u32(compacted.len() as u32);
            bodies.extend_from_slice(&size_leb);
            bodies.extend_from_slice(&compacted);
        } else {
            // Live function, no dead blocks: copy verbatim
            let end = entry_end.min(code_end);
            bodies.extend_from_slice(
                &data[entry_start..end],
            );
        }
        pos = entry_end;
    }
    wrap_code_section(num_functions, &bodies)
}

fn emit_dead_func(
    bodies: &mut Vec<u8>,
    data: &[u8],
    entry_start: usize,
    entry_end: usize,
    code_end: usize,
) {
    let orig_size = entry_end - entry_start;
    if orig_size <= 4 {
        bodies.extend_from_slice(
            &data[entry_start..entry_end.min(code_end)],
        );
    } else {
        // Minimal body: size=3, 0 locals, unreachable, end
        bodies.extend_from_slice(&[
            0x03, 0x00, 0x00, 0x0B,
        ]);
    }
}

/// Remove dead ranges from a function body.
/// `ranges` are absolute offsets; `base` is body start.
fn excise_ranges(
    body: &[u8],
    base: usize,
    ranges: &[(usize, usize)],
) -> Vec<u8> {
    let mut result = Vec::with_capacity(body.len());
    let mut pos = 0usize;
    for &(abs_start, abs_end) in ranges {
        let rel_start = abs_start.saturating_sub(base);
        let rel_end = abs_end.saturating_sub(base);
        if rel_start > pos && rel_start <= body.len() {
            result.extend_from_slice(
                &body[pos..rel_start],
            );
        }
        pos = rel_end;
    }
    if pos < body.len() {
        result.extend_from_slice(&body[pos..]);
    }
    result
}

fn wrap_code_section(
    num_functions: u32,
    bodies: &[u8],
) -> Vec<u8> {
    let num_funcs_leb = write_leb128_u32(num_functions);
    let content_size = num_funcs_leb.len() + bodies.len();
    let section_size_leb =
        write_leb128_u32(content_size as u32);
    let mut section = Vec::with_capacity(
        1 + section_size_leb.len() + content_size,
    );
    section.push(0x0A);
    section.extend_from_slice(&section_size_leb);
    section.extend_from_slice(&num_funcs_leb);
    section.extend_from_slice(bodies);
    section
}

fn read_leb128_u32(data: &[u8], mut pos: usize) -> (u32, usize) {
    let mut result = 0u32;
    let mut shift = 0;
    while pos < data.len() {
        let b = data[pos];
        pos += 1;
        result |= ((b & 0x7F) as u32) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 35 {
            break;
        }
    }
    (result, pos)
}

fn skip_leb128(data: &[u8], mut pos: usize) -> usize {
    while pos < data.len() {
        let b = data[pos];
        pos += 1;
        if b & 0x80 == 0 {
            break;
        }
    }
    pos
}

fn empty() -> (
    FuncMap,
    HashMap<String, (u64, u64)>,
    Vec<Section>,
) {
    (FuncMap::new(), HashMap::new(), Vec::new())
}
