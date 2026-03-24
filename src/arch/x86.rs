//! x86-64/32 instruction decoder for dead code analysis.
//!
//! Uses the `iced-x86` library to decode variable-length x86 instructions,
//! extracting call/branch targets, PC-relative references, and flow types.
//! Follows the System V AMD64 and cdecl calling conventions.

use crate::types::{DecodedInstr, FlowType};
use iced_x86::{Decoder, DecoderOptions, FlowControl, OpKind};

/// Decode all x86-64 instructions in a code section.
pub fn decode_text_x86(
    data: &[u8],
    text_offset: u64,
    text_vaddr: u64,
    text_size: u64,
) -> Vec<DecodedInstr> {
    let end = text_offset as usize + text_size as usize;
    let slice = &data[text_offset as usize..end.min(data.len())];
    let mut decoder = Decoder::with_ip(
        64, slice, text_vaddr, DecoderOptions::NONE,
    );
    let mut instrs = Vec::new();
    while decoder.can_decode() {
        instrs.push(decode_one(slice, text_vaddr, &decoder.decode()));
    }
    instrs
}

/// Decode a single x86 instruction into a DecodedInstr.
fn decode_one(
    slice: &[u8],
    base: u64,
    instr: &iced_x86::Instruction,
) -> DecodedInstr {
    let addr = instr.ip();
    let len = instr.len();
    let raw_start = (addr - base) as usize;
    let raw = slice
        .get(raw_start..raw_start + len)
        .unwrap_or(&[])
        .to_vec();
    let mut targets = Vec::new();
    match instr.flow_control() {
        FlowControl::Call
        | FlowControl::UnconditionalBranch
        | FlowControl::ConditionalBranch => {
            if let Some(t) = near_branch_target(instr) {
                targets.push(t);
            }
        }
        _ => {}
    }
    let pc_rel = extract_pc_rel(instr);
    if let Some(t) = pc_rel {
        if !targets.contains(&t) {
            targets.push(t);
        }
    }
    let flow = classify_flow(instr);
    DecodedInstr {
        addr,
        raw,
        len,
        targets,
        pc_rel_target: pc_rel,
        is_call: matches!(flow, FlowType::Call | FlowType::IndirectCall),
        flow,
    }
}

/// Extract the near branch target address if the first operand is NearBranch64.
fn near_branch_target(
    instr: &iced_x86::Instruction,
) -> Option<u64> {
    if instr.op_count() > 0
        && instr.op_kind(0) == OpKind::NearBranch64
    {
        return Some(instr.near_branch_target());
    }
    None
}

/// Extract the RIP-relative memory operand address if present.
fn extract_pc_rel(
    instr: &iced_x86::Instruction,
) -> Option<u64> {
    if instr.is_ip_rel_memory_operand() {
        return Some(instr.ip_rel_memory_address());
    }
    None
}

/// Map iced-x86 FlowControl to our FlowType enum.
fn classify_flow(instr: &iced_x86::Instruction) -> FlowType {
    match instr.flow_control() {
        FlowControl::Next => FlowType::Normal,
        FlowControl::Call => {
            if near_branch_target(instr).is_some() {
                FlowType::Call
            } else {
                FlowType::IndirectCall
            }
        }
        FlowControl::UnconditionalBranch => {
            if near_branch_target(instr).is_some() {
                FlowType::UnconditionalBranch
            } else {
                FlowType::IndirectBranch
            }
        }
        FlowControl::ConditionalBranch => {
            FlowType::ConditionalBranch
        }
        FlowControl::Return => FlowType::Return,
        FlowControl::IndirectBranch => FlowType::IndirectBranch,
        FlowControl::IndirectCall => FlowType::IndirectCall,
        FlowControl::Interrupt => {
            if is_halt_instr(instr) {
                FlowType::Halt
            } else {
                FlowType::Normal
            }
        }
        _ => FlowType::Normal,
    }
}

/// Check if an instruction is HLT or UD2 (halt/trap).
fn is_halt_instr(instr: &iced_x86::Instruction) -> bool {
    let code = instr.code();
    matches!(
        code,
        iced_x86::Code::Hlt | iced_x86::Code::Ud2
    )
}
