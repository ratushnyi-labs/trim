use crate::types::DecodedInstr;
use iced_x86::{Decoder, DecoderOptions, FlowControl, OpKind};

/// Decode all x86-64 instructions in the .text section.
pub fn decode_text(
    data: &[u8],
    text_offset: u64,
    text_vaddr: u64,
    text_size: u64,
) -> Vec<DecodedInstr> {
    let end = text_offset as usize + text_size as usize;
    let slice = &data[text_offset as usize..end.min(data.len())];
    let mut decoder =
        Decoder::with_ip(64, slice, text_vaddr, DecoderOptions::NONE);
    let mut instrs = Vec::new();
    while decoder.can_decode() {
        let instr = decoder.decode();
        let addr = instr.ip();
        let len = instr.len();
        let raw_start = (addr - text_vaddr) as usize;
        let raw = slice
            .get(raw_start..raw_start + len)
            .unwrap_or(&[])
            .to_vec();
        let mut targets = Vec::new();
        match instr.flow_control() {
            FlowControl::Call | FlowControl::UnconditionalBranch => {
                if let Some(t) = near_branch_target(&instr) {
                    targets.push(t);
                }
            }
            FlowControl::ConditionalBranch => {
                if let Some(t) = near_branch_target(&instr) {
                    targets.push(t);
                }
            }
            _ => {}
        }
        let rip_target = extract_rip_rel(&instr);
        if let Some(t) = rip_target {
            if !targets.contains(&t) {
                targets.push(t);
            }
        }
        instrs.push(DecodedInstr {
            addr,
            raw,
            len,
            targets,
            rip_target,
            is_call: matches!(
                instr.flow_control(),
                FlowControl::Call
            ),
        });
    }
    instrs
}

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

fn extract_rip_rel(
    instr: &iced_x86::Instruction,
) -> Option<u64> {
    if instr.is_ip_rel_memory_operand() {
        return Some(instr.ip_rel_memory_address());
    }
    None
}
