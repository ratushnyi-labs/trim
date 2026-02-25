use crate::analysis::lattice::{BinOp, CondCode};

/// Abstract register ID (arch-independent).
/// GPR 0..15 for x86 (RAX=0 .. R15=15), 0..30 for ARM.
/// FLAGS = 16.
pub type RegId = u8;

pub const FLAGS_REG: RegId = 16;
pub const REG_COUNT: usize = 17;

/// Simplified instruction effect for SSA.
#[derive(Debug, Clone)]
pub enum SsaEffect {
    /// reg = constant
    MovConst(RegId, i64),
    /// dst = src
    MovReg(RegId, RegId),
    /// dst = op(src1, src2)
    BinOp(RegId, BinOp, RegId, RegId),
    /// dst = op(src, imm)
    BinOpImm(RegId, BinOp, RegId, i64),
    /// FLAGS = cmp(a, b)
    CmpReg(RegId, RegId),
    /// FLAGS = cmp(reg, imm)
    CmpImm(RegId, i64),
    /// FLAGS = test(a, b) — AND without storing
    TestReg(RegId, RegId),
    /// FLAGS = test(reg, imm)
    TestImm(RegId, i64),
    /// Clobber a register (unknown value).
    Clobber(RegId),
    /// No effect on tracked registers.
    Nop,
}

/// Condition for a branch.
#[derive(Debug, Clone)]
pub struct BranchCond {
    pub cc: CondCode,
}

/// Extract SSA effects from x86 raw instruction bytes.
pub fn x86_effects(raw: &[u8], addr: u64) -> Vec<SsaEffect> {
    if raw.is_empty() {
        return vec![SsaEffect::Nop];
    }
    let mut decoder = iced_x86::Decoder::with_ip(
        64, raw, addr, iced_x86::DecoderOptions::NONE,
    );
    if !decoder.can_decode() {
        return vec![SsaEffect::Nop];
    }
    let instr = decoder.decode();
    extract_x86_effects(&instr)
}

fn extract_x86_effects(
    instr: &iced_x86::Instruction,
) -> Vec<SsaEffect> {
    use iced_x86::Mnemonic::*;
    match instr.mnemonic() {
        Mov => extract_mov(instr),
        Lea => extract_lea(instr),
        Xor if is_self_xor(instr) => extract_self_xor(instr),
        Add | Sub | And | Or | Xor => extract_alu(instr),
        Shl | Shr | Sar => extract_shift(instr),
        Imul => extract_imul(instr),
        Cmp => extract_cmp(instr),
        Test => extract_test(instr),
        Push | Pop | Call | Ret | Nop => vec![SsaEffect::Nop],
        _ => extract_clobbers(instr),
    }
}

fn extract_mov(
    instr: &iced_x86::Instruction,
) -> Vec<SsaEffect> {
    use iced_x86::OpKind;
    if instr.op_count() < 2 {
        return vec![SsaEffect::Nop];
    }
    let dst = instr.op_kind(0);
    let src = instr.op_kind(1);
    let dst_reg = match dst {
        OpKind::Register => x86_reg_id(instr.op_register(0)),
        _ => return vec![SsaEffect::Nop],
    };
    let dst_reg = match dst_reg {
        Some(r) => r,
        None => return vec![SsaEffect::Nop],
    };
    match src {
        OpKind::Register => {
            match x86_reg_id(instr.op_register(1)) {
                Some(s) => vec![SsaEffect::MovReg(dst_reg, s)],
                None => vec![SsaEffect::Clobber(dst_reg)],
            }
        }
        OpKind::Immediate8
        | OpKind::Immediate16
        | OpKind::Immediate32
        | OpKind::Immediate64
        | OpKind::Immediate8to16
        | OpKind::Immediate8to32
        | OpKind::Immediate8to64
        | OpKind::Immediate32to64 => {
            let imm = instr.immediate(1) as i64;
            vec![SsaEffect::MovConst(dst_reg, imm)]
        }
        _ => vec![SsaEffect::Clobber(dst_reg)],
    }
}

fn extract_lea(
    instr: &iced_x86::Instruction,
) -> Vec<SsaEffect> {
    let dst = match x86_reg_id(instr.op_register(0)) {
        Some(r) => r,
        None => return vec![SsaEffect::Nop],
    };
    vec![SsaEffect::Clobber(dst)]
}

fn extract_alu(
    instr: &iced_x86::Instruction,
) -> Vec<SsaEffect> {
    use iced_x86::{Mnemonic::*, OpKind};
    if instr.op_count() < 2 {
        return vec![SsaEffect::Nop];
    }
    let op = match instr.mnemonic() {
        Add => BinOp::Add,
        Sub => BinOp::Sub,
        And => BinOp::And,
        Or => BinOp::Or,
        Xor => BinOp::Xor,
        _ => return vec![SsaEffect::Nop],
    };
    let dst = match x86_reg_id(instr.op_register(0)) {
        Some(r) => r,
        None => return vec![SsaEffect::Nop],
    };
    let mut effects = Vec::new();
    match instr.op_kind(1) {
        OpKind::Register => {
            if let Some(s) = x86_reg_id(instr.op_register(1))
            {
                effects.push(SsaEffect::BinOp(
                    dst, op, dst, s,
                ));
            } else {
                effects.push(SsaEffect::Clobber(dst));
            }
        }
        OpKind::Immediate8
        | OpKind::Immediate16
        | OpKind::Immediate32
        | OpKind::Immediate8to16
        | OpKind::Immediate8to32
        | OpKind::Immediate8to64 => {
            let imm = instr.immediate(1) as i64;
            effects.push(SsaEffect::BinOpImm(
                dst, op, dst, imm,
            ));
        }
        _ => effects.push(SsaEffect::Clobber(dst)),
    }
    effects.push(SsaEffect::Clobber(FLAGS_REG));
    effects
}

fn extract_shift(
    instr: &iced_x86::Instruction,
) -> Vec<SsaEffect> {
    let dst = match x86_reg_id(instr.op_register(0)) {
        Some(r) => r,
        None => return vec![SsaEffect::Nop],
    };
    vec![
        SsaEffect::Clobber(dst),
        SsaEffect::Clobber(FLAGS_REG),
    ]
}

fn extract_imul(
    instr: &iced_x86::Instruction,
) -> Vec<SsaEffect> {
    let dst = match x86_reg_id(instr.op_register(0)) {
        Some(r) => r,
        None => return vec![SsaEffect::Nop],
    };
    vec![
        SsaEffect::Clobber(dst),
        SsaEffect::Clobber(FLAGS_REG),
    ]
}

fn extract_cmp(
    instr: &iced_x86::Instruction,
) -> Vec<SsaEffect> {
    use iced_x86::OpKind;
    if instr.op_count() < 2 {
        return vec![SsaEffect::Nop];
    }
    let a = match instr.op_kind(0) {
        OpKind::Register => x86_reg_id(instr.op_register(0)),
        _ => None,
    };
    match instr.op_kind(1) {
        OpKind::Register => {
            let b = x86_reg_id(instr.op_register(1));
            match (a, b) {
                (Some(ar), Some(br)) => {
                    vec![SsaEffect::CmpReg(ar, br)]
                }
                _ => vec![SsaEffect::Clobber(FLAGS_REG)],
            }
        }
        OpKind::Immediate8
        | OpKind::Immediate32
        | OpKind::Immediate8to32
        | OpKind::Immediate8to64 => {
            let imm = instr.immediate(1) as i64;
            match a {
                Some(ar) => {
                    vec![SsaEffect::CmpImm(ar, imm)]
                }
                None => {
                    vec![SsaEffect::Clobber(FLAGS_REG)]
                }
            }
        }
        _ => vec![SsaEffect::Clobber(FLAGS_REG)],
    }
}

fn extract_test(
    instr: &iced_x86::Instruction,
) -> Vec<SsaEffect> {
    use iced_x86::OpKind;
    if instr.op_count() < 2 {
        return vec![SsaEffect::Nop];
    }
    let a = match instr.op_kind(0) {
        OpKind::Register => x86_reg_id(instr.op_register(0)),
        _ => None,
    };
    match instr.op_kind(1) {
        OpKind::Register => {
            let b = x86_reg_id(instr.op_register(1));
            match (a, b) {
                (Some(ar), Some(br)) => {
                    vec![SsaEffect::TestReg(ar, br)]
                }
                _ => vec![SsaEffect::Clobber(FLAGS_REG)],
            }
        }
        OpKind::Immediate8
        | OpKind::Immediate32
        | OpKind::Immediate8to32 => {
            let imm = instr.immediate(1) as i64;
            match a {
                Some(ar) => {
                    vec![SsaEffect::TestImm(ar, imm)]
                }
                None => {
                    vec![SsaEffect::Clobber(FLAGS_REG)]
                }
            }
        }
        _ => vec![SsaEffect::Clobber(FLAGS_REG)],
    }
}

fn is_self_xor(instr: &iced_x86::Instruction) -> bool {
    instr.op_count() >= 2
        && instr.op_kind(0) == iced_x86::OpKind::Register
        && instr.op_kind(1) == iced_x86::OpKind::Register
        && instr.op_register(0) == instr.op_register(1)
}

fn extract_self_xor(
    instr: &iced_x86::Instruction,
) -> Vec<SsaEffect> {
    match x86_reg_id(instr.op_register(0)) {
        Some(r) => vec![
            SsaEffect::MovConst(r, 0),
            SsaEffect::Clobber(FLAGS_REG),
        ],
        None => vec![SsaEffect::Nop],
    }
}

fn extract_clobbers(
    instr: &iced_x86::Instruction,
) -> Vec<SsaEffect> {
    let mut factory = iced_x86::InstructionInfoFactory::new();
    let info = factory.info(instr);
    let mut effects = Vec::new();
    for reg in info.used_registers() {
        use iced_x86::OpAccess;
        if matches!(
            reg.access(),
            OpAccess::Write
                | OpAccess::CondWrite
                | OpAccess::ReadWrite
                | OpAccess::ReadCondWrite
        ) {
            if let Some(r) = x86_reg_id(reg.register()) {
                effects.push(SsaEffect::Clobber(r));
            }
        }
    }
    if effects.is_empty() {
        effects.push(SsaEffect::Nop);
    }
    effects
}

/// Map x86 register to abstract register ID.
fn x86_reg_id(reg: iced_x86::Register) -> Option<RegId> {
    use iced_x86::Register as R;
    match reg {
        R::RAX | R::EAX | R::AX | R::AL | R::AH => Some(0),
        R::RCX | R::ECX | R::CX | R::CL | R::CH => Some(1),
        R::RDX | R::EDX | R::DX | R::DL | R::DH => Some(2),
        R::RBX | R::EBX | R::BX | R::BL | R::BH => Some(3),
        R::RSP | R::ESP | R::SP | R::SPL => Some(4),
        R::RBP | R::EBP | R::BP | R::BPL => Some(5),
        R::RSI | R::ESI | R::SI | R::SIL => Some(6),
        R::RDI | R::EDI | R::DI | R::DIL => Some(7),
        R::R8 | R::R8D | R::R8W | R::R8L => Some(8),
        R::R9 | R::R9D | R::R9W | R::R9L => Some(9),
        R::R10 | R::R10D | R::R10W | R::R10L => Some(10),
        R::R11 | R::R11D | R::R11W | R::R11L => Some(11),
        R::R12 | R::R12D | R::R12W | R::R12L => Some(12),
        R::R13 | R::R13D | R::R13W | R::R13L => Some(13),
        R::R14 | R::R14D | R::R14W | R::R14L => Some(14),
        R::R15 | R::R15D | R::R15W | R::R15L => Some(15),
        _ => Option::None,
    }
}

/// Map x86 Jcc condition to CondCode.
pub fn x86_branch_cond(raw: &[u8]) -> Option<BranchCond> {
    if raw.is_empty() {
        return None;
    }
    let cc = match raw[0] {
        0x74 | 0x75 => {
            if raw[0] == 0x74 {
                CondCode::Eq
            } else {
                CondCode::Ne
            }
        }
        0x7C | 0x7D => {
            if raw[0] == 0x7C {
                CondCode::Lt
            } else {
                CondCode::Ge
            }
        }
        0x7E | 0x7F => {
            if raw[0] == 0x7E {
                CondCode::Le
            } else {
                CondCode::Gt
            }
        }
        0x72 | 0x73 => {
            if raw[0] == 0x72 {
                CondCode::Ltu
            } else {
                CondCode::Geu
            }
        }
        0x0F if raw.len() >= 2 => {
            decode_0f_condition(raw[1])?
        }
        _ => return None,
    };
    Some(BranchCond { cc })
}

fn decode_0f_condition(byte: u8) -> Option<CondCode> {
    match byte {
        0x84 => Some(CondCode::Eq),
        0x85 => Some(CondCode::Ne),
        0x8C => Some(CondCode::Lt),
        0x8D => Some(CondCode::Ge),
        0x8E => Some(CondCode::Le),
        0x8F => Some(CondCode::Gt),
        0x82 => Some(CondCode::Ltu),
        0x83 => Some(CondCode::Geu),
        _ => None,
    }
}

/// x86 caller-saved registers (clobbered at call sites).
pub const X86_CALLER_SAVED: &[RegId] =
    &[0, 1, 2, 6, 7, 8, 9, 10, 11, FLAGS_REG];
