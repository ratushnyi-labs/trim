use crate::analysis::lattice::{BinOp, CondCode};
use crate::types::Arch;

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

// ===== Multi-architecture SCCP effect dispatch =====

/// Dispatch to architecture-specific instruction effects.
pub fn arch_effects(
    raw: &[u8],
    addr: u64,
    arch: Arch,
    big_endian: bool,
) -> Vec<SsaEffect> {
    match arch {
        Arch::X86_64 | Arch::X86_32 => x86_effects(raw, addr),
        Arch::Aarch64 => aarch64_effects(raw),
        Arch::Arm32 => arm32_effects(raw),
        Arch::RiscV64 | Arch::RiscV32 => riscv_effects(raw),
        Arch::Mips32 | Arch::Mips64 => {
            mips_effects(raw, big_endian)
        }
        Arch::S390x => s390x_effects(raw),
        Arch::LoongArch64 => loongarch_effects(raw),
    }
}

/// Dispatch to architecture-specific caller-saved register set.
pub fn caller_saved(arch: Arch) -> &'static [RegId] {
    match arch {
        Arch::X86_64 | Arch::X86_32 => X86_CALLER_SAVED,
        Arch::Aarch64 => AARCH64_CALLER_SAVED,
        Arch::Arm32 => ARM32_CALLER_SAVED,
        Arch::RiscV64 | Arch::RiscV32 => RISCV_CALLER_SAVED,
        Arch::Mips32 | Arch::Mips64 => MIPS_CALLER_SAVED,
        Arch::S390x => S390X_CALLER_SAVED,
        Arch::LoongArch64 => LOONGARCH_CALLER_SAVED,
    }
}

// ===== AArch64 =====

/// AArch64 caller-saved: X0-X15, FLAGS.
pub const AARCH64_CALLER_SAVED: &[RegId] = &[
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    FLAGS_REG,
];

fn aarch64_reg_id(reg: u32) -> Option<RegId> {
    if reg <= 15 {
        Some(reg as RegId)
    } else {
        None
    }
}

fn aarch64_effects(raw: &[u8]) -> Vec<SsaEffect> {
    if raw.len() < 4 {
        return vec![SsaEffect::Nop];
    }
    let w = u32::from_le_bytes(
        raw[..4].try_into().unwrap_or([0; 4]),
    );
    // Move wide immediate: bits[28:23] = 100101
    if (w >> 23) & 0x3F == 0x25 {
        return a64_movwide(w);
    }
    // Add/sub immediate: bits[28:24] = 10001
    if (w >> 24) & 0x1F == 0x11 {
        return a64_addsub_imm(w);
    }
    // Add/sub shifted register: bits[28:24] = 01011
    if (w >> 24) & 0x1F == 0x0B {
        return a64_addsub_reg(w);
    }
    // Logical shifted register: bits[28:24] = 01010
    if (w >> 24) & 0x1F == 0x0A {
        return a64_logical_reg(w);
    }
    vec![SsaEffect::Nop]
}

fn a64_movwide(w: u32) -> Vec<SsaEffect> {
    let opc = (w >> 29) & 0x3;
    let hw = (w >> 21) & 0x3;
    let imm16 = ((w >> 5) & 0xFFFF) as u64;
    let rd = w & 0x1F;
    let rd_id = match aarch64_reg_id(rd) {
        Some(r) => r,
        None => return vec![SsaEffect::Nop],
    };
    let shift = hw * 16;
    match opc {
        0b10 => vec![SsaEffect::MovConst(
            rd_id,
            (imm16 << shift) as i64,
        )],
        0b00 => vec![SsaEffect::MovConst(
            rd_id,
            !((imm16 << shift) as i64),
        )],
        _ => vec![SsaEffect::Clobber(rd_id)],
    }
}

fn a64_addsub_imm(w: u32) -> Vec<SsaEffect> {
    let op = (w >> 30) & 1;
    let s_flag = (w >> 29) & 1;
    let sh = (w >> 22) & 1;
    let imm12 = ((w >> 10) & 0xFFF) as i64;
    let imm = if sh == 1 { imm12 << 12 } else { imm12 };
    let rn = (w >> 5) & 0x1F;
    let rd = w & 0x1F;
    if rd == 31 && s_flag == 1 {
        if op == 1 {
            if let Some(rn_id) = aarch64_reg_id(rn) {
                return vec![SsaEffect::CmpImm(rn_id, imm)];
            }
        }
        return vec![SsaEffect::Clobber(FLAGS_REG)];
    }
    let rd_id = match aarch64_reg_id(rd) {
        Some(r) => r,
        None => {
            return if s_flag == 1 {
                vec![SsaEffect::Clobber(FLAGS_REG)]
            } else {
                vec![SsaEffect::Nop]
            };
        }
    };
    let bin_op =
        if op == 1 { BinOp::Sub } else { BinOp::Add };
    let mut effects = Vec::new();
    if let Some(rn_id) = aarch64_reg_id(rn) {
        effects.push(SsaEffect::BinOpImm(
            rd_id, bin_op, rn_id, imm,
        ));
    } else {
        effects.push(SsaEffect::Clobber(rd_id));
    }
    if s_flag == 1 {
        effects.push(SsaEffect::Clobber(FLAGS_REG));
    }
    effects
}

fn a64_addsub_reg(w: u32) -> Vec<SsaEffect> {
    let op = (w >> 30) & 1;
    let s_flag = (w >> 29) & 1;
    let rm = (w >> 16) & 0x1F;
    let rn = (w >> 5) & 0x1F;
    let rd = w & 0x1F;
    if rd == 31 && s_flag == 1 && op == 1 {
        if let (Some(a), Some(b)) =
            (aarch64_reg_id(rn), aarch64_reg_id(rm))
        {
            return vec![SsaEffect::CmpReg(a, b)];
        }
        return vec![SsaEffect::Clobber(FLAGS_REG)];
    }
    let rd_id = match aarch64_reg_id(rd) {
        Some(r) => r,
        None => {
            return if s_flag == 1 {
                vec![SsaEffect::Clobber(FLAGS_REG)]
            } else {
                vec![SsaEffect::Nop]
            };
        }
    };
    let bin_op =
        if op == 1 { BinOp::Sub } else { BinOp::Add };
    let mut effects = Vec::new();
    match (aarch64_reg_id(rn), aarch64_reg_id(rm)) {
        (Some(a), Some(b)) => {
            effects
                .push(SsaEffect::BinOp(rd_id, bin_op, a, b));
        }
        _ => effects.push(SsaEffect::Clobber(rd_id)),
    }
    if s_flag == 1 {
        effects.push(SsaEffect::Clobber(FLAGS_REG));
    }
    effects
}

fn a64_logical_reg(w: u32) -> Vec<SsaEffect> {
    let opc = (w >> 29) & 0x3;
    let n_bit = (w >> 21) & 1;
    let rm = (w >> 16) & 0x1F;
    let imm6 = (w >> 10) & 0x3F;
    let rn = (w >> 5) & 0x1F;
    let rd = w & 0x1F;
    // ORR Xd, XZR, Xm (no shift) = MOV
    if opc == 0b01 && rn == 31 && imm6 == 0 && n_bit == 0
    {
        if let (Some(r), Some(s)) =
            (aarch64_reg_id(rd), aarch64_reg_id(rm))
        {
            return vec![SsaEffect::MovReg(r, s)];
        }
        if let Some(r) = aarch64_reg_id(rd) {
            return vec![SsaEffect::Clobber(r)];
        }
        return vec![SsaEffect::Nop];
    }
    // ANDS Rd=31 = TST
    if opc == 0b11 && rd == 31 {
        if imm6 == 0 && n_bit == 0 {
            if let (Some(a), Some(b)) =
                (aarch64_reg_id(rn), aarch64_reg_id(rm))
            {
                return vec![SsaEffect::TestReg(a, b)];
            }
        }
        return vec![SsaEffect::Clobber(FLAGS_REG)];
    }
    let rd_id = match aarch64_reg_id(rd) {
        Some(r) => r,
        None => {
            return if opc == 0b11 {
                vec![SsaEffect::Clobber(FLAGS_REG)]
            } else {
                vec![SsaEffect::Nop]
            };
        }
    };
    let bin_op = match opc {
        0b00 | 0b11 => BinOp::And,
        0b01 => BinOp::Or,
        _ => BinOp::Xor,
    };
    let mut effects = Vec::new();
    if imm6 == 0 && n_bit == 0 {
        if let (Some(a), Some(b)) =
            (aarch64_reg_id(rn), aarch64_reg_id(rm))
        {
            effects.push(SsaEffect::BinOp(
                rd_id, bin_op, a, b,
            ));
        } else {
            effects.push(SsaEffect::Clobber(rd_id));
        }
    } else {
        effects.push(SsaEffect::Clobber(rd_id));
    }
    if opc == 0b11 {
        effects.push(SsaEffect::Clobber(FLAGS_REG));
    }
    effects
}

// ===== ARM32 =====

/// ARM32 caller-saved: R0-R3, R12(IP), R14(LR), FLAGS.
pub const ARM32_CALLER_SAVED: &[RegId] =
    &[0, 1, 2, 3, 12, 14, FLAGS_REG];

fn arm32_reg_id(reg: u32) -> Option<RegId> {
    if reg <= 15 {
        Some(reg as RegId)
    } else {
        None
    }
}

fn arm32_effects(raw: &[u8]) -> Vec<SsaEffect> {
    if raw.len() < 4 {
        return vec![SsaEffect::Nop];
    }
    let w = u32::from_le_bytes(
        raw[..4].try_into().unwrap_or([0; 4]),
    );
    let cond = w >> 28;
    if cond == 0xF {
        return vec![SsaEffect::Nop];
    }
    // Data processing: bits[27:26] = 00
    if (w >> 26) & 0x3 != 0 {
        return vec![SsaEffect::Nop];
    }
    let i_bit = (w >> 25) & 1;
    let opcode = (w >> 21) & 0xF;
    let s_flag = (w >> 20) & 1;
    let rn = (w >> 16) & 0xF;
    let rd = (w >> 12) & 0xF;
    arm32_dp(w, i_bit, opcode, s_flag, rn, rd)
}

fn arm32_dp(
    w: u32,
    i_bit: u32,
    opcode: u32,
    s_flag: u32,
    rn: u32,
    rd: u32,
) -> Vec<SsaEffect> {
    let (op2_val, op2_reg) = if i_bit == 1 {
        let rotate = ((w >> 8) & 0xF) * 2;
        let imm8 = (w & 0xFF) as u32;
        (Some(imm8.rotate_right(rotate) as i64), None)
    } else {
        let rm = w & 0xF;
        let shift_type = (w >> 5) & 0x3;
        let shift_imm = (w >> 7) & 0x1F;
        if shift_imm == 0 && shift_type == 0 {
            (None, arm32_reg_id(rm))
        } else {
            (None, None)
        }
    };
    match opcode {
        0xD => arm32_mov(rd, s_flag, op2_val, op2_reg),
        0xF => arm32_mvn(rd, s_flag, op2_val),
        0x4 => arm32_addsub(
            BinOp::Add, rd, rn, s_flag, op2_val, op2_reg,
        ),
        0x2 => arm32_addsub(
            BinOp::Sub, rd, rn, s_flag, op2_val, op2_reg,
        ),
        0x0 => arm32_logic(
            BinOp::And, rd, rn, s_flag, op2_val, op2_reg,
        ),
        0x1 => arm32_logic(
            BinOp::Xor, rd, rn, s_flag, op2_val, op2_reg,
        ),
        0xC => arm32_logic(
            BinOp::Or, rd, rn, s_flag, op2_val, op2_reg,
        ),
        0xA => arm32_cmp(rn, op2_val, op2_reg),
        0x8 => arm32_tst(rn, op2_val, op2_reg),
        _ => vec![SsaEffect::Nop],
    }
}

fn arm32_mov(
    rd: u32,
    s_flag: u32,
    op2_val: Option<i64>,
    op2_reg: Option<RegId>,
) -> Vec<SsaEffect> {
    let rd_id = match arm32_reg_id(rd) {
        Some(r) => r,
        None => return vec![SsaEffect::Nop],
    };
    let mut effects = Vec::new();
    if let Some(val) = op2_val {
        effects.push(SsaEffect::MovConst(rd_id, val));
    } else if let Some(rm) = op2_reg {
        effects.push(SsaEffect::MovReg(rd_id, rm));
    } else {
        effects.push(SsaEffect::Clobber(rd_id));
    }
    if s_flag == 1 {
        effects.push(SsaEffect::Clobber(FLAGS_REG));
    }
    effects
}

fn arm32_mvn(
    rd: u32,
    s_flag: u32,
    op2_val: Option<i64>,
) -> Vec<SsaEffect> {
    let rd_id = match arm32_reg_id(rd) {
        Some(r) => r,
        None => return vec![SsaEffect::Nop],
    };
    let mut effects = Vec::new();
    if let Some(val) = op2_val {
        effects.push(SsaEffect::MovConst(rd_id, !val));
    } else {
        effects.push(SsaEffect::Clobber(rd_id));
    }
    if s_flag == 1 {
        effects.push(SsaEffect::Clobber(FLAGS_REG));
    }
    effects
}

fn arm32_addsub(
    op: BinOp,
    rd: u32,
    rn: u32,
    s_flag: u32,
    op2_val: Option<i64>,
    op2_reg: Option<RegId>,
) -> Vec<SsaEffect> {
    let rd_id = match arm32_reg_id(rd) {
        Some(r) => r,
        None => {
            return if s_flag == 1 {
                vec![SsaEffect::Clobber(FLAGS_REG)]
            } else {
                vec![SsaEffect::Nop]
            };
        }
    };
    let rn_opt = arm32_reg_id(rn);
    let mut effects = Vec::new();
    if let (Some(rn_id), Some(val)) = (rn_opt, op2_val) {
        effects.push(SsaEffect::BinOpImm(
            rd_id, op, rn_id, val,
        ));
    } else if let (Some(rn_id), Some(rm)) =
        (rn_opt, op2_reg)
    {
        effects.push(SsaEffect::BinOp(
            rd_id, op, rn_id, rm,
        ));
    } else {
        effects.push(SsaEffect::Clobber(rd_id));
    }
    if s_flag == 1 {
        effects.push(SsaEffect::Clobber(FLAGS_REG));
    }
    effects
}

fn arm32_logic(
    op: BinOp,
    rd: u32,
    rn: u32,
    s_flag: u32,
    op2_val: Option<i64>,
    op2_reg: Option<RegId>,
) -> Vec<SsaEffect> {
    let rd_id = match arm32_reg_id(rd) {
        Some(r) => r,
        None => {
            return if s_flag == 1 {
                vec![SsaEffect::Clobber(FLAGS_REG)]
            } else {
                vec![SsaEffect::Nop]
            };
        }
    };
    let rn_opt = arm32_reg_id(rn);
    let mut effects = Vec::new();
    if let (Some(rn_id), Some(val)) = (rn_opt, op2_val) {
        effects.push(SsaEffect::BinOpImm(
            rd_id, op, rn_id, val,
        ));
    } else if let (Some(rn_id), Some(rm)) =
        (rn_opt, op2_reg)
    {
        effects.push(SsaEffect::BinOp(
            rd_id, op, rn_id, rm,
        ));
    } else {
        effects.push(SsaEffect::Clobber(rd_id));
    }
    if s_flag == 1 {
        effects.push(SsaEffect::Clobber(FLAGS_REG));
    }
    effects
}

fn arm32_cmp(
    rn: u32,
    op2_val: Option<i64>,
    op2_reg: Option<RegId>,
) -> Vec<SsaEffect> {
    if let Some(rn_id) = arm32_reg_id(rn) {
        if let Some(val) = op2_val {
            return vec![SsaEffect::CmpImm(rn_id, val)];
        }
        if let Some(rm) = op2_reg {
            return vec![SsaEffect::CmpReg(rn_id, rm)];
        }
    }
    vec![SsaEffect::Clobber(FLAGS_REG)]
}

fn arm32_tst(
    rn: u32,
    op2_val: Option<i64>,
    op2_reg: Option<RegId>,
) -> Vec<SsaEffect> {
    if let Some(rn_id) = arm32_reg_id(rn) {
        if let Some(val) = op2_val {
            return vec![SsaEffect::TestImm(rn_id, val)];
        }
        if let Some(rm) = op2_reg {
            return vec![SsaEffect::TestReg(rn_id, rm)];
        }
    }
    vec![SsaEffect::Clobber(FLAGS_REG)]
}

// ===== RISC-V =====

/// RISC-V caller-saved: x1(ra), x5-x7(t0-t2),
/// x10-x15(a0-a5), FLAGS.
pub const RISCV_CALLER_SAVED: &[RegId] =
    &[1, 5, 6, 7, 10, 11, 12, 13, 14, 15, FLAGS_REG];

/// Map RISC-V register to RegId. x0 (zero) returns None.
fn riscv_reg_id(reg: u32) -> Option<RegId> {
    if reg >= 1 && reg <= 15 {
        Some(reg as RegId)
    } else {
        None
    }
}

fn riscv_effects(raw: &[u8]) -> Vec<SsaEffect> {
    if raw.len() < 2 {
        return vec![SsaEffect::Nop];
    }
    let lo2 = raw[0] & 0x03;
    if lo2 != 0x03 {
        let hw = u16::from_le_bytes(
            raw[..2].try_into().unwrap_or([0; 2]),
        );
        return rv_compressed(hw);
    }
    if raw.len() < 4 {
        return vec![SsaEffect::Nop];
    }
    let w = u32::from_le_bytes(
        raw[..4].try_into().unwrap_or([0; 4]),
    );
    rv_word(w)
}

fn rv_word(w: u32) -> Vec<SsaEffect> {
    let opcode = w & 0x7F;
    match opcode {
        0x37 => rv_lui(w),
        0x13 => rv_imm(w),
        0x33 => rv_reg(w),
        0x63 => rv_branch(w),
        _ => vec![SsaEffect::Nop],
    }
}

fn rv_lui(w: u32) -> Vec<SsaEffect> {
    let rd = (w >> 7) & 0x1F;
    if rd == 0 {
        return vec![SsaEffect::Nop];
    }
    let rd_id = match riscv_reg_id(rd) {
        Some(r) => r,
        None => return vec![SsaEffect::Nop],
    };
    let imm = (w & 0xFFFFF000) as i32 as i64;
    vec![SsaEffect::MovConst(rd_id, imm)]
}

fn rv_imm(w: u32) -> Vec<SsaEffect> {
    let funct3 = (w >> 12) & 0x7;
    let rd = (w >> 7) & 0x1F;
    let rs1 = (w >> 15) & 0x1F;
    let imm = ((w as i32) >> 20) as i64;
    if rd == 0 {
        return vec![SsaEffect::Nop];
    }
    let rd_id = match riscv_reg_id(rd) {
        Some(r) => r,
        None => return vec![SsaEffect::Nop],
    };
    match funct3 {
        0b000 => {
            // ADDI
            if rs1 == 0 {
                vec![SsaEffect::MovConst(rd_id, imm)]
            } else if let Some(s) = riscv_reg_id(rs1) {
                if imm == 0 {
                    vec![SsaEffect::MovReg(rd_id, s)]
                } else {
                    vec![SsaEffect::BinOpImm(
                        rd_id,
                        BinOp::Add,
                        s,
                        imm,
                    )]
                }
            } else {
                vec![SsaEffect::Clobber(rd_id)]
            }
        }
        0b111 => rv_imm_op(rd_id, rs1, imm, BinOp::And),
        0b110 => rv_imm_op(rd_id, rs1, imm, BinOp::Or),
        0b100 => rv_imm_op(rd_id, rs1, imm, BinOp::Xor),
        _ => vec![SsaEffect::Clobber(rd_id)],
    }
}

fn rv_imm_op(
    rd_id: RegId,
    rs1: u32,
    imm: i64,
    op: BinOp,
) -> Vec<SsaEffect> {
    if rs1 == 0 {
        let val = match op {
            BinOp::And => 0i64 & imm,
            BinOp::Or | BinOp::Xor => imm,
            _ => 0,
        };
        return vec![SsaEffect::MovConst(rd_id, val)];
    }
    if let Some(s) = riscv_reg_id(rs1) {
        vec![SsaEffect::BinOpImm(rd_id, op, s, imm)]
    } else {
        vec![SsaEffect::Clobber(rd_id)]
    }
}

fn rv_reg(w: u32) -> Vec<SsaEffect> {
    let funct3 = (w >> 12) & 0x7;
    let funct7 = (w >> 25) & 0x7F;
    let rd = (w >> 7) & 0x1F;
    let rs1 = (w >> 15) & 0x1F;
    let rs2 = (w >> 20) & 0x1F;
    if rd == 0 {
        return vec![SsaEffect::Nop];
    }
    let rd_id = match riscv_reg_id(rd) {
        Some(r) => r,
        None => return vec![SsaEffect::Nop],
    };
    match (funct3, funct7) {
        (0b000, 0b0000000) => {
            // ADD
            rv_add(rd_id, rs1, rs2)
        }
        (0b000, 0b0100000) => {
            // SUB
            rv_binop_reg(rd_id, rs1, rs2, BinOp::Sub)
        }
        (0b111, 0b0000000) => {
            rv_binop_reg(rd_id, rs1, rs2, BinOp::And)
        }
        (0b110, 0b0000000) => {
            rv_binop_reg(rd_id, rs1, rs2, BinOp::Or)
        }
        (0b100, 0b0000000) => {
            rv_binop_reg(rd_id, rs1, rs2, BinOp::Xor)
        }
        _ => vec![SsaEffect::Clobber(rd_id)],
    }
}

fn rv_add(
    rd_id: RegId,
    rs1: u32,
    rs2: u32,
) -> Vec<SsaEffect> {
    if rs1 == 0 && rs2 == 0 {
        return vec![SsaEffect::MovConst(rd_id, 0)];
    }
    if rs1 == 0 {
        return match riscv_reg_id(rs2) {
            Some(s) => vec![SsaEffect::MovReg(rd_id, s)],
            None => vec![SsaEffect::Clobber(rd_id)],
        };
    }
    if rs2 == 0 {
        return match riscv_reg_id(rs1) {
            Some(s) => vec![SsaEffect::MovReg(rd_id, s)],
            None => vec![SsaEffect::Clobber(rd_id)],
        };
    }
    rv_binop_reg(rd_id, rs1, rs2, BinOp::Add)
}

fn rv_binop_reg(
    rd_id: RegId,
    rs1: u32,
    rs2: u32,
    op: BinOp,
) -> Vec<SsaEffect> {
    match (riscv_reg_id(rs1), riscv_reg_id(rs2)) {
        (Some(a), Some(b)) => {
            vec![SsaEffect::BinOp(rd_id, op, a, b)]
        }
        _ => vec![SsaEffect::Clobber(rd_id)],
    }
}

fn rv_branch(w: u32) -> Vec<SsaEffect> {
    let rs1 = (w >> 15) & 0x1F;
    let rs2 = (w >> 20) & 0x1F;
    if rs2 == 0 {
        if let Some(id) = riscv_reg_id(rs1) {
            return vec![SsaEffect::CmpImm(id, 0)];
        }
    }
    if rs1 == 0 {
        if let Some(id) = riscv_reg_id(rs2) {
            return vec![SsaEffect::CmpImm(id, 0)];
        }
    }
    match (riscv_reg_id(rs1), riscv_reg_id(rs2)) {
        (Some(a), Some(b)) => {
            vec![SsaEffect::CmpReg(a, b)]
        }
        _ => vec![SsaEffect::Clobber(FLAGS_REG)],
    }
}

fn rv_compressed(hw: u16) -> Vec<SsaEffect> {
    let op = hw & 0x03;
    let funct3 = (hw >> 13) & 0x07;
    match (op, funct3) {
        (0x01, 0x02) => rv_c_li(hw),
        (0x01, 0x00) => rv_c_addi(hw),
        (0x02, 0x04) => rv_c_mv_add(hw),
        _ => vec![SsaEffect::Nop],
    }
}

fn rv_c_li(hw: u16) -> Vec<SsaEffect> {
    let rd = ((hw >> 7) & 0x1F) as u32;
    if rd == 0 {
        return vec![SsaEffect::Nop];
    }
    let rd_id = match riscv_reg_id(rd) {
        Some(r) => r,
        None => return vec![SsaEffect::Nop],
    };
    let lo = ((hw >> 2) & 0x1F) as i64;
    let sign = ((hw >> 12) & 1) as i64;
    let imm = if sign == 1 { lo | !0x1F_i64 } else { lo };
    vec![SsaEffect::MovConst(rd_id, imm)]
}

fn rv_c_addi(hw: u16) -> Vec<SsaEffect> {
    let rd = ((hw >> 7) & 0x1F) as u32;
    if rd == 0 {
        return vec![SsaEffect::Nop];
    }
    let rd_id = match riscv_reg_id(rd) {
        Some(r) => r,
        None => return vec![SsaEffect::Nop],
    };
    let lo = ((hw >> 2) & 0x1F) as i64;
    let sign = ((hw >> 12) & 1) as i64;
    let imm = if sign == 1 { lo | !0x1F_i64 } else { lo };
    if imm == 0 {
        return vec![SsaEffect::Nop];
    }
    vec![SsaEffect::BinOpImm(
        rd_id,
        BinOp::Add,
        rd_id,
        imm,
    )]
}

fn rv_c_mv_add(hw: u16) -> Vec<SsaEffect> {
    let bit12 = (hw >> 12) & 1;
    let rd = ((hw >> 7) & 0x1F) as u32;
    let rs2 = ((hw >> 2) & 0x1F) as u32;
    if rs2 == 0 || rd == 0 {
        return vec![SsaEffect::Nop];
    }
    let rd_id = match riscv_reg_id(rd) {
        Some(r) => r,
        None => return vec![SsaEffect::Nop],
    };
    if bit12 == 0 {
        // C.MV
        match riscv_reg_id(rs2) {
            Some(s) => vec![SsaEffect::MovReg(rd_id, s)],
            None => vec![SsaEffect::Clobber(rd_id)],
        }
    } else {
        // C.ADD
        match riscv_reg_id(rs2) {
            Some(s) => vec![SsaEffect::BinOp(
                rd_id,
                BinOp::Add,
                rd_id,
                s,
            )],
            None => vec![SsaEffect::Clobber(rd_id)],
        }
    }
}

// ===== MIPS =====

/// MIPS caller-saved: $1(at), $2-$15(v0..t7), FLAGS.
pub const MIPS_CALLER_SAVED: &[RegId] = &[
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    FLAGS_REG,
];

/// Map MIPS register to RegId. $0 (zero) returns None.
fn mips_reg_id(reg: u32) -> Option<RegId> {
    if reg >= 1 && reg <= 15 {
        Some(reg as RegId)
    } else {
        None
    }
}

fn mips_effects(
    raw: &[u8],
    big_endian: bool,
) -> Vec<SsaEffect> {
    if raw.len() < 4 {
        return vec![SsaEffect::Nop];
    }
    let w = if big_endian {
        u32::from_be_bytes(
            raw[..4].try_into().unwrap_or([0; 4]),
        )
    } else {
        u32::from_le_bytes(
            raw[..4].try_into().unwrap_or([0; 4]),
        )
    };
    let op = w >> 26;
    match op {
        0x00 => mips_special(w),
        0x09 => mips_addiu(w),
        0x0C => mips_andi(w),
        0x0D => mips_ori(w),
        0x0E => mips_xori(w),
        0x0F => mips_lui(w),
        0x04 | 0x05 => mips_branch(w),
        _ => vec![SsaEffect::Nop],
    }
}

fn mips_lui(w: u32) -> Vec<SsaEffect> {
    let rt = (w >> 16) & 0x1F;
    if let Some(r) = mips_reg_id(rt) {
        let imm16 = (w & 0xFFFF) as i64;
        vec![SsaEffect::MovConst(r, imm16 << 16)]
    } else {
        vec![SsaEffect::Nop]
    }
}

fn mips_addiu(w: u32) -> Vec<SsaEffect> {
    let rs = (w >> 21) & 0x1F;
    let rt = (w >> 16) & 0x1F;
    let imm = (w & 0xFFFF) as i16 as i64;
    let rt_id = match mips_reg_id(rt) {
        Some(r) => r,
        None => return vec![SsaEffect::Nop],
    };
    if rs == 0 {
        vec![SsaEffect::MovConst(rt_id, imm)]
    } else if let Some(rs_id) = mips_reg_id(rs) {
        vec![SsaEffect::BinOpImm(
            rt_id,
            BinOp::Add,
            rs_id,
            imm,
        )]
    } else {
        vec![SsaEffect::Clobber(rt_id)]
    }
}

fn mips_andi(w: u32) -> Vec<SsaEffect> {
    let rs = (w >> 21) & 0x1F;
    let rt = (w >> 16) & 0x1F;
    let imm = (w & 0xFFFF) as i64; // zero-extended
    let rt_id = match mips_reg_id(rt) {
        Some(r) => r,
        None => return vec![SsaEffect::Nop],
    };
    if rs == 0 {
        vec![SsaEffect::MovConst(rt_id, 0)]
    } else if let Some(rs_id) = mips_reg_id(rs) {
        vec![SsaEffect::BinOpImm(
            rt_id,
            BinOp::And,
            rs_id,
            imm,
        )]
    } else {
        vec![SsaEffect::Clobber(rt_id)]
    }
}

fn mips_ori(w: u32) -> Vec<SsaEffect> {
    let rs = (w >> 21) & 0x1F;
    let rt = (w >> 16) & 0x1F;
    let imm = (w & 0xFFFF) as i64; // zero-extended
    let rt_id = match mips_reg_id(rt) {
        Some(r) => r,
        None => return vec![SsaEffect::Nop],
    };
    if rs == 0 {
        vec![SsaEffect::MovConst(rt_id, imm)]
    } else if let Some(rs_id) = mips_reg_id(rs) {
        vec![SsaEffect::BinOpImm(
            rt_id,
            BinOp::Or,
            rs_id,
            imm,
        )]
    } else {
        vec![SsaEffect::Clobber(rt_id)]
    }
}

fn mips_xori(w: u32) -> Vec<SsaEffect> {
    let rs = (w >> 21) & 0x1F;
    let rt = (w >> 16) & 0x1F;
    let imm = (w & 0xFFFF) as i64; // zero-extended
    let rt_id = match mips_reg_id(rt) {
        Some(r) => r,
        None => return vec![SsaEffect::Nop],
    };
    if rs == 0 {
        vec![SsaEffect::MovConst(rt_id, imm)]
    } else if let Some(rs_id) = mips_reg_id(rs) {
        vec![SsaEffect::BinOpImm(
            rt_id,
            BinOp::Xor,
            rs_id,
            imm,
        )]
    } else {
        vec![SsaEffect::Clobber(rt_id)]
    }
}

fn mips_special(w: u32) -> Vec<SsaEffect> {
    let funct = w & 0x3F;
    let rs = (w >> 21) & 0x1F;
    let rt = (w >> 16) & 0x1F;
    let rd = (w >> 11) & 0x1F;
    let rd_id = match mips_reg_id(rd) {
        Some(r) => r,
        None => return vec![SsaEffect::Nop],
    };
    match funct {
        0x21 => {
            // ADDU
            if rs == 0 && rt == 0 {
                vec![SsaEffect::MovConst(rd_id, 0)]
            } else if rs == 0 {
                match mips_reg_id(rt) {
                    Some(s) => {
                        vec![SsaEffect::MovReg(rd_id, s)]
                    }
                    None => {
                        vec![SsaEffect::Clobber(rd_id)]
                    }
                }
            } else if rt == 0 {
                match mips_reg_id(rs) {
                    Some(s) => {
                        vec![SsaEffect::MovReg(rd_id, s)]
                    }
                    None => {
                        vec![SsaEffect::Clobber(rd_id)]
                    }
                }
            } else {
                mips_binop_r(rd_id, rs, rt, BinOp::Add)
            }
        }
        0x23 => mips_binop_r(rd_id, rs, rt, BinOp::Sub),
        0x24 => mips_binop_r(rd_id, rs, rt, BinOp::And),
        0x25 => mips_binop_r(rd_id, rs, rt, BinOp::Or),
        0x26 => mips_binop_r(rd_id, rs, rt, BinOp::Xor),
        _ => vec![SsaEffect::Clobber(rd_id)],
    }
}

fn mips_binop_r(
    rd_id: RegId,
    rs: u32,
    rt: u32,
    op: BinOp,
) -> Vec<SsaEffect> {
    match (mips_reg_id(rs), mips_reg_id(rt)) {
        (Some(a), Some(b)) => {
            vec![SsaEffect::BinOp(rd_id, op, a, b)]
        }
        _ => vec![SsaEffect::Clobber(rd_id)],
    }
}

fn mips_branch(w: u32) -> Vec<SsaEffect> {
    let rs = (w >> 21) & 0x1F;
    let rt = (w >> 16) & 0x1F;
    if rt == 0 {
        if let Some(id) = mips_reg_id(rs) {
            return vec![SsaEffect::CmpImm(id, 0)];
        }
    }
    if rs == 0 {
        if let Some(id) = mips_reg_id(rt) {
            return vec![SsaEffect::CmpImm(id, 0)];
        }
    }
    match (mips_reg_id(rs), mips_reg_id(rt)) {
        (Some(a), Some(b)) => {
            vec![SsaEffect::CmpReg(a, b)]
        }
        _ => vec![SsaEffect::Clobber(FLAGS_REG)],
    }
}

// ===== s390x =====

/// s390x caller-saved: R0-R5, R14(LR), FLAGS.
pub const S390X_CALLER_SAVED: &[RegId] =
    &[0, 1, 2, 3, 4, 5, 14, FLAGS_REG];

fn s390x_reg_id(reg: u8) -> Option<RegId> {
    if reg <= 15 {
        Some(reg as RegId)
    } else {
        None
    }
}

fn s390x_effects(raw: &[u8]) -> Vec<SsaEffect> {
    match raw.len() {
        2 => s390x_rr(raw),
        4 => s390x_4byte(raw),
        6 => s390x_6byte(raw),
        _ => vec![SsaEffect::Nop],
    }
}

fn s390x_rr(raw: &[u8]) -> Vec<SsaEffect> {
    let op = raw[0];
    let r1 = (raw[1] >> 4) & 0x0F;
    let r2 = raw[1] & 0x0F;
    match op {
        0x18 => {
            // LR: r1 = r2
            match (s390x_reg_id(r1), s390x_reg_id(r2)) {
                (Some(a), Some(b)) => {
                    vec![SsaEffect::MovReg(a, b)]
                }
                (Some(a), _) => {
                    vec![SsaEffect::Clobber(a)]
                }
                _ => vec![SsaEffect::Nop],
            }
        }
        0x1A => s390x_binop_rr(r1, r2, BinOp::Add),
        0x1B => s390x_binop_rr(r1, r2, BinOp::Sub),
        0x14 => s390x_binop_rr(r1, r2, BinOp::And),
        0x16 => s390x_binop_rr(r1, r2, BinOp::Or),
        0x17 => s390x_binop_rr(r1, r2, BinOp::Xor),
        0x19 => {
            // CR: compare r1, r2
            match (s390x_reg_id(r1), s390x_reg_id(r2)) {
                (Some(a), Some(b)) => {
                    vec![SsaEffect::CmpReg(a, b)]
                }
                _ => vec![SsaEffect::Clobber(FLAGS_REG)],
            }
        }
        _ => vec![SsaEffect::Nop],
    }
}

fn s390x_binop_rr(
    r1: u8,
    r2: u8,
    op: BinOp,
) -> Vec<SsaEffect> {
    match (s390x_reg_id(r1), s390x_reg_id(r2)) {
        (Some(a), Some(b)) => vec![
            SsaEffect::BinOp(a, op, a, b),
            SsaEffect::Clobber(FLAGS_REG),
        ],
        (Some(a), _) => vec![
            SsaEffect::Clobber(a),
            SsaEffect::Clobber(FLAGS_REG),
        ],
        _ => vec![SsaEffect::Clobber(FLAGS_REG)],
    }
}

fn s390x_4byte(raw: &[u8]) -> Vec<SsaEffect> {
    let op_hi = raw[0];
    match op_hi {
        0xA7 => s390x_ri(raw),
        0xB9 => s390x_rre(raw),
        _ => vec![SsaEffect::Nop],
    }
}

fn s390x_ri(raw: &[u8]) -> Vec<SsaEffect> {
    let r1 = (raw[1] >> 4) & 0x0F;
    let op4 = raw[1] & 0x0F;
    let i16_val = i16::from_be_bytes(
        raw[2..4].try_into().unwrap_or([0; 2]),
    ) as i64;
    match op4 {
        0x08 | 0x09 => {
            // LHI / LGHI
            match s390x_reg_id(r1) {
                Some(r) => {
                    vec![SsaEffect::MovConst(r, i16_val)]
                }
                None => vec![SsaEffect::Nop],
            }
        }
        0x0A | 0x0B => {
            // AHI / AGHI
            match s390x_reg_id(r1) {
                Some(r) => vec![
                    SsaEffect::BinOpImm(
                        r,
                        BinOp::Add,
                        r,
                        i16_val,
                    ),
                    SsaEffect::Clobber(FLAGS_REG),
                ],
                None => {
                    vec![SsaEffect::Clobber(FLAGS_REG)]
                }
            }
        }
        0x0E | 0x0F => {
            // CHI / CGHI
            match s390x_reg_id(r1) {
                Some(r) => {
                    vec![SsaEffect::CmpImm(r, i16_val)]
                }
                None => {
                    vec![SsaEffect::Clobber(FLAGS_REG)]
                }
            }
        }
        _ => vec![SsaEffect::Nop],
    }
}

fn s390x_rre(raw: &[u8]) -> Vec<SsaEffect> {
    let op_lo = raw[1];
    let r1 = (raw[3] >> 4) & 0x0F;
    let r2 = raw[3] & 0x0F;
    match op_lo {
        0x04 => {
            // LGR
            match (s390x_reg_id(r1), s390x_reg_id(r2)) {
                (Some(a), Some(b)) => {
                    vec![SsaEffect::MovReg(a, b)]
                }
                (Some(a), _) => {
                    vec![SsaEffect::Clobber(a)]
                }
                _ => vec![SsaEffect::Nop],
            }
        }
        0x08 => s390x_binop_rr(r1, r2, BinOp::Add),
        0x09 => s390x_binop_rr(r1, r2, BinOp::Sub),
        0x80 => s390x_binop_rr(r1, r2, BinOp::And),
        0x81 => s390x_binop_rr(r1, r2, BinOp::Or),
        0x82 => s390x_binop_rr(r1, r2, BinOp::Xor),
        0x20 => {
            // CGR
            match (s390x_reg_id(r1), s390x_reg_id(r2)) {
                (Some(a), Some(b)) => {
                    vec![SsaEffect::CmpReg(a, b)]
                }
                _ => vec![SsaEffect::Clobber(FLAGS_REG)],
            }
        }
        _ => vec![SsaEffect::Nop],
    }
}

fn s390x_6byte(_raw: &[u8]) -> Vec<SsaEffect> {
    // 6-byte instructions (RIL, etc.) — conservative
    vec![SsaEffect::Nop]
}

// ===== LoongArch64 =====

/// LoongArch caller-saved: $r1(ra), $r4-$r11(a0-a7),
/// $r12-$r15(t0-t3), FLAGS.
pub const LOONGARCH_CALLER_SAVED: &[RegId] = &[
    1, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    FLAGS_REG,
];

/// Map LoongArch register to RegId. $r0 (zero) -> None.
fn loongarch_reg_id(reg: u32) -> Option<RegId> {
    if reg >= 1 && reg <= 15 {
        Some(reg as RegId)
    } else {
        None
    }
}

fn loongarch_effects(raw: &[u8]) -> Vec<SsaEffect> {
    if raw.len() < 4 {
        return vec![SsaEffect::Nop];
    }
    let w = u32::from_le_bytes(
        raw[..4].try_into().unwrap_or([0; 4]),
    );
    // 1RI20: LU12I.W (bits[31:25] = 0x0A)
    let op7 = (w >> 25) & 0x7F;
    if op7 == 0x0A {
        return la_lu12iw(w);
    }
    // 2RI12 instructions
    let op10 = (w >> 22) & 0x3FF;
    match op10 {
        0x0A | 0x0B => return la_addi(w),
        0x0D => return la_andi(w),
        0x0E => return la_ori(w),
        0x0F => return la_xori(w),
        _ => {}
    }
    // Branches (set FLAGS for SCCP)
    let op6 = w >> 26;
    match op6 {
        0x16 | 0x17 | 0x18 | 0x19 | 0x1A | 0x1B => {
            return la_branch_2r(w);
        }
        0x10 | 0x11 => return la_branch_1r(w),
        _ => {}
    }
    // 3R instructions
    let op17 = (w >> 15) & 0x1FFFF;
    match op17 {
        0x20 | 0x21 => la_add(w),
        0x22 | 0x23 => la_binop_3r(w, BinOp::Sub),
        0x29 => la_binop_3r(w, BinOp::And),
        0x2A => la_binop_3r(w, BinOp::Or),
        0x2B => la_binop_3r(w, BinOp::Xor),
        _ => vec![SsaEffect::Nop],
    }
}

fn la_lu12iw(w: u32) -> Vec<SsaEffect> {
    let rd = w & 0x1F;
    let rd_id = match loongarch_reg_id(rd) {
        Some(r) => r,
        None => return vec![SsaEffect::Nop],
    };
    let imm20 = ((w >> 5) & 0xFFFFF) as i32;
    let val =
        ((imm20 << 12) >> 12) as i64 * (1i64 << 12);
    vec![SsaEffect::MovConst(rd_id, val)]
}

fn la_addi(w: u32) -> Vec<SsaEffect> {
    let rd = w & 0x1F;
    let rj = (w >> 5) & 0x1F;
    let imm12 = ((w >> 10) & 0xFFF) as i32;
    let imm = ((imm12 << 20) >> 20) as i64;
    let rd_id = match loongarch_reg_id(rd) {
        Some(r) => r,
        None => return vec![SsaEffect::Nop],
    };
    if rj == 0 {
        vec![SsaEffect::MovConst(rd_id, imm)]
    } else if let Some(rj_id) = loongarch_reg_id(rj) {
        if imm == 0 {
            vec![SsaEffect::MovReg(rd_id, rj_id)]
        } else {
            vec![SsaEffect::BinOpImm(
                rd_id,
                BinOp::Add,
                rj_id,
                imm,
            )]
        }
    } else {
        vec![SsaEffect::Clobber(rd_id)]
    }
}

fn la_andi(w: u32) -> Vec<SsaEffect> {
    let rd = w & 0x1F;
    let rj = (w >> 5) & 0x1F;
    let imm = ((w >> 10) & 0xFFF) as i64; // zero-extended
    let rd_id = match loongarch_reg_id(rd) {
        Some(r) => r,
        None => return vec![SsaEffect::Nop],
    };
    if rj == 0 {
        vec![SsaEffect::MovConst(rd_id, 0)]
    } else if let Some(rj_id) = loongarch_reg_id(rj) {
        vec![SsaEffect::BinOpImm(
            rd_id,
            BinOp::And,
            rj_id,
            imm,
        )]
    } else {
        vec![SsaEffect::Clobber(rd_id)]
    }
}

fn la_ori(w: u32) -> Vec<SsaEffect> {
    let rd = w & 0x1F;
    let rj = (w >> 5) & 0x1F;
    let imm = ((w >> 10) & 0xFFF) as i64; // zero-extended
    let rd_id = match loongarch_reg_id(rd) {
        Some(r) => r,
        None => return vec![SsaEffect::Nop],
    };
    if rj == 0 {
        vec![SsaEffect::MovConst(rd_id, imm)]
    } else if let Some(rj_id) = loongarch_reg_id(rj) {
        vec![SsaEffect::BinOpImm(
            rd_id,
            BinOp::Or,
            rj_id,
            imm,
        )]
    } else {
        vec![SsaEffect::Clobber(rd_id)]
    }
}

fn la_xori(w: u32) -> Vec<SsaEffect> {
    let rd = w & 0x1F;
    let rj = (w >> 5) & 0x1F;
    let imm = ((w >> 10) & 0xFFF) as i64; // zero-extended
    let rd_id = match loongarch_reg_id(rd) {
        Some(r) => r,
        None => return vec![SsaEffect::Nop],
    };
    if rj == 0 {
        vec![SsaEffect::MovConst(rd_id, imm)]
    } else if let Some(rj_id) = loongarch_reg_id(rj) {
        vec![SsaEffect::BinOpImm(
            rd_id,
            BinOp::Xor,
            rj_id,
            imm,
        )]
    } else {
        vec![SsaEffect::Clobber(rd_id)]
    }
}

fn la_add(w: u32) -> Vec<SsaEffect> {
    let rd = w & 0x1F;
    let rj = (w >> 5) & 0x1F;
    let rk = (w >> 10) & 0x1F;
    let rd_id = match loongarch_reg_id(rd) {
        Some(r) => r,
        None => return vec![SsaEffect::Nop],
    };
    if rj == 0 && rk == 0 {
        return vec![SsaEffect::MovConst(rd_id, 0)];
    }
    if rj == 0 {
        return match loongarch_reg_id(rk) {
            Some(s) => vec![SsaEffect::MovReg(rd_id, s)],
            None => vec![SsaEffect::Clobber(rd_id)],
        };
    }
    if rk == 0 {
        return match loongarch_reg_id(rj) {
            Some(s) => vec![SsaEffect::MovReg(rd_id, s)],
            None => vec![SsaEffect::Clobber(rd_id)],
        };
    }
    la_binop_3r(w, BinOp::Add)
}

fn la_binop_3r(w: u32, op: BinOp) -> Vec<SsaEffect> {
    let rd = w & 0x1F;
    let rj = (w >> 5) & 0x1F;
    let rk = (w >> 10) & 0x1F;
    let rd_id = match loongarch_reg_id(rd) {
        Some(r) => r,
        None => return vec![SsaEffect::Nop],
    };
    match (loongarch_reg_id(rj), loongarch_reg_id(rk)) {
        (Some(a), Some(b)) => {
            vec![SsaEffect::BinOp(rd_id, op, a, b)]
        }
        _ => vec![SsaEffect::Clobber(rd_id)],
    }
}

fn la_branch_2r(w: u32) -> Vec<SsaEffect> {
    let rj = (w >> 5) & 0x1F;
    let rd_field = w & 0x1F;
    if rd_field == 0 {
        if let Some(id) = loongarch_reg_id(rj) {
            return vec![SsaEffect::CmpImm(id, 0)];
        }
    }
    if rj == 0 {
        if let Some(id) = loongarch_reg_id(rd_field) {
            return vec![SsaEffect::CmpImm(id, 0)];
        }
    }
    match (
        loongarch_reg_id(rj),
        loongarch_reg_id(rd_field),
    ) {
        (Some(a), Some(b)) => {
            vec![SsaEffect::CmpReg(a, b)]
        }
        _ => vec![SsaEffect::Clobber(FLAGS_REG)],
    }
}

fn la_branch_1r(w: u32) -> Vec<SsaEffect> {
    let rj = (w >> 5) & 0x1F;
    if let Some(id) = loongarch_reg_id(rj) {
        vec![SsaEffect::CmpImm(id, 0)]
    } else {
        vec![SsaEffect::Clobber(FLAGS_REG)]
    }
}
