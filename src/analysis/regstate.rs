//! Register state tracking and instruction effect extraction for SCCP.
//!
//! Maps architecture-specific instructions to abstract SSA effects
//! (register moves, constants, binary ops, comparisons, clobbers).
//! Supports x86-64, AArch64, ARM32, RISC-V, MIPS, s390x, and
//! LoongArch. Each architecture has a dedicated effect extractor
//! and caller-saved register set used by the SCCP worklist solver.

use crate::analysis::lattice::{BinOp, CondCode};
use crate::types::Arch;

/// Abstract register ID (arch-independent): the architecture's own
/// register number for the GPRs 0..15 that are tracked (x86 RAX=0 ..
/// R15=15, AArch64 X0..X15, ARM32 R0..R15, s390x R0..R15; RISC-V, MIPS
/// and LoongArch 1..15, register 0 being hard-wired zero). Higher
/// registers are never tracked. FLAGS = 16.
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

/// Extract x86 effects, clobbering FLAGS for any instruction that
/// writes flags without a modeled compare (e.g. `dec`, `bt`, an ALU
/// op on memory), so a branch never reads a stale compare result.
fn extract_x86_effects(
    instr: &iced_x86::Instruction,
) -> Vec<SsaEffect> {
    let mut effects = extract_x86_reg_effects(instr);
    if instr.rflags_modified() != 0 && !defines_flags(&effects) {
        effects.push(SsaEffect::Clobber(FLAGS_REG));
    }
    effects
}

/// True if the effects already set or clobber FLAGS.
fn defines_flags(effects: &[SsaEffect]) -> bool {
    effects.iter().any(|e| {
        matches!(
            e,
            SsaEffect::CmpReg(..)
                | SsaEffect::CmpImm(..)
                | SsaEffect::TestReg(..)
                | SsaEffect::TestImm(..)
                | SsaEffect::Clobber(FLAGS_REG)
        )
    })
}

/// Dispatch x86 instruction to the appropriate effect extractor.
/// Anything not modeled (including `imul`, `push` and `pop`, which
/// write implicit registers) clobbers every register it writes.
fn extract_x86_reg_effects(
    instr: &iced_x86::Instruction,
) -> Vec<SsaEffect> {
    use iced_x86::Mnemonic::*;
    match instr.mnemonic() {
        Mov => extract_mov(instr),
        Lea => extract_lea(instr),
        Xor if is_self_xor(instr) => extract_self_xor(instr),
        Add | Sub | And | Or | Xor => extract_alu(instr),
        Shl | Shr | Sar => extract_shift(instr),
        Cmp => extract_cmp(instr),
        Test => extract_test(instr),
        Call | Ret | Nop => vec![SsaEffect::Nop],
        _ => extract_clobbers(instr),
    }
}

/// Map a full-width x86 destination to its register ID: a 64-bit
/// GPR, or a 32-bit GPR (flagged `true`) whose write zero-extends.
/// 8/16-bit writes merge into the old value and are not modeled.
fn x86_full_dst(
    reg: iced_x86::Register,
) -> Option<(RegId, bool)> {
    let id = x86_reg_id(reg)?;
    if reg.is_gpr64() {
        Some((id, false))
    } else if reg.is_gpr32() {
        Some((id, true))
    } else {
        None
    }
}

/// Append the implicit zero-extension of a 32-bit register write.
fn push_zext32(effects: &mut Vec<SsaEffect>, dst: RegId, is32: bool) {
    if is32 {
        effects.push(SsaEffect::BinOpImm(
            dst, BinOp::And, dst, 0xFFFF_FFFF,
        ));
    }
}

/// Map a compare/test operand to its register ID. AH/BH/CH/DH are
/// bits 8..15 of their parent, so comparing them as the parent's
/// low bits would be wrong; they are not modeled.
fn x86_cmp_reg(reg: iced_x86::Register) -> Option<RegId> {
    use iced_x86::Register as R;
    match reg {
        R::AH | R::BH | R::CH | R::DH => None,
        _ => x86_reg_id(reg),
    }
}

/// Extract SSA effects from a MOV instruction. Only 32/64-bit
/// register destinations are modeled; narrower ones are clobbered.
fn extract_mov(
    instr: &iced_x86::Instruction,
) -> Vec<SsaEffect> {
    use iced_x86::OpKind;
    if instr.op_count() < 2
        || instr.op_kind(0) != OpKind::Register
    {
        return vec![SsaEffect::Nop];
    }
    let (dst_reg, is32) =
        match x86_full_dst(instr.op_register(0)) {
            Some(d) => d,
            None => return extract_clobbers(instr),
        };
    let mut effects = vec![mov_src_effect(instr, dst_reg)];
    push_zext32(&mut effects, dst_reg, is32);
    effects
}

/// Effect of a MOV source operand on its register destination.
fn mov_src_effect(
    instr: &iced_x86::Instruction,
    dst_reg: RegId,
) -> SsaEffect {
    use iced_x86::OpKind;
    match instr.op_kind(1) {
        OpKind::Register => {
            match x86_reg_id(instr.op_register(1)) {
                Some(s) => SsaEffect::MovReg(dst_reg, s),
                None => SsaEffect::Clobber(dst_reg),
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
            SsaEffect::MovConst(dst_reg, imm)
        }
        _ => SsaEffect::Clobber(dst_reg),
    }
}

/// Extract SSA effects from a LEA instruction (clobber destination).
fn extract_lea(
    instr: &iced_x86::Instruction,
) -> Vec<SsaEffect> {
    let dst = match x86_reg_id(instr.op_register(0)) {
        Some(r) => r,
        None => return vec![SsaEffect::Nop],
    };
    vec![SsaEffect::Clobber(dst)]
}

/// Extract SSA effects from ALU instructions (ADD, SUB, AND, OR, XOR).
/// Only 32/64-bit register destinations are modeled; a memory
/// destination leaves registers alone, a narrower one is clobbered.
fn extract_alu(
    instr: &iced_x86::Instruction,
) -> Vec<SsaEffect> {
    use iced_x86::{Mnemonic::*, OpKind};
    if instr.op_count() < 2
        || instr.op_kind(0) != OpKind::Register
    {
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
    let (dst, is32) = match x86_full_dst(instr.op_register(0)) {
        Some(d) => d,
        None => return extract_clobbers(instr),
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
    push_zext32(&mut effects, dst, is32);
    effects.push(SsaEffect::Clobber(FLAGS_REG));
    effects
}

/// Extract SSA effects from shift instructions (SHL, SHR, SAR).
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

/// Extract SSA effects from CMP (sets FLAGS from subtraction).
fn extract_cmp(
    instr: &iced_x86::Instruction,
) -> Vec<SsaEffect> {
    use iced_x86::OpKind;
    if instr.op_count() < 2 {
        return vec![SsaEffect::Nop];
    }
    let a = match instr.op_kind(0) {
        OpKind::Register => x86_cmp_reg(instr.op_register(0)),
        _ => None,
    };
    match instr.op_kind(1) {
        OpKind::Register => {
            let b = x86_cmp_reg(instr.op_register(1));
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

/// Extract SSA effects from TEST (sets FLAGS from bitwise AND).
fn extract_test(
    instr: &iced_x86::Instruction,
) -> Vec<SsaEffect> {
    use iced_x86::OpKind;
    if instr.op_count() < 2 {
        return vec![SsaEffect::Nop];
    }
    let a = match instr.op_kind(0) {
        OpKind::Register => x86_cmp_reg(instr.op_register(0)),
        _ => None,
    };
    match instr.op_kind(1) {
        OpKind::Register => {
            let b = x86_cmp_reg(instr.op_register(1));
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

/// Check if an XOR instruction is a self-XOR (register zeroing idiom).
fn is_self_xor(instr: &iced_x86::Instruction) -> bool {
    instr.op_count() >= 2
        && instr.op_kind(0) == iced_x86::OpKind::Register
        && instr.op_kind(1) == iced_x86::OpKind::Register
        && instr.op_register(0) == instr.op_register(1)
}

/// Self-XOR of a 32/64-bit register produces MovConst(reg, 0) and
/// clobbers FLAGS; a narrower one only zeroes part of the register.
fn extract_self_xor(
    instr: &iced_x86::Instruction,
) -> Vec<SsaEffect> {
    match x86_full_dst(instr.op_register(0)) {
        Some((r, _)) => vec![
            SsaEffect::MovConst(r, 0),
            SsaEffect::Clobber(FLAGS_REG),
        ],
        None => extract_clobbers(instr),
    }
}

/// Clobber all registers written by an unrecognized instruction.
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

/// Decode the 0x0F-prefixed Jcc condition byte to a CondCode.
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

// ===== Conditional branch conditions =====

/// The value a decoded conditional branch tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestSrc {
    /// The FLAGS value left by the last compare/test effect.
    Flags,
    /// Register `RegId` masked with the `i64` bits (AArch64 CBZ/CBNZ
    /// on the W or X width, TBZ/TBNZ on one bit). Exact: tracked
    /// AArch64 values are the full 64-bit register contents.
    RegBits(RegId, i64),
}

/// A decoded conditional branch: `cc` EQ is taken when the tested
/// value is zero, NE when it is nonzero. x86 also reports ordered
/// conditions, which are never folded.
#[derive(Debug, Clone, Copy)]
pub struct BranchTest {
    pub cc: CondCode,
    pub src: TestSrc,
}

/// What a conditional branch tests, or None when it is not decoded.
/// AArch64 branches may test FLAGS or a register (`a64_branch_test`);
/// elsewhere they test FLAGS. Outside x86 only equality branches are
/// decoded, and only those whose FLAGS value comes from the matching
/// compare effect.
pub fn branch_test(
    raw: &[u8],
    arch: Arch,
    big_endian: bool,
) -> Option<BranchTest> {
    let cc = match arch {
        Arch::Aarch64 => return a64_branch_test(word_le(raw)?),
        Arch::X86_64 | Arch::X86_32 => x86_branch_cond(raw)?.cc,
        Arch::Arm32 => arm32_branch_cond(word_le(raw)?)?,
        Arch::RiscV64 | Arch::RiscV32 => rv_branch_cond(raw)?,
        Arch::Mips32 | Arch::Mips64 => mips_branch_cond(raw, big_endian)?,
        Arch::S390x => s390x_branch_cond(raw)?,
        Arch::LoongArch64 => la_branch_cond(word_le(raw)?)?,
    };
    Some(BranchTest { cc, src: TestSrc::Flags })
}

/// Read a little-endian 32-bit instruction word.
fn word_le(raw: &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(raw.get(..4)?.try_into().ok()?))
}

/// Map an "equal"/"not equal" selector to a CondCode.
fn eq_ne(is_eq: bool) -> CondCode {
    if is_eq { CondCode::Eq } else { CondCode::Ne }
}

/// AArch64 B.EQ / B.NE (not BC.cond).
fn a64_branch_cond(w: u32) -> Option<CondCode> {
    if w & 0xFF00_0010 != 0x5400_0000 {
        return None;
    }
    match w & 0xF {
        0 | 1 => Some(eq_ne(w & 0xF == 0)),
        _ => None,
    }
}

/// AArch64 B.EQ/B.NE on FLAGS, CBZ/CBNZ on a W or X register, and
/// TBZ/TBNZ on one register bit. Bit 24 selects the NZ form.
fn a64_branch_test(w: u32) -> Option<BranchTest> {
    if let Some(cc) = a64_branch_cond(w) {
        return Some(BranchTest { cc, src: TestSrc::Flags });
    }
    let mask = match w & 0x7E00_0000 {
        // CBZ/CBNZ: sf 011010 op imm19 Rt
        0x3400_0000 if w >> 31 == 1 => -1,
        0x3400_0000 => 0xFFFF_FFFF,
        // TBZ/TBNZ: b5 011011 op b40 imm14 Rt
        0x3600_0000 => 1i64 << (((w >> 31) << 5) | ((w >> 19) & 0x1F)),
        _ => return None,
    };
    let reg = aarch64_reg_id(w & 0x1F)?;
    let cc = eq_ne((w >> 24) & 1 == 0);
    Some(BranchTest { cc, src: TestSrc::RegBits(reg, mask) })
}

/// ARM32 BEQ / BNE (A32 B encoding, not BL).
fn arm32_branch_cond(w: u32) -> Option<CondCode> {
    if (w >> 24) & 0xF != 0xA {
        return None;
    }
    match w >> 28 {
        0 | 1 => Some(eq_ne(w >> 28 == 0)),
        _ => None,
    }
}

/// RISC-V BEQ / BNE; `rv_branch` sets FLAGS from the same operands.
/// Compressed C.BEQZ/C.BNEZ set no FLAGS effect and are not decoded.
fn rv_branch_cond(raw: &[u8]) -> Option<CondCode> {
    if raw.first()? & 0x03 != 0x03 {
        return None;
    }
    let w = word_le(raw)?;
    if w & 0x7F != 0x63 {
        return None;
    }
    match (w >> 12) & 0x7 {
        0 | 1 => Some(eq_ne((w >> 12) & 0x7 == 0)),
        _ => None,
    }
}

/// MIPS BEQ / BNE; `mips_branch` sets FLAGS from the same operands.
fn mips_branch_cond(
    raw: &[u8],
    big_endian: bool,
) -> Option<CondCode> {
    let bytes: [u8; 4] = raw.get(..4)?.try_into().ok()?;
    let w = if big_endian {
        u32::from_be_bytes(bytes)
    } else {
        u32::from_le_bytes(bytes)
    };
    match w >> 26 {
        0x04 | 0x05 => Some(eq_ne(w >> 26 == 0x04)),
        _ => None,
    }
}

/// LoongArch BEQ/BNE/BEQZ/BNEZ; `la_branch_*` set FLAGS from them.
fn la_branch_cond(w: u32) -> Option<CondCode> {
    match w >> 26 {
        0x16 | 0x10 => Some(CondCode::Eq),
        0x17 | 0x11 => Some(CondCode::Ne),
        _ => None,
    }
}

/// s390x BRC/BRCL with mask 8 (equal) or 7 (not equal).
fn s390x_branch_cond(raw: &[u8]) -> Option<CondCode> {
    let is_brc = raw.len() == 4 && raw[0] == 0xA7;
    let is_brcl = raw.len() == 6 && raw[0] == 0xC0;
    if !(is_brc || is_brcl) || raw[1] & 0x0F != 0x04 {
        return None;
    }
    match raw[1] >> 4 {
        8 | 7 => Some(eq_ne(raw[1] >> 4 == 8)),
        _ => None,
    }
}

// ===== AArch64 =====

/// AArch64 caller-saved: X0-X15 and FLAGS. A call also clobbers
/// X16-X18 and X30, which are never tracked (see `aarch64_reg_id`).
pub const AARCH64_CALLER_SAVED: &[RegId] = &[
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    FLAGS_REG,
];

/// Every AArch64 register the constant model tracks: X0-X15 (those
/// `aarch64_reg_id` maps) and FLAGS. An unknown instruction clobbers
/// all of them, whatever the calling convention says.
const AARCH64_TRACKED: &[RegId] = &[
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    FLAGS_REG,
];

/// Map AArch64 register number to abstract register ID. Only X0-X15
/// are tracked; X16-X30 and 31 (SP or XZR) never hold a constant.
fn aarch64_reg_id(reg: u32) -> Option<RegId> {
    if reg <= 15 {
        Some(reg as RegId)
    } else {
        None
    }
}

/// Extract SSA effects from a raw AArch64 instruction word. Each word
/// is classified by its top-level encoding group (bits 28:25). An
/// instruction not modeled exactly clobbers every register and FLAGS
/// it may write; an unclassified one clobbers all of them.
fn aarch64_effects(raw: &[u8]) -> Vec<SsaEffect> {
    let w = match word_le(raw) {
        Some(w) => w,
        None => return a64_clobber_all(),
    };
    match (w >> 25) & 0xF {
        0b1000 | 0b1001 => a64_dp_imm(w),
        0b1010 | 0b1011 => a64_branch_sys(w),
        0b0100 | 0b0110 | 0b1100 | 0b1110 => a64_ldst(w),
        0b0101 | 0b1101 => a64_dp_reg(w),
        0b0111 | 0b1111 => a64_fp_simd(w),
        // Reserved, SME, SVE and unallocated encodings.
        _ => a64_clobber_all(),
    }
}

/// Clobber every tracked AArch64 register and FLAGS.
fn a64_clobber_all() -> Vec<SsaEffect> {
    AARCH64_TRACKED
        .iter()
        .map(|&r| SsaEffect::Clobber(r))
        .collect()
}

/// Clobber the register in a 5-bit field if it is tracked.
fn a64_clobber_reg(effects: &mut Vec<SsaEffect>, field: u32) {
    if let Some(r) = aarch64_reg_id(field) {
        effects.push(SsaEffect::Clobber(r));
    }
}

/// Effect of an unmodeled instruction whose only possible writes are
/// the Rd field (bits 4:0) and, when `flags` is set, FLAGS.
fn a64_clobber_rd(w: u32, flags: bool) -> Vec<SsaEffect> {
    let mut effects = Vec::new();
    a64_clobber_reg(&mut effects, w & 0x1F);
    if flags {
        effects.push(SsaEffect::Clobber(FLAGS_REG));
    }
    a64_or_nop(effects)
}

/// Return the effects, or a single Nop when there are none.
fn a64_or_nop(effects: Vec<SsaEffect>) -> Vec<SsaEffect> {
    if effects.is_empty() {
        vec![SsaEffect::Nop]
    } else {
        effects
    }
}

// ----- AArch64 data processing (immediate) -----

/// Data processing (immediate), by bits 25:23. Each instruction here
/// writes at most Rd; only ADDS/SUBS and ANDS write FLAGS.
fn a64_dp_imm(w: u32) -> Vec<SsaEffect> {
    match (w >> 23) & 0x7 {
        0b010 => a64_addsub_imm(w),
        0b100 => a64_logical_imm(w),
        0b101 => a64_movwide(w),
        // ADR/ADRP (PC-relative: not a constant in a PIE), add/sub
        // with tags, min/max immediate, bitfield (LSL/LSR/ASR/UBFX/
        // SXTW...) and extract.
        _ => a64_clobber_rd(w, false),
    }
}

/// AArch64 ADD/SUB (immediate), including CMP/CMN and MOV to/from SP.
/// Rn = 31 is SP, Rd = 31 is SP or (when setting flags) XZR; neither
/// is tracked. FLAGS gets Rn - imm (SUBS) or Rn + imm (ADDS).
fn a64_addsub_imm(w: u32) -> Vec<SsaEffect> {
    let is_sub = (w >> 30) & 1 == 1;
    let imm12 = ((w >> 10) & 0xFFF) as i64;
    let imm = if (w >> 22) & 1 == 1 { imm12 << 12 } else { imm12 };
    let rn = aarch64_reg_id((w >> 5) & 0x1F);
    let mut effects = Vec::new();
    if (w >> 29) & 1 == 1 {
        effects.push(match rn {
            Some(n) if is_sub => SsaEffect::CmpImm(n, imm),
            Some(n) => SsaEffect::CmpImm(n, -imm),
            None => SsaEffect::Clobber(FLAGS_REG),
        });
    }
    if let Some(d) = aarch64_reg_id(w & 0x1F) {
        let op = if is_sub { BinOp::Sub } else { BinOp::Add };
        effects.push(match rn {
            Some(n) => SsaEffect::BinOpImm(d, op, n, imm),
            None => SsaEffect::Clobber(d),
        });
        push_zext32(&mut effects, d, w >> 31 == 0);
    }
    a64_or_nop(effects)
}

/// AArch64 AND/ORR/EOR/ANDS (immediate), including MOV (bitmask
/// immediate) and TST. Rn = 31 is XZR; Rd = 31 is SP, or XZR for ANDS.
fn a64_logical_imm(w: u32) -> Vec<SsaEffect> {
    let opc = (w >> 29) & 0x3;
    let imm = a64_bitmask_imm(w);
    let rn_zr = (w >> 5) & 0x1F == 31;
    let rn = aarch64_reg_id((w >> 5) & 0x1F);
    let mut effects = Vec::new();
    if opc == 0b11 {
        effects.push(match (rn, imm) {
            (Some(n), Some(i)) => SsaEffect::TestImm(n, i),
            _ => SsaEffect::Clobber(FLAGS_REG),
        });
    }
    if let Some(d) = aarch64_reg_id(w & 0x1F) {
        let op = a64_logic_op(opc);
        effects.push(match (rn, imm) {
            (_, Some(i)) if rn_zr && op != BinOp::And => {
                SsaEffect::MovConst(d, i)
            }
            (_, Some(_)) if rn_zr => SsaEffect::MovConst(d, 0),
            (Some(n), Some(i)) => SsaEffect::BinOpImm(d, op, n, i),
            _ => SsaEffect::Clobber(d),
        });
        push_zext32(&mut effects, d, w >> 31 == 0);
    }
    a64_or_nop(effects)
}

/// Logical opcode (bits 30:29) to its operation; ANDS is AND.
fn a64_logic_op(opc: u32) -> BinOp {
    match opc {
        0b01 => BinOp::Or,
        0b10 => BinOp::Xor,
        _ => BinOp::And,
    }
}

/// Decode the N:immr:imms bitmask immediate of a logical (immediate)
/// instruction (the ARM `DecodeBitMasks`), or None if reserved.
fn a64_bitmask_imm(w: u32) -> Option<i64> {
    let is64 = w >> 31 == 1;
    let n = (w >> 22) & 1;
    let immr = (w >> 16) & 0x3F;
    let imms = (w >> 10) & 0x3F;
    if !is64 && n == 1 {
        return None;
    }
    let combined = (n << 6) | (!imms & 0x3F);
    let len = 31u32.checked_sub(combined.leading_zeros())?;
    if len == 0 {
        return None;
    }
    let esize = 1u32 << len;
    let levels = esize - 1;
    let (s, r) = (imms & levels, immr & levels);
    if s == levels {
        return None;
    }
    let elem = a64_rotate_elem((1u64 << (s + 1)) - 1, r, esize);
    let size = if is64 { 64 } else { 32 };
    let mut value = 0u64;
    let mut pos = 0;
    while pos < size {
        value |= elem << pos;
        pos += esize;
    }
    Some(value as i64)
}

/// Rotate the low `esize` bits of `elem` right by `r` (r < esize).
fn a64_rotate_elem(elem: u64, r: u32, esize: u32) -> u64 {
    if r == 0 {
        return elem;
    }
    let mask = if esize == 64 { u64::MAX } else { (1u64 << esize) - 1 };
    ((elem >> r) | (elem << (esize - r))) & mask
}

/// AArch64 MOVN/MOVZ/MOVK. MOVK replaces one 16-bit field of Rd and
/// keeps the others.
fn a64_movwide(w: u32) -> Vec<SsaEffect> {
    let d = match aarch64_reg_id(w & 0x1F) {
        Some(d) => d,
        None => return vec![SsaEffect::Nop],
    };
    let shift = ((w >> 21) & 0x3) * 16;
    let imm = (((w >> 5) & 0xFFFF) as i64) << shift;
    let mut effects = match (w >> 29) & 0x3 {
        0b00 => vec![SsaEffect::MovConst(d, !imm)],
        0b10 => vec![SsaEffect::MovConst(d, imm)],
        0b11 => vec![
            SsaEffect::BinOpImm(d, BinOp::And, d, !(0xFFFF_i64 << shift)),
            SsaEffect::BinOpImm(d, BinOp::Or, d, imm),
        ],
        _ => vec![SsaEffect::Clobber(d)],
    };
    push_zext32(&mut effects, d, w >> 31 == 0);
    effects
}

// ----- AArch64 branches, exception generation and system -----

/// Branches, exception generation and system instructions. MSR and
/// PSTATE writes may change NZCV; MRS writes Rt, and MRS of RNDR or
/// RNDRRS also writes NZCV (Z set when no random number was returned),
/// so every MRS clobbers FLAGS. SVC, SYS/SYSL,
/// register branches (BLRAA, ...) and anything unknown clobber all
/// tracked registers and FLAGS. BL/BLR get the call clobber before
/// effects are extracted.
fn a64_branch_sys(w: u32) -> Vec<SsaEffect> {
    if a64_writes_nothing(w) {
        return vec![SsaEffect::Nop];
    }
    // MSR (immediate) to PSTATE (CFINV, AXFLAG, ...) or MSR (register).
    if w & 0xFFF8_F01F == 0xD500_401F || w & 0xFFF0_0000 == 0xD510_0000
    {
        return vec![SsaEffect::Clobber(FLAGS_REG)];
    }
    // MRS Xt, <sysreg> (RNDR, RNDRRS: also NZCV)
    if w & 0xFFF0_0000 == 0xD530_0000 {
        return a64_clobber_rd(w, true);
    }
    a64_clobber_all()
}

/// B, CBZ/CBNZ, TBZ/TBNZ, B.cond/BC.cond, hints (NOP, BTI, PAC on
/// X16/X17/X30) and barriers write no tracked register or FLAGS.
fn a64_writes_nothing(w: u32) -> bool {
    w & 0xFC00_0000 == 0x1400_0000
        || w & 0x7E00_0000 == 0x3400_0000
        || w & 0x7E00_0000 == 0x3600_0000
        || w & 0xFF00_0000 == 0x5400_0000
        || w & 0xFFFF_F01F == 0xD503_201F
        || w & 0xFFFF_F01F == 0xD503_301F
}

// ----- AArch64 loads and stores -----

/// Loads and stores, by bits 29:27. Register and pair forms and
/// literal loads are modeled; exclusives, LDAR/STLR, CAS, LDAPR/STLUR,
/// memory tags, MOPS (which also sets NZCV) and SIMD structure loads
/// clobber all tracked registers and FLAGS.
fn a64_ldst(w: u32) -> Vec<SsaEffect> {
    match (w >> 27) & 0x7 {
        0b111 => a64_ldst_reg(w),
        0b101 => a64_ldst_pair(w),
        0b011 if (w >> 24) & 1 == 0 => a64_ldr_literal(w),
        _ => a64_clobber_all(),
    }
}

/// Load/store register: unsigned offset, unscaled, pre/post-index,
/// unprivileged and register offset. A GPR load writes Rt; pre- and
/// post-index write back Rn. The atomic (LDADD, SWP, LD64B, ...) and
/// LDRAA/LDRAB forms in the same space clobber everything.
fn a64_ldst_reg(w: u32) -> Vec<SsaEffect> {
    let mut effects = Vec::new();
    if (w >> 24) & 1 == 0 {
        match ((w >> 21) & 1, (w >> 10) & 0x3) {
            (0, 0b01) | (0, 0b11) => {
                a64_clobber_reg(&mut effects, (w >> 5) & 0x1F);
            }
            (0, _) | (1, 0b10) => {}
            _ => return a64_clobber_all(),
        }
    }
    let size = w >> 30;
    let opc = (w >> 22) & 0x3;
    let is_prfm = opc == 0b10 && size == 0b11;
    let is_gpr_load = (w >> 26) & 1 == 0 && opc != 0b00 && !is_prfm;
    if is_gpr_load {
        a64_clobber_reg(&mut effects, w & 0x1F);
    }
    a64_or_nop(effects)
}

/// Load/store pair (LDP/STP/LDNP/STNP/LDPSW/STGP and SIMD&FP pairs).
/// A GPR pair load writes Rt and Rt2; pre- and post-index (bit 23)
/// write back Rn. GPR opc 11 is not a base pair form.
fn a64_ldst_pair(w: u32) -> Vec<SsaEffect> {
    let is_simd = (w >> 26) & 1 == 1;
    if !is_simd && w >> 30 == 0b11 {
        return a64_clobber_all();
    }
    let mut effects = Vec::new();
    if (w >> 23) & 1 == 1 {
        a64_clobber_reg(&mut effects, (w >> 5) & 0x1F);
    }
    if !is_simd && (w >> 22) & 1 == 1 {
        a64_clobber_reg(&mut effects, w & 0x1F);
        a64_clobber_reg(&mut effects, (w >> 10) & 0x1F);
    }
    a64_or_nop(effects)
}

/// Load register (literal): a GPR load writes Rt; PRFM (opc 11) and
/// SIMD&FP loads write no tracked register.
fn a64_ldr_literal(w: u32) -> Vec<SsaEffect> {
    if (w >> 26) & 1 == 1 || w >> 30 == 0b11 {
        return vec![SsaEffect::Nop];
    }
    a64_clobber_rd(w, false)
}

// ----- AArch64 data processing (register) -----

/// Data processing (register): each instruction writes at most Rd and
/// FLAGS. Unshifted logical and add/sub are modeled; conditional
/// compares only write FLAGS; for the other known classes (add/sub
/// extended or with carry, RMIF/SETF, CSEL/CSINC, 1-, 2- and 3-source)
/// bit 29 (S) says whether FLAGS is written.
fn a64_dp_reg(w: u32) -> Vec<SsaEffect> {
    let sets_flags = (w >> 29) & 1 == 1;
    if (w >> 28) & 1 == 0 {
        return match ((w >> 24) & 1, (w >> 21) & 1) {
            (0, _) => a64_logical_reg(w),
            (1, 0) => a64_addsub_reg(w),
            _ => a64_clobber_rd(w, sets_flags),
        };
    }
    match (w >> 21) & 0xF {
        0b0010 => vec![SsaEffect::Clobber(FLAGS_REG)],
        0b0000 | 0b0100 | 0b0110 => a64_clobber_rd(w, sets_flags),
        op if op & 0b1000 != 0 => a64_clobber_rd(w, sets_flags),
        _ => a64_clobber_all(),
    }
}

/// AArch64 ADD/SUB (shifted register), including CMP/CMN/NEG. Only
/// the unshifted form is modeled; Rn/Rm = 31 is XZR (not tracked).
/// FLAGS gets Rn - Rm for SUBS; ADDS clobbers it.
fn a64_addsub_reg(w: u32) -> Vec<SsaEffect> {
    let is_sub = (w >> 30) & 1 == 1;
    let unshifted = (w >> 10) & 0x3F == 0;
    let ops = match (
        aarch64_reg_id((w >> 5) & 0x1F),
        aarch64_reg_id((w >> 16) & 0x1F),
    ) {
        (Some(n), Some(m)) if unshifted => Some((n, m)),
        _ => None,
    };
    let mut effects = Vec::new();
    if (w >> 29) & 1 == 1 {
        effects.push(match ops {
            Some((n, m)) if is_sub => SsaEffect::CmpReg(n, m),
            _ => SsaEffect::Clobber(FLAGS_REG),
        });
    }
    if let Some(d) = aarch64_reg_id(w & 0x1F) {
        let op = if is_sub { BinOp::Sub } else { BinOp::Add };
        effects.push(match ops {
            Some((n, m)) => SsaEffect::BinOp(d, op, n, m),
            None => SsaEffect::Clobber(d),
        });
        push_zext32(&mut effects, d, w >> 31 == 0);
    }
    a64_or_nop(effects)
}

/// AArch64 logical (shifted register): AND/BIC/ORR/ORN/EOR/EON/ANDS/
/// BICS, including MOV (ORR from XZR) and TST. Only the unshifted,
/// non-inverted form is modeled; Rn/Rm = 31 is XZR.
fn a64_logical_reg(w: u32) -> Vec<SsaEffect> {
    let opc = (w >> 29) & 0x3;
    let plain = (w >> 10) & 0x3F == 0 && (w >> 21) & 1 == 0;
    let rn_zr = (w >> 5) & 0x1F == 31;
    let n = aarch64_reg_id((w >> 5) & 0x1F);
    let m = aarch64_reg_id((w >> 16) & 0x1F);
    let mut effects = Vec::new();
    if opc == 0b11 {
        effects.push(match (n, m) {
            (Some(a), Some(b)) if plain => SsaEffect::TestReg(a, b),
            _ => SsaEffect::Clobber(FLAGS_REG),
        });
    }
    if let Some(d) = aarch64_reg_id(w & 0x1F) {
        effects.push(match (n, m) {
            (_, Some(b)) if plain && rn_zr && opc == 0b01 => {
                SsaEffect::MovReg(d, b)
            }
            (Some(a), Some(b)) if plain => {
                SsaEffect::BinOp(d, a64_logic_op(opc), a, b)
            }
            _ => SsaEffect::Clobber(d),
        });
        push_zext32(&mut effects, d, w >> 31 == 0);
    }
    a64_or_nop(effects)
}

// ----- AArch64 scalar floating-point and Advanced SIMD -----

/// Scalar FP and Advanced SIMD. Only conversions to a GPR (FCVT*,
/// FJCVTZS), FMOV to a GPR and SMOV/UMOV write a GPR, and only FCMP,
/// FCMPE, FCCMP, FCCMPE and FJCVTZS write NZCV. Bits 28:24 = 11110
/// select the scalar FP classes (bit 30 clear) and the Advanced SIMD
/// scalar classes (bit 30 set) alike. Within them, every conversion
/// form (bit 21 clear: fixed-point; bits 15:10 zero: integer, FMOV)
/// clobbers Rd and FLAGS, and every other form FLAGS; SMOV/UMOV and
/// the other Advanced SIMD copies clobber Rd. Rd of most of these
/// matches is a SIMD register and most write no NZCV, so the extra
/// clobbers only lose precision.
fn a64_fp_simd(w: u32) -> Vec<SsaEffect> {
    // Scalar FP or Advanced SIMD scalar (bits 28:24 = 11110).
    let scalar_fp = (w >> 24) & 0x1F == 0b11110;
    let to_gpr = scalar_fp
        && ((w >> 21) & 1 == 0 || (w >> 10) & 0x3F == 0);
    let simd_copy = w & 0x9FE0_8400 == 0x0E00_0400;
    if to_gpr || simd_copy {
        return a64_clobber_rd(w, scalar_fp);
    }
    if scalar_fp {
        return vec![SsaEffect::Clobber(FLAGS_REG)];
    }
    vec![SsaEffect::Nop]
}

// ===== ARM32 =====

/// ARM32 caller-saved: R0-R3, R12(IP), R14(LR), FLAGS.
pub const ARM32_CALLER_SAVED: &[RegId] =
    &[0, 1, 2, 3, 12, 14, FLAGS_REG];

/// Map ARM32 register number to abstract register ID (R0..R15 tracked).
fn arm32_reg_id(reg: u32) -> Option<RegId> {
    if reg <= 15 {
        Some(reg as RegId)
    } else {
        None
    }
}

/// Extract SSA effects from a raw ARM32 instruction word.
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

/// Decode ARM32 data-processing instruction effects.
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

/// ARM32 MOV/MOVS effect.
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

/// ARM32 MVN (bitwise NOT) effect.
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

/// ARM32 ADD/SUB effect.
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

/// ARM32 AND/ORR/EOR/BIC logic effect.
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

/// ARM32 CMP/CMN effect (sets FLAGS).
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

/// ARM32 TST/TEQ effect (sets FLAGS via AND/EOR).
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
/// Map RISC-V register number to abstract register ID (x0..x15 tracked).
fn riscv_reg_id(reg: u32) -> Option<RegId> {
    if reg >= 1 && reg <= 15 {
        Some(reg as RegId)
    } else {
        None
    }
}

/// Extract SSA effects from a raw RISC-V instruction (32-bit or 16-bit compressed).
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
/// Map MIPS register number to abstract register ID ($0..$15 tracked).
fn mips_reg_id(reg: u32) -> Option<RegId> {
    if reg >= 1 && reg <= 15 {
        Some(reg as RegId)
    } else {
        None
    }
}

/// Extract SSA effects from a raw MIPS instruction word.
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

/// Map s390x general register number to abstract register ID (R0..R15 tracked).
fn s390x_reg_id(reg: u8) -> Option<RegId> {
    if reg <= 15 {
        Some(reg as RegId)
    } else {
        None
    }
}

/// Extract SSA effects from a raw s390x instruction (2/4/6 bytes, big-endian).
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
/// Map LoongArch register number to abstract register ID ($r0..$r15 tracked).
fn loongarch_reg_id(reg: u32) -> Option<RegId> {
    if reg >= 1 && reg <= 15 {
        Some(reg as RegId)
    } else {
        None
    }
}

/// Extract SSA effects from a raw LoongArch64 instruction word.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Registers an effect list clobbers.
    fn clobbered(effects: &[SsaEffect]) -> Vec<RegId> {
        effects
            .iter()
            .filter_map(|e| match e {
                SsaEffect::Clobber(r) => Some(*r),
                _ => None,
            })
            .collect()
    }

    /// MRS of RNDR (d53b2409: mrs x9, s3_3_c2_c4_0) writes x9 and NZCV.
    #[test]
    fn mrs_rndr_clobbers_rt_and_flags() {
        let got = clobbered(&aarch64_effects(&0xd53b_2409u32.to_le_bytes()));
        assert_eq!(got, vec![9, FLAGS_REG]);
    }

    /// The clobber-everything effect covers exactly the registers the
    /// model tracks: every register `aarch64_reg_id` maps, and FLAGS.
    #[test]
    fn a64_clobber_all_covers_every_tracked_register() {
        let mut want: Vec<RegId> =
            (0..32).filter_map(aarch64_reg_id).collect();
        want.push(FLAGS_REG);
        assert_eq!(clobbered(&a64_clobber_all()), want);
    }
}
