/// Check if a byte is RISC-V padding (0x00 = c.unimp).
pub fn is_padding_riscv(b: u8) -> bool {
    b == 0x00
}
