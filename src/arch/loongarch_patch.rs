/// Check if a byte is LoongArch padding (0x00).
pub fn is_padding_loongarch(b: u8) -> bool {
    b == 0x00
}
