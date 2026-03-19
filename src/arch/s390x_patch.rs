/// Check if a byte is s390x padding (0x00).
pub fn is_padding_s390x(b: u8) -> bool {
    b == 0x00
}
