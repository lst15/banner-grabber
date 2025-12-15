pub fn to_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_hex() {
        let s = to_hex(&[0xde, 0xad]);
        assert_eq!(s, "de ad");
    }
}
