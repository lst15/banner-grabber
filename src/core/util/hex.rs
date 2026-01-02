pub fn to_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn from_hex(hex: &str) -> Result<Vec<u8>, String> {
    let cleaned: Vec<char> = hex.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.len() % 2 != 0 {
        return Err("hex string has an odd length".into());
    }
    let mut bytes = Vec::with_capacity(cleaned.len() / 2);
    let mut idx = 0;
    while idx < cleaned.len() {
        let pair: String = cleaned[idx..idx + 2].iter().collect();
        let byte =
            u8::from_str_radix(&pair, 16).map_err(|_| format!("invalid hex pair: {pair}"))?;
        bytes.push(byte);
        idx += 2;
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_hex() {
        let s = to_hex(&[0xde, 0xad]);
        assert_eq!(s, "de ad");
    }

    #[test]
    fn parses_hex() {
        let bytes = from_hex("de ad").unwrap();
        assert_eq!(bytes, vec![0xde, 0xad]);
    }
}
