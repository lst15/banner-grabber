pub mod hex;

use std::sync::OnceLock;
use std::time::Instant;

pub fn sanitize_text(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| match b {
            0x20..=0x7e => *b as char,
            b'\n' => '\n',
            b'\r' => '\r',
            _ => '.',
        })
        .collect()
}

pub fn now_millis() -> u128 {
    static START: OnceLock<Instant> = OnceLock::new();
    let start = START.get_or_init(Instant::now);
    Instant::now().duration_since(*start).as_millis()
}
