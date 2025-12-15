pub mod hex;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub fn duration_from_millis(ms: u64) -> Duration {
    Duration::from_millis(ms)
}

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
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
}
