use crate::model::ScanOutcome;

pub(super) fn raw_banner_for_data(outcome: &ScanOutcome) -> String {
    if !outcome.banner.printable.is_empty() {
        return outcome.banner.printable.clone();
    }
    decode_banner_raw(&outcome.banner.raw_hex).unwrap_or_default()
}

pub(super) fn decode_banner_raw(raw_hex: &str) -> Option<String> {
    let bytes = decode_banner_raw_bytes(raw_hex)?;
    Some(String::from_utf8_lossy(&bytes).to_string())
}

pub(super) fn decode_banner_raw_bytes(raw_hex: &str) -> Option<Vec<u8>> {
    crate::util::hex::from_hex(raw_hex).ok()
}
