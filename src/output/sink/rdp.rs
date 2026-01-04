use crate::model::ScanOutcome;
use serde_json::{Map, Value};

use super::common::decode_banner_raw_bytes;

pub(super) fn rdp_data(outcome: &ScanOutcome) -> Value {
    let raw_bytes = decode_banner_raw_bytes(&outcome.banner.raw_hex).unwrap_or_default();
    if let Some(value) = parse_json_payload(&raw_bytes) {
        return value;
    }

    let text = String::from_utf8_lossy(&raw_bytes);

    let mut security_layer = Map::new();
    let mut ciphers = Map::new();
    let mut ntlm_info = Map::new();
    let mut encryption_level: Option<String> = None;
    let mut protocol_version: Option<String> = None;

    enum Section {
        None,
        Security,
        Encryption,
        Ntlm,
    }

    let mut section = Section::None;
    for line in text.lines() {
        match line {
            "SECURITY_LAYER" => section = Section::Security,
            "END_SECURITY_LAYER" => section = Section::None,
            "ENCRYPTION" => section = Section::Encryption,
            "END_ENCRYPTION" => section = Section::None,
            "NTLM_INFO" => section = Section::Ntlm,
            "END_NTLM_INFO" => section = Section::None,
            _ => match section {
                Section::Security => {
                    if let Some((key, value)) = line.split_once(": ") {
                        security_layer.insert(key.to_string(), Value::String(value.to_string()));
                    }
                }
                Section::Encryption => {
                    if let Some((key, value)) = line.split_once(": ") {
                        if key == "RDP Encryption level" {
                            encryption_level = Some(value.to_string());
                        } else if key == "RDP Protocol Version" {
                            protocol_version = Some(value.to_string());
                        } else {
                            ciphers.insert(key.to_string(), Value::String(value.to_string()));
                        }
                    }
                }
                Section::Ntlm => {
                    if let Some((key, value)) = line.split_once(": ") {
                        ntlm_info.insert(key.to_string(), Value::String(value.to_string()));
                    }
                }
                Section::None => {}
            },
        }
    }

    serde_json::json!({
        "security_layer": security_layer,
        "rdp_encryption_level": encryption_level.unwrap_or_default(),
        "rdp_ciphers": ciphers,
        "rdp_protocol_version": protocol_version.unwrap_or_default(),
        "ntlm_info": ntlm_info,
        "tcp_port": outcome.target.port,
    })
}

fn parse_json_payload(bytes: &[u8]) -> Option<Value> {
    if let Ok(value) = serde_json::from_slice::<Value>(bytes) {
        if value.is_object() {
            return Some(value);
        }
    }

    let start = bytes.iter().position(|b| *b == b'{')?;
    let end = bytes.iter().rposition(|b| *b == b'}')?;
    if start >= end {
        return None;
    }
    serde_json::from_slice::<Value>(&bytes[start..=end]).ok()
}
