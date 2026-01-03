use crate::model::ScanOutcome;
use serde_json::Value;

use super::common::decode_banner_raw_bytes;

pub(super) fn ssh_data(outcome: &ScanOutcome) -> Value {
    let raw_bytes = decode_banner_raw_bytes(&outcome.banner.raw_hex).unwrap_or_default();
    let banner_raw = String::from_utf8_lossy(&raw_bytes).to_string();
    let banner = extract_ssh_banner_line(&banner_raw)
        .unwrap_or_else(|| banner_raw.trim_end_matches(&['\r', '\n'][..]).to_string());
    let (product, version, os) = parse_ssh_software(&banner);
    let kex = parse_ssh_kexinit(&raw_bytes).unwrap_or_default();
    let compression_algorithms = merge_algorithms(
        &kex.compression_algorithms_client_to_server,
        &kex.compression_algorithms_server_to_client,
    );
    let weak_algorithms = collect_weak_algorithms(&kex);
    serde_json::json!({
        "banner_raw": banner_raw,
        "banner": banner,
        "software": {
            "product": product,
            "version": version,
            "os": os,
        },
        "key_exchange": kex.key_exchange,
        "server_host_key_algorithms": kex.server_host_key_algorithms,
        "encryption_algorithms_client_to_server": kex.encryption_algorithms_client_to_server,
        "encryption_algorithms_server_to_client": kex.encryption_algorithms_server_to_client,
        "mac_algorithms_client_to_server": kex.mac_algorithms_client_to_server,
        "mac_algorithms_server_to_client": kex.mac_algorithms_server_to_client,
        "compression_algorithms": compression_algorithms,
        "strict_key_exchange": kex
            .key_exchange
            .iter()
            .any(|algo| algo == "kex-strict-s-v00@openssh.com"),
        "weak_algorithms": weak_algorithms,
        "fingerprint": {
            "rsa": "",
            "ecdsa": "",
            "ed25519": "",
        },
    })
}

#[derive(Default)]
struct SshKexInitData {
    key_exchange: Vec<String>,
    server_host_key_algorithms: Vec<String>,
    encryption_algorithms_client_to_server: Vec<String>,
    encryption_algorithms_server_to_client: Vec<String>,
    mac_algorithms_client_to_server: Vec<String>,
    mac_algorithms_server_to_client: Vec<String>,
    compression_algorithms_client_to_server: Vec<String>,
    compression_algorithms_server_to_client: Vec<String>,
}

fn extract_ssh_banner_line(raw: &str) -> Option<String> {
    raw.lines()
        .map(str::trim_end)
        .find(|line| line.starts_with("SSH-"))
        .map(|line| line.trim_end_matches(&['\r', '\n'][..]).to_string())
}

fn parse_ssh_software(banner: &str) -> (String, String, String) {
    if !banner.starts_with("SSH-") {
        return (String::new(), String::new(), String::new());
    }
    let mut parts = banner.splitn(3, '-');
    let _ = parts.next();
    let _ = parts.next();
    let rest = match parts.next() {
        Some(value) => value,
        None => return (String::new(), String::new(), String::new()),
    };
    let mut rest_parts = rest.splitn(2, ' ');
    let software_id = rest_parts.next().unwrap_or_default();
    let os = rest_parts.next().unwrap_or_default().to_string();
    let (product, version) = split_product_version(software_id);
    (product, version, os)
}

fn split_product_version(software_id: &str) -> (String, String) {
    let idx = software_id
        .find(|ch| ch == '_' || ch == '-')
        .unwrap_or(software_id.len());
    if idx == software_id.len() {
        return (software_id.to_string(), String::new());
    }
    let product = software_id[..idx].to_string();
    let version = software_id[idx + 1..].to_string();
    (product, version)
}

fn parse_ssh_kexinit(bytes: &[u8]) -> Option<SshKexInitData> {
    let mut pos = bytes.iter().position(|&b| b == b'\n')? + 1;
    while pos + 5 <= bytes.len() {
        let packet_len = read_u32(bytes, pos)? as usize;
        if packet_len == 0 {
            break;
        }
        let packet_end = pos + 4 + packet_len;
        if packet_end > bytes.len() {
            break;
        }
        let padding_len = bytes[pos + 4] as usize;
        if packet_len <= padding_len {
            pos = packet_end;
            continue;
        }
        let payload_len = packet_len.saturating_sub(padding_len + 1);
        let payload_start = pos + 5;
        let payload_end = payload_start + payload_len;
        if payload_end > bytes.len() {
            break;
        }
        let payload = &bytes[payload_start..payload_end];
        if payload.first() == Some(&20) {
            return parse_ssh_kexinit_payload(payload);
        }
        pos = packet_end;
    }
    None
}

fn parse_ssh_kexinit_payload(payload: &[u8]) -> Option<SshKexInitData> {
    if payload.len() < 17 {
        return None;
    }
    let mut idx = 1 + 16;
    let key_exchange = parse_name_list(payload, &mut idx)?;
    let server_host_key_algorithms = parse_name_list(payload, &mut idx)?;
    let encryption_algorithms_client_to_server = parse_name_list(payload, &mut idx)?;
    let encryption_algorithms_server_to_client = parse_name_list(payload, &mut idx)?;
    let mac_algorithms_client_to_server = parse_name_list(payload, &mut idx)?;
    let mac_algorithms_server_to_client = parse_name_list(payload, &mut idx)?;
    let compression_algorithms_client_to_server = parse_name_list(payload, &mut idx)?;
    let compression_algorithms_server_to_client = parse_name_list(payload, &mut idx)?;
    let _languages_client_to_server = parse_name_list(payload, &mut idx)?;
    let _languages_server_to_client = parse_name_list(payload, &mut idx)?;
    Some(SshKexInitData {
        key_exchange,
        server_host_key_algorithms,
        encryption_algorithms_client_to_server,
        encryption_algorithms_server_to_client,
        mac_algorithms_client_to_server,
        mac_algorithms_server_to_client,
        compression_algorithms_client_to_server,
        compression_algorithms_server_to_client,
    })
}

fn parse_name_list(payload: &[u8], idx: &mut usize) -> Option<Vec<String>> {
    let len = read_u32(payload, *idx)? as usize;
    *idx += 4;
    if *idx + len > payload.len() {
        return None;
    }
    let data = &payload[*idx..*idx + len];
    *idx += len;
    if len == 0 {
        return Some(Vec::new());
    }
    let list = String::from_utf8_lossy(data)
        .split(',')
        .filter(|entry| !entry.is_empty())
        .map(|entry| entry.to_string())
        .collect();
    Some(list)
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let slice = bytes.get(offset..offset + 4)?;
    Some(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn merge_algorithms(primary: &[String], secondary: &[String]) -> Vec<String> {
    let mut combined = Vec::new();
    for entry in primary.iter().chain(secondary.iter()) {
        if !combined.contains(entry) {
            combined.push(entry.clone());
        }
    }
    combined
}

fn collect_weak_algorithms(kex: &SshKexInitData) -> Vec<String> {
    let weak = [
        "ssh-rsa",
        "hmac-sha1",
        "hmac-sha1-etm@openssh.com",
        "diffie-hellman-group1-sha1",
        "diffie-hellman-group14-sha1",
        "diffie-hellman-group14-sha256",
    ];
    let mut found = Vec::new();
    for list in [
        &kex.key_exchange,
        &kex.server_host_key_algorithms,
        &kex.encryption_algorithms_client_to_server,
        &kex.encryption_algorithms_server_to_client,
        &kex.mac_algorithms_client_to_server,
        &kex.mac_algorithms_server_to_client,
        &kex.compression_algorithms_client_to_server,
        &kex.compression_algorithms_server_to_client,
    ] {
        for algo in list.iter() {
            if weak.contains(&algo.as_str()) && !found.contains(algo) {
                found.push(algo.clone());
            }
        }
    }
    found
}
