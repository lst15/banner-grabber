use crate::model::ScanOutcome;
use serde_json::Value;

use super::common::decode_banner_raw_bytes;

pub(super) fn mysql_data(outcome: &ScanOutcome) -> Value {
    let raw_bytes = decode_banner_raw_bytes(&outcome.banner.raw_hex).unwrap_or_default();
    let info = parse_mysql_greeting(&raw_bytes);

    let capabilities = info.capabilities.clone().unwrap_or_default();
    let status = info.status.map(|value| {
        if value == 2 {
            "Autocommit".to_string()
        } else {
            value.to_string()
        }
    });

    serde_json::json!({
        "protocol": info.protocol.map(Value::from).unwrap_or(Value::Null),
        "version": info.version.unwrap_or_default(),
        "thread_id": info.thread_id.map(Value::from).unwrap_or(Value::Null),
        "capabilities_flags": info.capabilities_flags.map(Value::from).unwrap_or(Value::Null),
        "capabilities": capabilities,
        "status": status.unwrap_or_default(),
        "salt": info.salt.unwrap_or_default(),
        "auth_plugin_name": info.auth_plugin_name.unwrap_or_default(),
        "tcp_port": outcome.target.port,
    })
}

#[derive(Default)]
struct MysqlGreetingInfo {
    protocol: Option<u8>,
    version: Option<String>,
    thread_id: Option<u32>,
    capabilities_flags: Option<u16>,
    capabilities: Option<Vec<String>>,
    status: Option<u16>,
    salt: Option<String>,
    auth_plugin_name: Option<String>,
}

fn parse_mysql_greeting(raw_bytes: &[u8]) -> MysqlGreetingInfo {
    let mut info = MysqlGreetingInfo::default();
    let payload = extract_mysql_payload(raw_bytes).unwrap_or_else(|| raw_bytes.to_vec());
    if payload.is_empty() {
        return info;
    }

    let mut pos = 0usize;
    let protocol = payload.get(pos).copied();
    pos += 1;
    info.protocol = protocol;

    let (version, next) = read_null_terminated(&payload, pos);
    if version.is_empty() {
        return info;
    }
    info.version = Some(version);
    pos = next;

    if let Some(thread_id) = read_u32_le(&payload, pos) {
        info.thread_id = Some(thread_id);
        pos += 4;
    } else {
        return info;
    }

    if protocol != Some(10) {
        return info;
    }

    let salt_part1 = payload.get(pos..pos + 8).unwrap_or_default().to_vec();
    if salt_part1.len() == 8 {
        pos += 8;
    }

    pos = pos.saturating_add(1);
    let capabilities = read_u16_le(&payload, pos);
    if let Some(flags) = capabilities {
        info.capabilities_flags = Some(flags);
        pos += 2;
    } else {
        return info;
    }

    let charset = payload.get(pos).copied();
    let _ = charset;
    pos += 1;

    let status = read_u16_le(&payload, pos);
    if let Some(value) = status {
        info.status = Some(value);
        pos += 2;
    } else {
        return info;
    }

    let extcapabilities = read_u16_le(&payload, pos);
    let extcapabilities = match extcapabilities {
        Some(value) => {
            pos += 2;
            value
        }
        None => return info,
    };

    let auth_plugin_len = payload.get(pos).copied().unwrap_or(0) as usize;
    pos += 1;

    pos = pos.saturating_add(10);

    let mut salt = salt_part1;
    let extra_len = std::cmp::max(13, auth_plugin_len.saturating_sub(8));
    let salt_part2_len = extra_len.saturating_sub(1);
    if salt_part2_len > 0 {
        let end = std::cmp::min(payload.len(), pos + salt_part2_len);
        if end > pos {
            salt.extend_from_slice(&payload[pos..end]);
            pos = end;
        }
    }
    if !salt.is_empty() {
        info.salt = Some(format_salt(&salt));
    }

    let capabilities_list = capabilities_list(capabilities.unwrap_or_default(), extcapabilities);
    if !capabilities_list.is_empty() {
        info.capabilities = Some(capabilities_list);
    }

    if extcapabilities & EXT_CAPABILITIES_SUPPORTS_AUTH_PLUGINS != 0 {
        let (plugin, _) = read_null_terminated(&payload, pos);
        if !plugin.is_empty() {
            info.auth_plugin_name = Some(plugin);
        }
    }

    info
}

fn extract_mysql_payload(raw: &[u8]) -> Option<Vec<u8>> {
    if raw.len() < 4 {
        return None;
    }
    let len = raw[0] as usize | ((raw[1] as usize) << 8) | ((raw[2] as usize) << 16);
    if len == 0 || raw.len() < 4 + len {
        return None;
    }
    Some(raw[4..4 + len].to_vec())
}

fn read_null_terminated(bytes: &[u8], start: usize) -> (String, usize) {
    if start >= bytes.len() {
        return (String::new(), start);
    }
    let end = bytes[start..]
        .iter()
        .position(|&b| b == 0)
        .map(|idx| start + idx)
        .unwrap_or(bytes.len());
    let value = String::from_utf8_lossy(&bytes[start..end]).to_string();
    let next = if end < bytes.len() { end + 1 } else { end };
    (value, next)
}

fn read_u16_le(bytes: &[u8], offset: usize) -> Option<u16> {
    let slice = bytes.get(offset..offset + 2)?;
    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    let slice = bytes.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn format_salt(bytes: &[u8]) -> String {
    let mut out = String::new();
    for &b in bytes {
        if (0x20..=0x7e).contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("\\x{b:02x}"));
        }
    }
    out
}

fn capabilities_list(flags: u16, ext_flags: u16) -> Vec<String> {
    let mut caps = Vec::new();
    for (name, bit) in CAPABILITIES {
        if flags & bit != 0 {
            caps.push((*name).to_string());
        }
    }
    for (name, bit) in EXT_CAPABILITIES {
        if ext_flags & bit != 0 {
            caps.push((*name).to_string());
        }
    }
    caps
}

const CAPABILITIES: &[(&str, u16)] = &[
    ("LongPassword", 0x0001),
    ("FoundRows", 0x0002),
    ("LongColumnFlag", 0x0004),
    ("ConnectWithDatabase", 0x0008),
    ("DontAllowDatabaseTableColumn", 0x0010),
    ("SupportsCompression", 0x0020),
    ("ODBCClient", 0x0040),
    ("SupportsLoadDataLocal", 0x0080),
    ("IgnoreSpaceBeforeParenthesis", 0x0100),
    ("Speaks41ProtocolNew", 0x0200),
    ("InteractiveClient", 0x0400),
    ("SwitchToSSLAfterHandshake", 0x0800),
    ("IgnoreSigpipes", 0x1000),
    ("SupportsTransactions", 0x2000),
    ("Speaks41ProtocolOld", 0x4000),
    ("Support41Auth", 0x8000),
];

const EXT_CAPABILITIES: &[(&str, u16)] = &[
    ("SupportsMultipleStatments", 0x0001),
    ("SupportsMultipleResults", 0x0002),
    ("SupportsAuthPlugins", 0x0008),
];

const EXT_CAPABILITIES_SUPPORTS_AUTH_PLUGINS: u16 = 0x0008;
