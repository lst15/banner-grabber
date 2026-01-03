use crate::model::{OutputConfig, OutputFormat, ScanOutcome, Status, TlsInfo};
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::{BufWriter, Write};

pub struct OutputSink {
    cfg: OutputConfig,
    writer: BufWriter<std::io::Stdout>,
}

#[derive(Serialize)]
struct StandardizedOutcome<'a> {
    ip: &'a str,
    timestamp: &'a str,
    port: u16,
    proto: &'a str,
    ttl: Option<u8>,
    data: Value,
}

impl OutputSink {
    pub fn new(cfg: OutputConfig) -> Self {
        Self {
            cfg,
            writer: BufWriter::new(std::io::stdout()),
        }
    }

    pub fn write_outcome(&mut self, outcome: ScanOutcome) -> anyhow::Result<()> {
        match self.cfg.format {
            OutputFormat::Jsonl => {
                let proto = outcome.fingerprint.protocol.as_deref().unwrap_or("unknown");
                let data = if matches!(proto, "http" | "https") {
                    http_data(&outcome, proto)
                } else if proto == "imap" {
                    imap_data(&outcome)
                } else if matches!(proto, "mssql" | "ms-sql-s") {
                    mssql_data(&outcome)
                } else if proto == "ssh" {
                    ssh_data(&outcome)
                } else if proto == "postgres" {
                    postgres_data(&outcome)
                } else {
                    serde_json::json!(raw_banner_for_data(&outcome))
                };
                let formatted = StandardizedOutcome {
                    ip: &outcome.target.addr,
                    timestamp: &outcome.timestamp,
                    port: outcome.target.port,
                    proto,
                    ttl: outcome.ttl,
                    data,
                };
                let line = serde_json::to_string(&formatted)?;
                writeln!(self.writer, "{line}")?;
            }
            OutputFormat::Pretty => {
                writeln!(
                    self.writer,
                    "{} {} -> {}",
                    outcome.target.host,
                    outcome.target.port,
                    outcome.status_text()
                )?;
                writeln!(self.writer, "  banner: {}", outcome.banner.printable)?;
                if let Some(webdriver) = &outcome.webdriver {
                    writeln!(self.writer, "  webdriver: {}", webdriver)?;
                }
                if let Some(diag) = &outcome.diagnostics {
                    writeln!(
                        self.writer,
                        "  diagnostics: [{}] {}",
                        diag.stage, diag.message
                    )?;
                }
            }
        }
        Ok(())
    }

    pub fn flush(&mut self) {
        let _ = self.writer.flush();
    }
}

fn http_data(outcome: &ScanOutcome, proto: &str) -> Value {
    let status_reqwest = parse_http_status_code(&outcome.banner.printable).unwrap_or_default();
    let title = extract_html_title(&outcome.banner.printable).unwrap_or_default();
    let body = extract_http_body(&outcome.banner.printable);
    let engine_body = outcome.webdriver.clone().unwrap_or_default();
    let headers = parse_http_headers(&outcome.banner.printable);
    let tls_info = if proto == "https" {
        outcome.tls_info.clone().unwrap_or_default()
    } else {
        TlsInfo::default()
    };
    let technologies = outcome
        .technologies
        .as_ref()
        .map(|scan| {
            serde_json::json!({
                "scan_time_seconds": scan.scan_time_seconds,
                "list": &scan.list,
            })
        })
        .unwrap_or_else(|| serde_json::json!(""));
    let location = find_header_value(&headers, "Location");
    let redirect_entry = location
        .as_deref()
        .map(|url| serde_json::json!({ "url": url, "status": status_reqwest }))
        .unwrap_or_else(|| serde_json::json!({ "url": "", "status": "" }));
    serde_json::json!({
        "status_code": status_reqwest,
        "headers": headers,
        "body": body,
        "engine_body": engine_body,
        "title": title,
        "favicon_hash": "",
        "technologies": technologies,
        "redirects": [
            redirect_entry
        ],
        "tls_info": {
            "cipher": tls_info.cipher,
            "version": tls_info.version,
            "cert_subject": tls_info.cert_subject,
            "cert_issuer": tls_info.cert_issuer,
            "cert_valid_from": tls_info.cert_valid_from,
            "cert_valid_to": tls_info.cert_valid_to,
        },
    })
}

fn ssh_data(outcome: &ScanOutcome) -> Value {
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

fn raw_banner_for_data(outcome: &ScanOutcome) -> String {
    if !outcome.banner.printable.is_empty() {
        return outcome.banner.printable.clone();
    }
    decode_banner_raw(&outcome.banner.raw_hex).unwrap_or_default()
}

fn postgres_data(outcome: &ScanOutcome) -> Value {
    let raw_bytes = decode_banner_raw_bytes(&outcome.banner.raw_hex).unwrap_or_default();
    let parsed = parse_postgres_messages(&raw_bytes);
    let server_version = parsed
        .parameters
        .get("server_version")
        .cloned()
        .or(parsed.server_version);
    serde_json::json!({
        "protocol_version": "3.0",
        "server_version": server_version.clone().unwrap_or_default(),
        "server_type": "PostgreSQL",
        "version_detail": parse_postgres_version_detail(server_version.as_deref()),
        "auth_method": parsed.auth_method,
        "ssl_required": parsed.ssl_required,
        "parameters": parsed.parameters,
        "weak_auth": parsed.weak_auth,
        "allows_remote_connections": parsed.allows_remote_connections,
        "error_message": parsed.error_message,
        "supports_ssl": parsed.supports_ssl,
        "auth_code": parsed.auth_code,
        "auth_mechanisms": parsed.auth_mechanisms,
        "raw_hex": outcome.banner.raw_hex,
        "read_reason": outcome.banner.read_reason,
    })
}

struct PostgresAuthInfo {
    auth_method: String,
    auth_code: Option<u32>,
    auth_mechanisms: Vec<String>,
    parameters: BTreeMap<String, String>,
    error_message: Option<String>,
    server_version: Option<String>,
    supports_ssl: Option<bool>,
    ssl_required: Option<bool>,
    weak_auth: bool,
    allows_remote_connections: bool,
}

fn parse_postgres_messages(bytes: &[u8]) -> PostgresAuthInfo {
    let mut info = PostgresAuthInfo {
        auth_method: "unknown".to_string(),
        auth_code: None,
        auth_mechanisms: Vec::new(),
        parameters: BTreeMap::new(),
        error_message: None,
        server_version: None,
        supports_ssl: None,
        ssl_required: None,
        weak_auth: false,
        allows_remote_connections: true,
    };
    let mut idx = 0usize;
    while idx + 5 <= bytes.len() {
        let msg_type = bytes[idx];
        let Some(len) = read_u32(bytes, idx + 1) else {
            break;
        };
        let total_len = len as usize + 1;
        if total_len < 5 || idx + total_len > bytes.len() {
            break;
        }
        let payload = &bytes[idx + 5..idx + total_len];
        match msg_type {
            b'R' => parse_postgres_auth_request(payload, &mut info),
            b'S' => parse_postgres_parameter_status(payload, &mut info),
            b'E' => parse_postgres_error_response(payload, &mut info),
            _ => {}
        }
        idx += total_len;
    }

    if let Some(err) = info.error_message.as_deref() {
        if err.to_ascii_lowercase().contains("no pg_hba.conf entry") {
            info.allows_remote_connections = false;
        }
    }

    info.weak_auth = matches!(info.auth_method.as_str(), "trust" | "password");
    info
}

fn parse_postgres_auth_request(payload: &[u8], info: &mut PostgresAuthInfo) {
    let code = read_u32(payload, 0);
    info.auth_code = code;
    match code {
        Some(0) => info.auth_method = "trust".to_string(),
        Some(3) => info.auth_method = "password".to_string(),
        Some(5) => info.auth_method = "md5".to_string(),
        Some(10) => {
            info.auth_mechanisms = parse_postgres_sasl_mechanisms(payload.get(4..).unwrap_or(&[]));
            if info
                .auth_mechanisms
                .iter()
                .any(|mech| mech.eq_ignore_ascii_case("SCRAM-SHA-256"))
            {
                info.auth_method = "scram-sha-256".to_string();
            } else if !info.auth_mechanisms.is_empty() {
                info.auth_method = "sasl".to_string();
            }
        }
        Some(11) => info.auth_method = "sasl-continue".to_string(),
        Some(12) => info.auth_method = "sasl-final".to_string(),
        Some(_) | None => {}
    }
}

fn parse_postgres_parameter_status(payload: &[u8], info: &mut PostgresAuthInfo) {
    let (name, idx) = match read_cstring(payload, 0) {
        Some(val) => val,
        None => return,
    };
    let (value, _) = match read_cstring(payload, idx) {
        Some(val) => val,
        None => return,
    };
    if name == "server_version" {
        info.server_version = Some(value.clone());
    }
    info.parameters.insert(name, value);
}

fn parse_postgres_error_response(payload: &[u8], info: &mut PostgresAuthInfo) {
    let mut idx = 0usize;
    while idx < payload.len() {
        let field_type = payload[idx];
        idx += 1;
        if field_type == 0 {
            break;
        }
        let (value, next_idx) = match read_cstring(payload, idx) {
            Some(val) => val,
            None => break,
        };
        idx = next_idx;
        if field_type == b'M' {
            info.error_message = Some(value);
        }
    }
}

fn parse_postgres_sasl_mechanisms(bytes: &[u8]) -> Vec<String> {
    let mut mechanisms = Vec::new();
    let mut start = 0usize;
    for (idx, byte) in bytes.iter().enumerate() {
        if *byte == 0 {
            if idx == start {
                break;
            }
            let mech = String::from_utf8_lossy(&bytes[start..idx]).to_string();
            if !mech.is_empty() {
                mechanisms.push(mech);
            }
            start = idx + 1;
        }
    }
    mechanisms
}

fn parse_postgres_version_detail(value: Option<&str>) -> Value {
    let Some(value) = value else {
        return serde_json::json!({
            "major": null,
            "minor": null,
            "patch": null,
            "distribution": "",
            "build_info": "",
        });
    };
    let mut major = None;
    let mut minor = None;
    let mut patch = None;
    let mut distribution = String::new();
    let mut build_info = String::new();

    let mut parts = value.splitn(2, ' ');
    let version_part = parts.next().unwrap_or_default();
    let tail = parts.next().unwrap_or_default();
    let mut version_iter = version_part.split('.');
    major = version_iter.next().and_then(|v| v.parse::<u32>().ok());
    minor = version_iter.next().and_then(|v| v.parse::<u32>().ok());
    patch = version_iter.next().and_then(|v| v.parse::<u32>().ok());

    if let Some(start) = tail.find('(') {
        if let Some(end) = tail.rfind(')') {
            let inside = tail[start + 1..end].trim();
            if let Some((dist, build)) = inside.split_once(' ') {
                distribution = dist.to_string();
                build_info = build.to_string();
            } else {
                distribution = inside.to_string();
            }
        }
    }

    serde_json::json!({
        "major": major,
        "minor": minor,
        "patch": patch,
        "distribution": distribution,
        "build_info": build_info,
    })
}

fn read_cstring(bytes: &[u8], start: usize) -> Option<(String, usize)> {
    let end = bytes.get(start..)?.iter().position(|b| *b == 0)?;
    let slice = &bytes[start..start + end];
    let value = String::from_utf8_lossy(slice).to_string();
    Some((value, start + end + 1))
}

fn imap_data(outcome: &ScanOutcome) -> Value {
    let banner_raw = decode_banner_raw(&outcome.banner.raw_hex)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| raw_banner_for_data(outcome));
    let mut pre_login_capabilities = Vec::new();
    let mut errors_observed = Vec::new();
    let mut server_identity = String::new();
    let mut requires_auth_before_capability = false;

    for line in banner_raw.lines().map(|line| line.trim_end_matches('\r')) {
        if let Some(caps) = extract_imap_greeting_capabilities(line) {
            extend_unique(&mut pre_login_capabilities, caps);
        }
        if let Some(caps) = extract_imap_capability_line(line) {
            extend_unique(&mut pre_login_capabilities, caps);
        }
        if server_identity.is_empty() {
            if let Some(identity) = extract_imap_server_identity(line) {
                server_identity = identity;
            }
        }
        if let Some((tag, status)) = extract_imap_tag_status(line) {
            if status == "BAD" || status == "NO" {
                errors_observed.push(line.to_string());
                if tag == "a001" {
                    requires_auth_before_capability = true;
                }
            }
        }
    }

    let auth_mechanisms = pre_login_capabilities
        .iter()
        .filter_map(|cap| cap.strip_prefix("AUTH="))
        .map(|value| value.to_string())
        .collect::<Vec<_>>();
    let supports_starttls = pre_login_capabilities
        .iter()
        .any(|cap| cap.eq_ignore_ascii_case("STARTTLS"));
    let weak_auth = auth_mechanisms
        .iter()
        .any(|mech| mech.eq_ignore_ascii_case("LOGIN") || mech.eq_ignore_ascii_case("PLAIN"));
    let server_software = extract_imap_server_software(&server_identity);

    serde_json::json!({
        "banner": banner_raw,
        "server_software": server_software,
        "software_version": Value::Null,
        "capabilities": {
            "pre_login": pre_login_capabilities,
            "post_login": [],
        },
        "auth_mechanisms": auth_mechanisms,
        "supports_starttls": supports_starttls,
        "requires_auth_before_capability": requires_auth_before_capability,
        "server_identity": server_identity,
        "weak_auth": weak_auth,
        "errors_observed": errors_observed,
    })
}

fn mssql_data(outcome: &ScanOutcome) -> Value {
    let raw_bytes = decode_banner_raw_bytes(&outcome.banner.raw_hex).unwrap_or_default();
    let version_info = parse_mssql_prelogin_version(&raw_bytes);
    let version_json = match version_info {
        Some(info) => serde_json::json!({
            "name": info.name,
            "number": info.number,
            "product": info.product,
            "service_pack_level": info.service_pack_level,
            "post_sp_patches_applied": info.post_sp_patches_applied,
        }),
        None => serde_json::json!({
            "name": "",
            "number": "",
            "product": "",
            "service_pack_level": "",
            "post_sp_patches_applied": Value::Null,
        }),
    };

    serde_json::json!({
        "version": version_json,
        "tcp_port": outcome.target.port,
    })
}

fn extract_imap_greeting_capabilities(line: &str) -> Option<Vec<String>> {
    let start = line.find("[CAPABILITY ")?;
    let value_start = start + "[CAPABILITY ".len();
    let rest = &line[value_start..];
    let end = rest.find(']').unwrap_or(rest.len());
    let caps = rest[..end]
        .split_whitespace()
        .filter(|cap| !cap.is_empty())
        .map(|cap| cap.to_string())
        .collect::<Vec<_>>();
    if caps.is_empty() {
        None
    } else {
        Some(caps)
    }
}

fn extract_imap_capability_line(line: &str) -> Option<Vec<String>> {
    let prefix = "* CAPABILITY ";
    let value = line.strip_prefix(prefix)?;
    let caps = value
        .split_whitespace()
        .filter(|cap| !cap.is_empty())
        .map(|cap| cap.to_string())
        .collect::<Vec<_>>();
    if caps.is_empty() {
        None
    } else {
        Some(caps)
    }
}

fn extract_imap_server_identity(line: &str) -> Option<String> {
    if !line.starts_with("* OK") {
        return None;
    }
    if let Some(idx) = line.rfind("] ") {
        let identity = line[idx + 2..].trim();
        return Some(identity.to_string());
    }
    let identity = line.trim_start_matches("* OK").trim();
    if identity.is_empty() {
        None
    } else {
        Some(identity.to_string())
    }
}

fn extract_imap_tag_status(line: &str) -> Option<(&str, &str)> {
    let mut parts = line.split_whitespace();
    let tag = parts.next()?;
    let status = parts.next()?;
    if tag == "*" {
        return None;
    }
    Some((tag, status))
}

fn extract_imap_server_software(identity: &str) -> String {
    if identity.contains("Dovecot") {
        return "Dovecot".to_string();
    }
    if identity.contains("Cyrus") {
        return "Cyrus".to_string();
    }
    identity
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_string()
}

fn extend_unique(target: &mut Vec<String>, incoming: Vec<String>) {
    for item in incoming {
        if !target.contains(&item) {
            target.push(item);
        }
    }
}

fn decode_banner_raw(raw_hex: &str) -> Option<String> {
    let bytes = decode_banner_raw_bytes(raw_hex)?;
    Some(String::from_utf8_lossy(&bytes).to_string())
}

fn decode_banner_raw_bytes(raw_hex: &str) -> Option<Vec<u8>> {
    crate::util::hex::from_hex(raw_hex).ok()
}

struct MssqlVersionInfo {
    name: String,
    number: String,
    product: String,
    service_pack_level: String,
    post_sp_patches_applied: Option<bool>,
}

fn parse_mssql_prelogin_version(raw_bytes: &[u8]) -> Option<MssqlVersionInfo> {
    let payload = extract_tds_payload(raw_bytes);
    let parsed = payload
        .as_deref()
        .and_then(parse_mssql_prelogin_version_bytes)
        .or_else(|| parse_mssql_prelogin_version_any(raw_bytes))?;
    let (major, minor, build, sub_build) = parsed;
    let branded = mssql_branded_version(major, minor)?;
    let product = format!("Microsoft SQL Server {branded}");
    let (service_pack_level, post_sp_patches_applied) = mssql_service_pack_level(&branded, build);
    let number = format!("{}.{:02}.{}.{:02}", major, minor, build, sub_build);
    let name = mssql_version_name(&product, &service_pack_level, post_sp_patches_applied);

    Some(MssqlVersionInfo {
        name,
        number,
        product,
        service_pack_level,
        post_sp_patches_applied,
    })
}

fn extract_tds_payload(raw: &[u8]) -> Option<Vec<u8>> {
    let mut payload = Vec::new();
    let mut pos = 0;
    while pos + 8 <= raw.len() {
        let length = u16::from_be_bytes([raw[pos + 2], raw[pos + 3]]) as usize;
        if length < 8 || pos + length > raw.len() {
            break;
        }
        payload.extend_from_slice(&raw[pos + 8..pos + length]);
        pos += length;
    }
    if payload.is_empty() {
        None
    } else {
        Some(payload)
    }
}

fn parse_mssql_prelogin_version_bytes(payload: &[u8]) -> Option<(u8, u8, u16, u16)> {
    let mut pos = 0;
    while pos < payload.len() {
        let option_type = *payload.get(pos)?;
        pos += 1;
        if option_type == 0xff {
            break;
        }
        let offset = u16::from_be_bytes([*payload.get(pos)?, *payload.get(pos + 1)?]) as usize;
        pos += 2;
        let length = u16::from_be_bytes([*payload.get(pos)?, *payload.get(pos + 1)?]) as usize;
        pos += 2;
        let data_start = offset;
        let data_end = data_start + length;
        if data_end > payload.len() {
            return None;
        }
        if option_type == 0x00 && length >= 6 {
            let data = &payload[data_start..data_start + 6];
            let major = data[0];
            let minor = data[1];
            let build = u16::from_be_bytes([data[2], data[3]]);
            let sub_build = u16::from_be_bytes([data[4], data[5]]);
            return Some((major, minor, build, sub_build));
        }
    }
    None
}

fn parse_mssql_prelogin_version_any(bytes: &[u8]) -> Option<(u8, u8, u16, u16)> {
    if bytes.len() < 6 {
        return None;
    }
    for base in 0..bytes.len().saturating_sub(6) {
        if bytes.get(base)? != &0x00 {
            continue;
        }
        let offset = u16::from_be_bytes([*bytes.get(base + 1)?, *bytes.get(base + 2)?]) as usize;
        let length = u16::from_be_bytes([*bytes.get(base + 3)?, *bytes.get(base + 4)?]) as usize;
        if length < 6 {
            continue;
        }
        let data_start = base + offset;
        if data_start + 6 > bytes.len() {
            continue;
        }
        let data = &bytes[data_start..data_start + 6];
        let major = data[0];
        let minor = data[1];
        if !(6..=20).contains(&major) || minor > 60 {
            continue;
        }
        let build = u16::from_be_bytes([data[2], data[3]]);
        let sub_build = u16::from_be_bytes([data[4], data[5]]);
        return Some((major, minor, build, sub_build));
    }
    None
}

fn mssql_branded_version(major: u8, minor: u8) -> Option<&'static str> {
    match (major, minor) {
        (6, 0) => Some("6.0"),
        (6, 5) => Some("6.5"),
        (7, 0) => Some("7.0"),
        (8, 0) => Some("2000"),
        (9, 0) => Some("2005"),
        (10, 0) => Some("2008"),
        (10, 50) => Some("2008 R2"),
        (11, 0) => Some("2012"),
        (12, 0) => Some("2014"),
        (13, 0) => Some("2016"),
        (14, 0) => Some("2017"),
        (15, 0) => Some("2019"),
        (16, 0) => Some("2022"),
        _ => None,
    }
}

fn mssql_version_name(product: &str, service_pack_level: &str, patched: Option<bool>) -> String {
    if service_pack_level.is_empty() {
        return product.to_string();
    }
    let mut name = format!("{product} {service_pack_level}");
    if matches!(patched, Some(true)) {
        name.push('+');
    }
    name
}

fn mssql_service_pack_level(branded_version: &str, build: u16) -> (String, Option<bool>) {
    let table = match branded_version {
        "6.5" => MSSQL_SP_65,
        "7.0" => MSSQL_SP_70,
        "2000" => MSSQL_SP_2000,
        "2005" => MSSQL_SP_2005,
        "2008" => MSSQL_SP_2008,
        "2008 R2" => MSSQL_SP_2008_R2,
        "2012" => MSSQL_SP_2012,
        "2014" => MSSQL_SP_2014,
        "2016" => MSSQL_SP_2016,
        "2017" => MSSQL_SP_2017,
        "2019" => MSSQL_SP_2019,
        "2022" => MSSQL_SP_2022,
        _ => &[],
    };

    if table.is_empty() {
        return (String::new(), None);
    }

    if build < table[0].0 {
        return ("Pre-RTM".to_string(), None);
    }

    let mut last = table[0];
    for entry in table.iter() {
        if entry.0 > build {
            break;
        }
        last = *entry;
    }

    let patched = Some(build != last.0);
    (last.1.to_string(), patched)
}

const MSSQL_SP_65: &[(u16, &str)] = &[
    (201, "RTM"),
    (213, "SP1"),
    (240, "SP2"),
    (258, "SP3"),
    (281, "SP4"),
    (415, "SP5"),
    (416, "SP5a"),
    (417, "SP5/SP5a"),
];

const MSSQL_SP_70: &[(u16, &str)] = &[
    (623, "RTM"),
    (699, "SP1"),
    (842, "SP2"),
    (961, "SP3"),
    (1063, "SP4"),
];

const MSSQL_SP_2000: &[(u16, &str)] = &[
    (194, "RTM"),
    (384, "SP1"),
    (532, "SP2"),
    (534, "SP2"),
    (760, "SP3"),
    (766, "SP3a"),
    (767, "SP3/SP3a"),
    (2039, "SP4"),
];

const MSSQL_SP_2005: &[(u16, &str)] = &[
    (1399, "RTM"),
    (2047, "SP1"),
    (3042, "SP2"),
    (4035, "SP3"),
    (5000, "SP4"),
];

const MSSQL_SP_2008: &[(u16, &str)] = &[
    (1600, "RTM"),
    (2531, "SP1"),
    (4000, "SP2"),
    (5500, "SP3"),
    (6000, "SP4"),
];

const MSSQL_SP_2008_R2: &[(u16, &str)] =
    &[(1600, "RTM"), (2500, "SP1"), (4000, "SP2"), (6000, "SP3")];

const MSSQL_SP_2012: &[(u16, &str)] = &[
    (1103, "CTP1"),
    (1440, "CTP3"),
    (1750, "RC0"),
    (1913, "RC1"),
    (2100, "RTM"),
    (2316, "RTMCU1"),
    (2325, "RTMCU2"),
    (2332, "RTMCU3"),
    (2383, "RTMCU4"),
    (2395, "RTMCU5"),
    (2401, "RTMCU6"),
    (2405, "RTMCU7"),
    (2410, "RTMCU8"),
    (2419, "RTMCU9"),
    (2420, "RTMCU10"),
    (2424, "RTMCU11"),
    (3000, "SP1"),
    (3321, "SP1CU1"),
    (3339, "SP1CU2"),
    (3349, "SP1CU3"),
    (3368, "SP1CU4"),
    (3373, "SP1CU5"),
    (3381, "SP1CU6"),
    (3393, "SP1CU7"),
    (3401, "SP1CU8"),
    (3412, "SP1CU9"),
    (3431, "SP1CU10"),
    (3449, "SP1CU11"),
    (3470, "SP1CU12"),
    (3482, "SP1CU13"),
    (3486, "SP1CU14"),
    (3487, "SP1CU15"),
    (3492, "SP1CU16"),
    (5058, "SP2"),
    (5532, "SP2CU1"),
    (5548, "SP2CU2"),
    (5556, "SP2CU3"),
    (5569, "SP2CU4"),
    (5582, "SP2CU5"),
    (5592, "SP2CU6"),
    (5623, "SP2CU7"),
    (5634, "SP2CU8"),
    (5641, "SP2CU9"),
    (5644, "SP2CU10"),
    (5646, "SP2CU11"),
    (5649, "SP2CU12"),
    (5655, "SP2CU13"),
    (5657, "SP2CU14"),
    (5676, "SP2CU15"),
    (5678, "SP2CU16"),
    (6020, "SP3"),
    (6518, "SP3CU1"),
    (6523, "SP3CU2"),
    (6537, "SP3CU3"),
    (6540, "SP3CU4"),
    (6544, "SP3CU5"),
    (6567, "SP3CU6"),
    (6579, "SP3CU7"),
    (6594, "SP3CU8"),
    (6598, "SP3CU9"),
    (6607, "SP3CU10"),
    (7001, "SP4"),
];

const MSSQL_SP_2014: &[(u16, &str)] = &[
    (1524, "CTP2"),
    (2000, "RTM"),
    (2342, "RTMCU1"),
    (2370, "RTMCU2"),
    (2402, "RTMCU3"),
    (2430, "RTMCU4"),
    (2456, "RTMCU5"),
    (2480, "RTMCU6"),
    (2495, "RTMCU7"),
    (2546, "RTMCU8"),
    (2553, "RTMCU9"),
    (2556, "RTMCU10"),
    (2560, "RTMCU11"),
    (2564, "RTMCU12"),
    (2568, "RTMCU13"),
    (2569, "RTMCU14"),
    (4100, "SP1"),
    (4416, "SP1CU1"),
    (4422, "SP1CU2"),
    (4427, "SP1CU3"),
    (4436, "SP1CU4"),
    (4439, "SP1CU5"),
    (4449, "SP1CU6"),
    (4459, "SP1CU7"),
    (4468, "SP1CU8"),
    (4474, "SP1CU9"),
    (4491, "SP1CU10"),
    (4502, "SP1CU11"),
    (4511, "SP1CU12"),
    (4522, "SP1CU13"),
    (5000, "SP2"),
    (5511, "SP2CU1"),
    (5522, "SP2CU2"),
    (5538, "SP2CU3"),
    (5540, "SP2CU4"),
    (5546, "SP2CU5"),
    (5553, "SP2CU6"),
    (5556, "SP2CU7"),
    (5557, "SP2CU8"),
    (5563, "SP2CU9"),
    (5571, "SP2CU10"),
    (5579, "SP2CU11"),
    (5589, "SP2CU12"),
    (5590, "SP2CU13"),
    (5600, "SP2CU14"),
    (5605, "SP2CU15"),
    (5626, "SP2CU16"),
    (5632, "SP2CU17"),
    (5687, "SP2CU18"),
    (6024, "SP3"),
    (6205, "SP3CU1"),
    (6214, "SP3CU2"),
    (6259, "SP3CU3"),
    (6329, "SP3CU4"),
];

const MSSQL_SP_2016: &[(u16, &str)] = &[
    (200, "CTP2"),
    (300, "CTP2.1"),
    (407, "CTP2.2"),
    (500, "CTP2.3"),
    (600, "CTP2.4"),
    (700, "CTP3.0"),
    (800, "CTP3.1"),
    (900, "CTP3.2"),
    (1000, "CTP3.3"),
    (1100, "RC0"),
    (1200, "RC1"),
    (1300, "RC2"),
    (1400, "RC3"),
    (1601, "RTM"),
    (2149, "RTMCU1"),
    (2164, "RTMCU2"),
    (2186, "RTMCU3"),
    (2193, "RTMCU4"),
    (2197, "RTMCU5"),
    (2204, "RTMCU6"),
    (2210, "RTMCU7"),
    (2213, "RTMCU8"),
    (2216, "RTMCU9"),
    (4001, "SP1"),
    (4411, "SP1CU1"),
    (4422, "SP1CU2"),
    (4435, "SP1CU3"),
    (4446, "SP1CU4"),
    (4451, "SP1CU5"),
    (4457, "SP1CU6"),
    (4466, "SP1CU7"),
    (4474, "SP1CU8"),
    (4502, "SP1CU9"),
    (4514, "SP1CU10"),
    (4528, "SP1CU11"),
    (4541, "SP1CU12"),
    (4550, "SP1CU13"),
    (4560, "SP1CU14"),
    (4574, "SP1CU15"),
    (5026, "SP2"),
    (5149, "SP2CU1"),
    (5153, "SP2CU2"),
    (5216, "SP2CU3"),
    (5233, "SP2CU4"),
    (5264, "SP2CU5"),
    (5292, "SP2CU6"),
    (5337, "SP2CU7"),
    (5426, "SP2CU8"),
    (5479, "SP2CU9"),
    (5492, "SP2CU10"),
    (5598, "SP2CU11"),
    (5698, "SP2CU12"),
    (5820, "SP2CU13"),
    (5830, "SP2CU14"),
    (5850, "SP2CU15"),
    (5882, "SP2CU16"),
    (5888, "SP2CU17"),
    (6300, "SP3"),
];

const MSSQL_SP_2017: &[(u16, &str)] = &[
    (1, "CTP1"),
    (100, "CTP1.1"),
    (200, "CTP1.2"),
    (304, "CTP1.3"),
    (405, "CTP1.4"),
    (500, "CTP2.0"),
    (600, "CTP2.1"),
    (800, "RC1"),
    (900, "RC2"),
    (1000, "RTM"),
    (3006, "CU1"),
    (3008, "CU2"),
    (3015, "CU3"),
    (3022, "CU4"),
    (3023, "CU5"),
    (3025, "CU6"),
    (3026, "CU7"),
    (3029, "CU8"),
    (3030, "CU9"),
    (3037, "CU10"),
    (3038, "CU11"),
    (3045, "CU12"),
    (3048, "CU13"),
    (3076, "CU14"),
    (3162, "CU15"),
    (3223, "CU16"),
    (3238, "CU17"),
    (3257, "CU18"),
    (3281, "CU19"),
    (3294, "CU20"),
    (3335, "CU21"),
    (3356, "CU22"),
    (3381, "CU23"),
    (3391, "CU24"),
    (3401, "CU25"),
    (3411, "CU26"),
    (3421, "CU27"),
    (3430, "CU28"),
    (3436, "CU29"),
    (3451, "CU30"),
    (3456, "CU31"),
];

const MSSQL_SP_2019: &[(u16, &str)] = &[
    (1000, "CTP2.0"),
    (1100, "CTP2.1"),
    (1200, "CTP2.2"),
    (1300, "CTP2.3"),
    (1400, "CTP2.4"),
    (1500, "CTP2.5"),
    (1600, "CTP3.0"),
    (1700, "CTP3.1"),
    (1800, "CTP3.2"),
    (1900, "RC1"),
    (2000, "RTM"),
    (2070, "GDR1"),
    (4003, "CU1"),
    (4013, "CU2"),
    (4023, "CU3"),
    (4033, "CU4"),
    (4043, "CU5"),
    (4053, "CU6"),
    (4063, "CU7"),
    (4073, "CU8"),
    (4102, "CU9"),
    (4123, "CU10"),
    (4138, "CU11"),
    (4153, "CU12"),
    (4178, "CU13"),
    (4188, "CU14"),
    (4198, "CU15"),
    (4223, "CU16"),
    (4249, "CU17"),
    (4261, "CU18"),
    (4298, "CU19"),
    (4312, "CU20"),
    (4316, "CU21"),
    (4322, "CU22"),
    (4335, "CU23"),
    (4345, "CU24"),
    (4355, "CU25"),
];

const MSSQL_SP_2022: &[(u16, &str)] = &[
    (100, "CTP1.0"),
    (101, "CTP1.1"),
    (200, "CTP1.2"),
    (300, "CTP1.3"),
    (400, "CTP1.4"),
    (500, "CTP1.5"),
    (600, "CTP2.0"),
    (700, "CTP2.1"),
    (900, "RC0"),
    (950, "RC1"),
    (1000, "RTM"),
    (4003, "CU1"),
    (4015, "CU2"),
    (4025, "CU3"),
    (4035, "CU4"),
    (4045, "CU5"),
    (4055, "CU6"),
    (4065, "CU7"),
    (4075, "CU8"),
    (4085, "CU9"),
    (4095, "CU10"),
    (4105, "CU11"),
];

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

fn extract_http_body(printable: &str) -> String {
    if let Some(idx) = printable.find("\r\n\r\n") {
        return printable[idx + 4..].to_string();
    }
    if let Some(idx) = printable.find("\n\n") {
        return printable[idx + 2..].to_string();
    }
    String::new()
}

fn parse_http_status_code(printable: &str) -> Option<String> {
    let line = printable.lines().next()?.trim_start();
    let mut parts = line.split_whitespace();
    let protocol = parts.next()?;
    if !protocol.to_ascii_uppercase().starts_with("HTTP/") {
        return None;
    }
    let code = parts.next()?;
    Some(code.to_string())
}

fn parse_http_headers(printable: &str) -> BTreeMap<String, String> {
    let mut headers = BTreeMap::new();
    let mut lines = printable.lines();
    let first_line = match lines.next() {
        Some(line) => line.trim_start(),
        None => return headers,
    };
    if !first_line.to_ascii_uppercase().starts_with("HTTP/") {
        return headers;
    }
    for line in lines {
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            break;
        }
        let Some((name, value)) = trimmed.split_once(':') else {
            continue;
        };
        let key = name.trim().to_string();
        let val = value.trim().to_string();
        headers
            .entry(key)
            .and_modify(|existing| {
                if !val.is_empty() {
                    if !existing.is_empty() {
                        existing.push_str(", ");
                    }
                    existing.push_str(&val);
                }
            })
            .or_insert(val);
    }
    headers
}

fn find_header_value(headers: &BTreeMap<String, String>, name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.clone())
}

fn extract_html_title(printable: &str) -> Option<String> {
    let lowered = printable.to_lowercase();
    let start = lowered.find("<title")?;
    let tag_end = lowered[start..].find('>')? + start;
    let after_tag = tag_end + 1;
    let end = lowered[after_tag..].find("</title>")? + after_tag;
    let title = printable[after_tag..end].trim();
    if title.is_empty() {
        None
    } else {
        Some(title.to_string())
    }
}

impl ScanOutcome {
    fn status_text(&self) -> &'static str {
        match self.status {
            Status::Open => "open",
            Status::Timeout => "timeout",
            Status::Error => "error",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_postgres_scram_auth_request() {
        let bytes = [
            0x52, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x0a, 0x53, 0x43, 0x52,
            0x41, 0x4d, 0x2d, 0x53, 0x48, 0x41, 0x2d, 0x32, 0x35, 0x36, 0x00, 0x00,
        ];
        let info = parse_postgres_messages(&bytes);
        assert_eq!(info.auth_code, Some(10));
        assert_eq!(info.auth_method, "scram-sha-256");
        assert_eq!(info.auth_mechanisms, vec!["SCRAM-SHA-256".to_string()]);
    }

    #[test]
    fn parses_postgres_parameter_status() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"S\0\0\0\0");
        let payload = b"server_version\015.4\0";
        let len = (payload.len() + 4) as u32;
        bytes[1..5].copy_from_slice(&len.to_be_bytes());
        bytes.extend_from_slice(payload);
        let info = parse_postgres_messages(&bytes);
        assert_eq!(
            info.parameters.get("server_version"),
            Some(&"15.4".to_string())
        );
    }

    #[test]
    fn parses_postgres_error_response() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"E\0\0\0\0");
        let payload = b"Mno pg_hba.conf entry\0\0";
        let len = (payload.len() + 4) as u32;
        bytes[1..5].copy_from_slice(&len.to_be_bytes());
        bytes.extend_from_slice(payload);
        let info = parse_postgres_messages(&bytes);
        assert_eq!(
            info.error_message,
            Some("no pg_hba.conf entry".to_string())
        );
        assert!(!info.allows_remote_connections);
    }
}
