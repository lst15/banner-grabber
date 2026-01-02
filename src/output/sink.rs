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
                } else if proto == "ssh" {
                    ssh_data(&outcome)
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
