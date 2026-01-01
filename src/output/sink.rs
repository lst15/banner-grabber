use crate::model::{OutputConfig, OutputFormat, ScanOutcome, Status};
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
                    http_data(&outcome)
                } else {
                    serde_json::json!({})
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

fn http_data(outcome: &ScanOutcome) -> Value {
    let status_reqwest = parse_http_status_code(&outcome.banner.printable).unwrap_or_default();
    let title = extract_html_title(&outcome.banner.printable).unwrap_or_default();
    let engine_body = outcome.webdriver.clone().unwrap_or_default();
    let body = extract_raw_body(&outcome.banner.printable).unwrap_or_default();
    let headers = parse_http_headers(&outcome.banner.printable);
    let location = find_header_value(&headers, "Location");
    let redirect_entry = location
        .as_deref()
        .map(|url| serde_json::json!({ "url": url, "status": status_reqwest }))
        .unwrap_or_else(|| serde_json::json!({ "url": "", "status": "" }));
    serde_json::json!({
        "status_code": {
            "engine": "",
            "reqwest": status_reqwest,
        },
        "headers": headers,
        "engine_body": engine_body,
        "body": body,
        "title": title,
        "favicon_hash": "",
        "technologies": "",
        "redirects": [
            redirect_entry
        ],
        "tls_info": {
            "cipher": "",
            "version": "",
            "cert_subject": "",
            "cert_issuer": "",
            "cert_valid_from": "",
            "cert_valid_to": "",
        },
    })
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

fn extract_raw_body(printable: &str) -> Option<String> {
    if let Some((_, body)) = printable.split_once("\r\n\r\n") {
        return Some(body.to_string());
    }
    if let Some((_, body)) = printable.split_once("\n\n") {
        return Some(body.to_string());
    }
    None
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
