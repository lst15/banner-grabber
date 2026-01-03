use crate::model::{ScanOutcome, TlsInfo};
use serde_json::Value;
use std::collections::BTreeMap;

pub(super) fn http_data(outcome: &ScanOutcome, proto: &str) -> Value {
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
