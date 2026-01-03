use crate::model::ScanOutcome;
use serde_json::Value;

use super::common::{decode_banner_raw, raw_banner_for_data};

pub(super) fn imap_data(outcome: &ScanOutcome) -> Value {
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
