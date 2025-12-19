use crate::engine::reader::ReadResult;
use crate::model::Fingerprint;
use std::collections::BTreeMap;

pub fn fingerprint(read: &ReadResult) -> Fingerprint {
    let banner = &read.bytes;
    let mut fields = BTreeMap::new();
    fields.insert("length".into(), banner.len().to_string());
    fields.insert("truncated".into(), read.truncated.to_string());
    fields.insert("read_reason".into(), format!("{:?}", read.reason));
    let limited: Vec<u8> = banner.iter().copied().take(2048).collect();
    let text = String::from_utf8_lossy(&limited).to_string();
    let lower = text.to_lowercase();

    if is_tls_handshake(banner) {
        fields.insert("hint".into(), "tls-handshake".into());
        if let Some(version) = tls_version(banner) {
            fields.insert("version".into(), version);
        }
        return Fingerprint {
            protocol: Some("tls".into()),
            score: 0.75,
            fields,
        };
    }

    if let Some((proto_version, software)) = ssh_details(&text) {
        fields.insert("hint".into(), "ssh-like".into());
        fields.insert("protocol_version".into(), proto_version);
        if let Some(software) = software {
            fields.insert("software".into(), software);
        }
        return Fingerprint {
            protocol: Some("ssh".into()),
            score: 0.9,
            fields,
        };
    }
    if let Some(version) = mysql_version(banner) {
        fields.insert("hint".into(), "mysql-handshake".into());
        fields.insert("version".into(), version);
        return Fingerprint {
            protocol: Some("mysql".into()),
            score: 0.9,
            fields,
        };
    }
    if text.contains("HTTP/1.") || text.contains("Server:") {
        fields.insert("hint".into(), "http".into());
        return Fingerprint {
            protocol: Some("http".into()),
            score: 0.8,
            fields,
        };
    }
    if banner.starts_with(b"-ERR") {
        fields.insert("hint".into(), "redis/resp".into());
        return Fingerprint {
            protocol: Some("redis".into()),
            score: 0.7,
            fields,
        };
    }
    if lower.starts_with("220") && lower.contains("smtp") {
        fields.insert("hint".into(), "smtp".into());
        return Fingerprint {
            protocol: Some("smtp".into()),
            score: 0.7,
            fields,
        };
    }
    if lower.starts_with("220") && lower.contains("ftp") {
        fields.insert("hint".into(), "ftp".into());
        return Fingerprint {
            protocol: Some("ftp".into()),
            score: 0.65,
            fields,
        };
    }

    if let Some(error) = extract_error_line(&text) {
        fields.insert("error".into(), error);
    }

    Fingerprint {
        protocol: None,
        score: 0.1,
        fields,
    }
}

fn tls_version(banner: &[u8]) -> Option<String> {
    if !is_tls_handshake(banner) {
        return None;
    }

    match banner[2] {
        0x00 => Some("SSL 3.0".into()),
        0x01 => Some("TLS 1.0".into()),
        0x02 => Some("TLS 1.1".into()),
        0x03 => Some("TLS 1.2".into()),
        0x04 => Some("TLS 1.3".into()),
        _ => None,
    }
}

fn is_tls_handshake(banner: &[u8]) -> bool {
    banner.len() >= 3 && banner[0] == 0x16 && banner[1] == 0x03
}

fn ssh_details(text: &str) -> Option<(String, Option<String>)> {
    let line = text.lines().next()?.trim();
    if !line.starts_with("SSH-") {
        return None;
    }

    let mut parts = line.splitn(3, '-');
    let _ssh_tag = parts.next()?;
    let proto_version = parts.next()?.to_string();
    let software = parts.next().map(|s| s.to_string());

    Some((proto_version, software))
}

fn mysql_version(banner: &[u8]) -> Option<String> {
    if banner.len() < 6 {
        return None;
    }

    let payload = banner.get(4..)?;
    if payload.first().copied()? != 0x0a {
        return None;
    }

    let version_bytes: Vec<u8> = payload
        .iter()
        .copied()
        .skip(1)
        .take_while(|b| *b != 0)
        .collect();
    if version_bytes.is_empty() {
        return None;
    }

    String::from_utf8(version_bytes).ok()
}

fn extract_error_line(text: &str) -> Option<String> {
    text.lines()
        .map(str::trim)
        .find(|line| {
            let lower = line.to_ascii_lowercase();
            !line.is_empty()
                && (lower.contains("error")
                    || lower.contains("denied")
                    || lower.starts_with("-err"))
        })
        .map(|line| line.chars().take(160).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ReadStopReason;

    #[test]
    fn fingerprints_tls() {
        let banner = ReadResult {
            bytes: vec![0x16, 0x03, 0x04, 0x00, 0x20],
            reason: ReadStopReason::Delimiter,
            truncated: false,
        };
        let fp = fingerprint(&banner);
        assert_eq!(fp.protocol.as_deref(), Some("tls"));
        assert_eq!(
            fp.fields.get("version").map(|s| s.as_str()),
            Some("TLS 1.3")
        );
    }

    #[test]
    fn fingerprints_tls_without_known_version() {
        let banner = ReadResult {
            bytes: vec![0x16, 0x03, 0x05, 0x00, 0x20],
            reason: ReadStopReason::Delimiter,
            truncated: false,
        };
        let fp = fingerprint(&banner);
        assert_eq!(fp.protocol.as_deref(), Some("tls"));
        assert!(fp.fields.get("version").is_none());
    }

    #[test]
    fn fingerprints_smtp_and_ftp() {
        let smtp_fp = fingerprint(&ReadResult {
            bytes: b"220 mail.example.com ESMTP ready\r\n".to_vec(),
            reason: ReadStopReason::ConnectionClosed,
            truncated: false,
        });
        assert_eq!(smtp_fp.protocol.as_deref(), Some("smtp"));
        let ftp_fp = fingerprint(&ReadResult {
            bytes: b"220 FTP server ready\r\n".to_vec(),
            reason: ReadStopReason::ConnectionClosed,
            truncated: false,
        });
        assert_eq!(ftp_fp.protocol.as_deref(), Some("ftp"));
    }

    #[test]
    fn fingerprints_mysql_handshake() {
        let mut banner = vec![0x2c, 0x00, 0x00, 0x00, 0x0a];
        banner.extend_from_slice(b"8.0.36\0");
        let fp = fingerprint(&ReadResult {
            bytes: banner.clone(),
            reason: ReadStopReason::ConnectionClosed,
            truncated: false,
        });
        assert_eq!(fp.protocol.as_deref(), Some("mysql"));
        assert_eq!(fp.fields.get("version").map(|s| s.as_str()), Some("8.0.36"));
        let length = banner.len().to_string();
        assert_eq!(
            fp.fields.get("length").map(|s| s.as_str()),
            Some(length.as_str())
        );
    }

    #[test]
    fn fingerprints_ssh_with_details() {
        let fp = fingerprint(&ReadResult {
            bytes: b"SSH-2.0-OpenSSH_9.3\r\n".to_vec(),
            reason: ReadStopReason::ConnectionClosed,
            truncated: false,
        });
        assert_eq!(fp.protocol.as_deref(), Some("ssh"));
        assert_eq!(
            fp.fields.get("protocol_version").map(|s| s.as_str()),
            Some("2.0")
        );
        assert_eq!(
            fp.fields.get("software").map(|s| s.as_str()),
            Some("OpenSSH_9.3")
        );
    }

    #[test]
    fn fingerprints_error_banners() {
        let banner = ReadResult {
            bytes: b"500 internal server error\r\n".to_vec(),
            reason: ReadStopReason::Delimiter,
            truncated: false,
        };
        let fp = fingerprint(&banner);
        assert_eq!(fp.protocol, None);
        assert_eq!(
            fp.fields.get("error").map(|s| s.as_str()),
            Some("500 internal server error")
        );
        let length = banner.bytes.len().to_string();
        assert_eq!(
            fp.fields.get("length").map(|s| s.as_str()),
            Some(length.as_str())
        );
    }
}
