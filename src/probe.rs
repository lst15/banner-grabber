use crate::engine::reader::{BannerReader, ReadResult};
use crate::model::Config;
use crate::model::{Fingerprint, ScanMode, Target};
use anyhow::Context;
use async_trait::async_trait;
use std::collections::BTreeMap;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

#[async_trait]
pub trait Prober: Send + Sync {
    fn name(&self) -> &'static str;
    fn probe_bytes(&self) -> &'static [u8];
    fn expected_delimiter(&self) -> Option<&'static [u8]> {
        None
    }

    fn matches(&self, target: &Target) -> bool;

    #[allow(dead_code)]
    fn fingerprint(&self, _banner: &ReadResult) -> Fingerprint {
        Fingerprint {
            protocol: None,
            score: 0.0,
            fields: Default::default(),
        }
    }

    async fn execute(&self, stream: &mut TcpStream, cfg: &Config) -> anyhow::Result<ReadResult> {
        if !self.probe_bytes().is_empty() {
            stream
                .write_all(self.probe_bytes())
                .await
                .with_context(|| format!("failed to write probe {}", self.name()))?;
        }

        let mut reader = BannerReader::new(cfg.max_bytes, cfg.read_timeout);
        reader.read(stream, self.expected_delimiter()).await
    }
}

pub struct ProbeRequest {
    pub target: Target,
    pub mode: ScanMode,
}

static HTTP_PROBE: HttpProbe = HttpProbe;
static REDIS_PROBE: RedisProbe = RedisProbe;
static TLS_PROBE: TlsProbe = TlsProbe;
static PROBES: [&dyn Prober; 3] = [&REDIS_PROBE, &TLS_PROBE, &HTTP_PROBE];

pub fn probe_for_target(req: &ProbeRequest) -> Option<&'static dyn Prober> {
    if matches!(req.mode, ScanMode::Passive) {
        return None;
    }

    // Always reuse the same probe instances to avoid allocations on hot paths.
    if let Some(probe) = PROBES
        .iter()
        .copied()
        .find(|probe| probe.matches(&req.target))
    {
        return Some(probe);
    }

    // Fall back to a generic HTTP probe in active mode to coax banners from
    // services running on non-standard ports that are unlikely to speak TLS.
    matches!(req.mode, ScanMode::Active)
        .then(|| {
            if is_probably_tls_port(req.target.resolved.port()) {
                None
            } else {
                Some(&HTTP_PROBE as &'static dyn Prober)
            }
        })
        .flatten()
}

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

struct HttpProbe;
struct RedisProbe;
struct TlsProbe;

impl Prober for HttpProbe {
    fn name(&self) -> &'static str {
        "http"
    }

    fn probe_bytes(&self) -> &'static [u8] {
        b"GET / HTTP/1.0\r\nHost: example\r\n\r\n"
    }

    fn matches(&self, target: &Target) -> bool {
        matches!(target.resolved.port(), 80 | 443 | 8000 | 8080 | 8443)
    }
}

impl Prober for RedisProbe {
    fn name(&self) -> &'static str {
        "redis"
    }

    fn probe_bytes(&self) -> &'static [u8] {
        b"PING\r\n"
    }

    fn matches(&self, target: &Target) -> bool {
        target.resolved.port() == 6379
    }
}

impl Prober for TlsProbe {
    fn name(&self) -> &'static str {
        "tls"
    }

    fn probe_bytes(&self) -> &'static [u8] {
        // Minimal TLS ClientHello that negotiates modern cipher suites without
        // allocating on the hot path.
        const CLIENT_HELLO: &[u8] = b"\x16\x03\x01\x00\x31\x01\x00\x00\x2d\x03\x03\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x00\x00\x02\x13\x01\x00\x00\x05\x00\xff\x01\x00\x01\x00";
        CLIENT_HELLO
    }

    fn matches(&self, target: &Target) -> bool {
        is_probably_tls_port(target.resolved.port())
    }
}

fn is_probably_tls_port(port: u16) -> bool {
    matches!(port, 443 | 8443 | 9443 | 10443)
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

    #[test]
    fn fingerprints_tls() {
        let banner = ReadResult {
            bytes: vec![0x16, 0x03, 0x04, 0x00, 0x20],
            reason: crate::model::ReadStopReason::Delimiter,
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
            reason: crate::model::ReadStopReason::Delimiter,
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
            reason: crate::model::ReadStopReason::ConnectionClosed,
            truncated: false,
        });
        assert_eq!(smtp_fp.protocol.as_deref(), Some("smtp"));
        let ftp_fp = fingerprint(&ReadResult {
            bytes: b"220 FTP server ready\r\n".to_vec(),
            reason: crate::model::ReadStopReason::ConnectionClosed,
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
            reason: crate::model::ReadStopReason::ConnectionClosed,
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
            reason: crate::model::ReadStopReason::ConnectionClosed,
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
            reason: crate::model::ReadStopReason::Delimiter,
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
