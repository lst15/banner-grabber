use crate::engine::reader::BannerReader;
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
    fn fingerprint(&self, _banner: &[u8]) -> Fingerprint {
        Fingerprint {
            protocol: None,
            score: 0.0,
            fields: Default::default(),
        }
    }

    async fn execute(
        &self,
        stream: &mut TcpStream,
        capture: &mut Vec<u8>,
        cfg: &Config,
    ) -> anyhow::Result<()> {
        if !self.probe_bytes().is_empty() {
            stream
                .write_all(self.probe_bytes())
                .await
                .with_context(|| format!("failed to write probe {}", self.name()))?;
        }

        let mut reader = BannerReader::new(cfg.max_bytes);
        let bytes = reader.read(stream, self.expected_delimiter()).await?;
        capture.extend_from_slice(&bytes);
        Ok(())
    }
}

pub struct ProbeRequest {
    pub target: Target,
    pub mode: ScanMode,
}

static HTTP_PROBE: HttpProbe = HttpProbe;
static REDIS_PROBE: RedisProbe = RedisProbe;
static PROBES: [&dyn Prober; 2] = [&REDIS_PROBE, &HTTP_PROBE];

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
    // services running on non-standard ports.
    matches!(req.mode, ScanMode::Active).then_some(&HTTP_PROBE as &'static dyn Prober)
}

pub fn fingerprint(banner: &[u8]) -> Fingerprint {
    let mut fields = BTreeMap::new();
    fields.insert("length".into(), banner.len().to_string());
    let text = String::from_utf8_lossy(banner).to_string();
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
        let banner = [0x16, 0x03, 0x04, 0x00, 0x20];
        let fp = fingerprint(&banner);
        assert_eq!(fp.protocol.as_deref(), Some("tls"));
        assert_eq!(
            fp.fields.get("version").map(|s| s.as_str()),
            Some("TLS 1.3")
        );
    }

    #[test]
    fn fingerprints_tls_without_known_version() {
        let banner = [0x16, 0x03, 0x05, 0x00, 0x20];
        let fp = fingerprint(&banner);
        assert_eq!(fp.protocol.as_deref(), Some("tls"));
        assert!(fp.fields.get("version").is_none());
    }

    #[test]
    fn fingerprints_smtp_and_ftp() {
        let smtp_fp = fingerprint(b"220 mail.example.com ESMTP ready\r\n");
        assert_eq!(smtp_fp.protocol.as_deref(), Some("smtp"));
        let ftp_fp = fingerprint(b"220 FTP server ready\r\n");
        assert_eq!(ftp_fp.protocol.as_deref(), Some("ftp"));
    }

    #[test]
    fn fingerprints_mysql_handshake() {
        let mut banner = vec![0x2c, 0x00, 0x00, 0x00, 0x0a];
        banner.extend_from_slice(b"8.0.36\0");
        let fp = fingerprint(&banner);
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
        let fp = fingerprint(b"SSH-2.0-OpenSSH_9.3\r\n");
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
        let banner = b"500 internal server error\r\n";
        let fp = fingerprint(banner);
        assert_eq!(fp.protocol, None);
        assert_eq!(
            fp.fields.get("error").map(|s| s.as_str()),
            Some("500 internal server error")
        );
        let length = banner.len().to_string();
        assert_eq!(
            fp.fields.get("length").map(|s| s.as_str()),
            Some(length.as_str())
        );
    }
}
