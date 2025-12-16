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
            protocol: Some(self.name().into()),
            score: 0.7,
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
    let text = String::from_utf8_lossy(banner).to_string();
    let lower = text.to_lowercase();

    if let Some(version) = tls_version(banner) {
        fields.insert("hint".into(), "tls-handshake".into());
        fields.insert("version".into(), version);
        return Fingerprint {
            protocol: Some("tls".into()),
            score: 0.75,
            fields,
        };
    }

    if text.starts_with("SSH-") {
        fields.insert("hint".into(), "ssh-like".into());
        return Fingerprint {
            protocol: Some("ssh".into()),
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
    if banner.len() < 3 {
        return None;
    }

    if banner[0] == 0x16 && banner[1] == 0x03 {
        let major = banner[1];
        let minor = banner[2];
        return Some(format!("TLS {major}.{minor}"));
    }

    None
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
            Some("TLS 3.4")
        );
    }

    #[test]
    fn fingerprints_smtp_and_ftp() {
        let smtp_fp = fingerprint(b"220 mail.example.com ESMTP ready\r\n");
        assert_eq!(smtp_fp.protocol.as_deref(), Some("smtp"));
        let ftp_fp = fingerprint(b"220 FTP server ready\r\n");
        assert_eq!(ftp_fp.protocol.as_deref(), Some("ftp"));
    }
}
