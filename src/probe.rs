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
        let bytes = reader.read(stream).await?;
        capture.extend_from_slice(&bytes);
        Ok(())
    }
}

pub struct ProbeRequest {
    pub target: Target,
    pub mode: ScanMode,
}

pub fn probe_for_target(req: &ProbeRequest) -> Option<Box<dyn Prober>> {
    if matches!(req.mode, ScanMode::Passive) {
        return None;
    }

    let probes: Vec<Box<dyn Prober>> = vec![Box::new(HttpProbe), Box::new(RedisProbe)];
    for probe in probes {
        if probe.matches(&req.target) {
            return Some(probe);
        }
    }
    None
}

pub fn fingerprint(banner: &[u8]) -> Fingerprint {
    let mut fields = BTreeMap::new();
    let text = String::from_utf8_lossy(banner).to_string();

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
        target.resolved.port() == 80
            || target.resolved.port() == 8080
            || target.resolved.port() == 8000
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
