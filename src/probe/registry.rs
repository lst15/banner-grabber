use crate::engine::reader::{BannerReader, ReadResult};
use crate::model::{Config, ScanMode, Target};
use anyhow::Context;
use async_trait::async_trait;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use super::fingerprint;
use super::http::HttpProbe;
use super::redis::RedisProbe;
use super::tls::TlsProbe;
use super::is_probably_tls_port;

#[async_trait]
pub trait Prober: Send + Sync {
    fn name(&self) -> &'static str;
    fn probe_bytes(&self) -> &'static [u8];
    fn expected_delimiter(&self) -> Option<&'static [u8]> {
        None
    }

    fn matches(&self, target: &Target) -> bool;

    #[allow(dead_code)]
    fn fingerprint(&self, _banner: &ReadResult) -> crate::model::Fingerprint {
        fingerprint(_banner)
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

    if let Some(probe) = PROBES
        .iter()
        .copied()
        .find(|probe| probe.matches(&req.target))
    {
        return Some(probe);
    }

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
