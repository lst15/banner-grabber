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

#[async_trait]
pub trait Prober: Send + Sync {
    fn name(&self) -> &'static str;
    fn probe_bytes(&self) -> &'static [u8];

    fn build_probe(&self, _target: &Target) -> std::borrow::Cow<'static, [u8]> {
        std::borrow::Cow::Borrowed(self.probe_bytes())
    }
    fn expected_delimiter(&self) -> Option<&'static [u8]> {
        None
    }

    fn matches(&self, target: &Target) -> bool;

    #[allow(dead_code)]
    fn fingerprint(&self, _banner: &ReadResult) -> crate::model::Fingerprint {
        fingerprint(_banner)
    }

    async fn execute(
        &self,
        stream: &mut TcpStream,
        cfg: &Config,
        target: &Target,
    ) -> anyhow::Result<ReadResult> {
        let probe_bytes = self.build_probe(target);

        if !probe_bytes.is_empty() {
            stream
                .write_all(&probe_bytes)
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
static PROBES: [&dyn Prober; 2] = [&REDIS_PROBE, &TLS_PROBE];

pub fn probe_for_target(req: &ProbeRequest) -> Option<&'static dyn Prober> {
    if matches!(req.mode, ScanMode::Passive) {
        return None;
    }

    if HTTP_PROBE.matches(&req.target) {
        return Some(&HTTP_PROBE);
    }

    if let Some(probe) = PROBES
        .iter()
        .copied()
        .find(|probe| probe.matches(&req.target))
    {
        return Some(probe);
    }

    matches!(req.mode, ScanMode::Active).then_some(&HTTP_PROBE as &'static dyn Prober)
}
