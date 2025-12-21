use crate::engine::reader::{BannerReader, ReadResult};
use crate::model::{Config, Protocol, ScanMode, Target};
use anyhow::Context;
use async_trait::async_trait;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use super::http::HttpProbe;
use super::redis::RedisProbe;
use super::tls::TlsProbe;

#[async_trait]
pub trait Prober: Send + Sync {
    fn name(&self) -> &'static str;
    fn probe_bytes(&self) -> &'static [u8];
    fn expected_delimiter(&self) -> Option<&'static [u8]> {
        None
    }

    #[allow(dead_code)]
    fn matches(&self, target: &Target) -> bool;

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
    #[allow(dead_code)]
    pub target: Target,
    pub mode: ScanMode,
    pub protocol: Protocol,
}

static HTTP_PROBE: HttpProbe = HttpProbe;
static REDIS_PROBE: RedisProbe = RedisProbe;
static TLS_PROBE: TlsProbe = TlsProbe;

pub fn probe_for_target(req: &ProbeRequest) -> Option<&'static dyn Prober> {
    if matches!(req.mode, ScanMode::Passive) {
        return None;
    }

    match req.protocol {
        Protocol::Http => Some(&HTTP_PROBE as &'static dyn Prober),
        Protocol::Https | Protocol::Tls => Some(&TLS_PROBE as &'static dyn Prober),
        Protocol::Redis => Some(&REDIS_PROBE as &'static dyn Prober),
        _ => None,
    }
}
