use super::Prober;
use crate::engine::reader::BannerReader;
use crate::model::{Config, Target};
use anyhow::Context;
use async_trait::async_trait;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

pub(super) struct HttpProbe;

#[async_trait]
impl Prober for HttpProbe {
    fn name(&self) -> &'static str {
        "http"
    }

    fn probe_bytes(&self) -> &'static [u8] {
        &[]
    }

    fn matches(&self, target: &Target) -> bool {
        matches!(target.resolved.port(), 80 | 443 | 8000 | 8080 | 8443)
    }

    async fn execute(
        &self,
        mut stream: TcpStream,
        cfg: &Config,
        target: &Target,
    ) -> anyhow::Result<crate::engine::reader::ReadResult> {
        let host = target.original.host.as_str();
        let host_header = if host.is_empty() {
            target.resolved.ip().to_string()
        } else {
            host.to_string()
        };
        let request = format!("GET / HTTP/1.0\r\nHost: {host_header}\r\n\r\n");

        stream
            .write_all(request.as_bytes())
            .await
            .with_context(|| format!("failed to write probe {}", self.name()))?;

        let mut reader = BannerReader::new(cfg.max_bytes, cfg.read_timeout);
        reader.read(&mut stream, self.expected_delimiter()).await
    }
}
