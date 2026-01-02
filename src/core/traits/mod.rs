use crate::core::engine::reader::{BannerReader, ReadResult};
use crate::core::model::{Config, Target};
use anyhow::Context;
use async_trait::async_trait;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

#[async_trait]
pub trait Prober: Send + Sync {
    fn name(&self) -> &'static str;
    fn probe_bytes(&self) -> &'static [u8];
    fn expected_delimiter(&self) -> Option<&'static [u8]> {
        None
    }

    #[allow(dead_code)]
    fn matches(&self, target: &Target) -> bool;

    async fn execute(
        &self,
        mut stream: TcpStream,
        cfg: &Config,
        _target: &Target,
    ) -> anyhow::Result<ReadResult> {
        if !self.probe_bytes().is_empty() {
            stream
                .write_all(self.probe_bytes())
                .await
                .with_context(|| format!("failed to write probe {}", self.name()))?;
        }

        let mut reader = BannerReader::new(cfg.max_bytes, cfg.read_timeout);
        reader.read(&mut stream, self.expected_delimiter()).await
    }
}
