use crate::model::{Config, Target};
use async_trait::async_trait;
use tokio::net::TcpStream;

use super::session::ClientSession;
use super::Client;

pub(super) struct MemcachedClient;

#[async_trait]
impl Client for MemcachedClient {
    fn name(&self) -> &'static str {
        "memcached"
    }

    fn matches(&self, target: &Target) -> bool {
        target.resolved.port() == 11211
    }

    async fn execute(
        &self,
        stream: &mut TcpStream,
        cfg: &Config,
    ) -> anyhow::Result<crate::engine::reader::ReadResult> {
        let mut session = ClientSession::new(cfg);
        session.send(stream, b"version\r\n").await?;
        session.read(stream, None).await?;
        session.send(stream, b"stats\r\n").await?;
        session.read(stream, None).await?;
        Ok(session.finish())
    }
}
