use crate::core::model::{Config, Target};
use async_trait::async_trait;
use tokio::net::TcpStream;

use crate::core::clients::session::ClientSession;
use crate::core::clients::Client;

pub(crate) struct RedisClient;

#[async_trait]
impl Client for RedisClient {
    fn name(&self) -> &'static str {
        "redis"
    }

    fn matches(&self, target: &Target) -> bool {
        target.resolved.port() == 6379
    }

    async fn execute(
        &self,
        stream: &mut TcpStream,
        cfg: &Config,
    ) -> anyhow::Result<crate::core::engine::reader::ReadResult> {
        let mut session = ClientSession::new(cfg);
        session.send(stream, b"PING\r\n").await?;
        session.read(stream, None).await?;
        session.send(stream, b"INFO\r\n").await?;
        session.read(stream, None).await?;
        Ok(session.finish())
    }
}
