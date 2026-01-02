use crate::core::model::{Config, Target};
use async_trait::async_trait;
use tokio::net::TcpStream;

use crate::core::clients::session::ClientSession;
use crate::core::clients::Client;

pub(crate) struct Pop3Client;

#[async_trait]
impl Client for Pop3Client {
    fn name(&self) -> &'static str {
        "pop3"
    }

    fn matches(&self, target: &Target) -> bool {
        target.resolved.port() == 110
    }

    async fn execute(
        &self,
        stream: &mut TcpStream,
        cfg: &Config,
    ) -> anyhow::Result<crate::core::engine::reader::ReadResult> {
        let mut session = ClientSession::new(cfg);
        session.read(stream, Some(b"\n")).await?;
        session.send(stream, b"CAPA\r\n").await?;
        session.read(stream, None).await?;
        Ok(session.finish())
    }
}
