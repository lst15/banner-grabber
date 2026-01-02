use crate::core::model::{Config, Target};
use async_trait::async_trait;
use tokio::net::TcpStream;

use crate::core::clients::session::ClientSession;
use crate::core::clients::Client;

pub(crate) struct ImapClient;

#[async_trait]
impl Client for ImapClient {
    fn name(&self) -> &'static str {
        "imap"
    }

    fn matches(&self, target: &Target) -> bool {
        target.resolved.port() == 143
    }

    async fn execute(
        &self,
        stream: &mut TcpStream,
        cfg: &Config,
    ) -> anyhow::Result<crate::core::engine::reader::ReadResult> {
        let mut session = ClientSession::new(cfg);
        session.read(stream, Some(b"\n")).await?;
        session.send(stream, b"a001 CAPABILITY\r\n").await?;
        session.read(stream, None).await?;

        session.send(stream, b"a002 NAMESPACE\r\n").await?;
        session.read(stream, None).await?;
        //
        // // session.send(stream, b"a002 ID (\"name\" \"fingerprint\")\r\n").await?;
        // session.read(stream, None).await?;

        Ok(session.finish())
    }
}
