use crate::clients::session::ClientSession;
use crate::clients::Client;
use crate::model::{Config, Target};
use async_trait::async_trait;
use tokio::net::TcpStream;

pub(crate) struct ImqBrokerClient;

#[async_trait]
impl Client for ImqBrokerClient {
    fn name(&self) -> &'static str {
        "imqbroker"
    }

    fn matches(&self, target: &Target) -> bool {
        matches!(
            target.resolved.port(),
            7676 | 7677 | 7678 | 7679 | 8686 | 8687 | 9696
        )
    }

    async fn execute(
        &self,
        stream: &mut TcpStream,
        cfg: &Config,
    ) -> anyhow::Result<crate::engine::reader::ReadResult> {
        let mut session = ClientSession::new(cfg);
        session.send(stream, b"101 imqbroker probe\n").await?;
        session.read(stream, Some(b"\n")).await?;
        Ok(session.finish())
    }
}
