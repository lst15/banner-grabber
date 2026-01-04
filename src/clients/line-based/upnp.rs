use crate::model::{Config, Target};
use async_trait::async_trait;
use tokio::net::TcpStream;

use crate::clients::session::ClientSession;
use crate::clients::Client;

pub(crate) struct UpnpClient;

#[async_trait]
impl Client for UpnpClient {
    fn name(&self) -> &'static str {
        "upnp"
    }

    fn matches(&self, target: &Target) -> bool {
        target.resolved.port() == 1900
    }

    async fn execute(
        &self,
        stream: &mut TcpStream,
        cfg: &Config,
    ) -> anyhow::Result<crate::engine::reader::ReadResult> {
        let mut session = ClientSession::new(cfg);
        session.read(stream, None).await?;
        Ok(session.finish())
    }
}
