use crate::core::model::{Config, Target};
use async_trait::async_trait;
use tokio::net::TcpStream;

use crate::core::clients::session::ClientSession;
use crate::core::clients::Client;

pub(crate) struct PostgresClient;

#[async_trait]
impl Client for PostgresClient {
    fn name(&self) -> &'static str {
        "postgres"
    }

    fn matches(&self, target: &Target) -> bool {
        target.resolved.port() == 5432
    }

    async fn execute(
        &self,
        stream: &mut TcpStream,
        cfg: &Config,
    ) -> anyhow::Result<crate::core::engine::reader::ReadResult> {
        let mut session = ClientSession::new(cfg);
        let mut body = Vec::new();
        body.extend_from_slice(&196_608u32.to_be_bytes());
        body.extend_from_slice(b"user\0banner\0database\0postgres\0\0");

        let length = (body.len() + 4) as u32;
        let mut startup = Vec::new();
        startup.extend_from_slice(&length.to_be_bytes());
        startup.extend_from_slice(&body);

        session.send(stream, &startup).await?;
        session.read(stream, None).await?;
        Ok(session.finish())
    }
}
