use crate::core::model::{Config, Target};
use async_trait::async_trait;
use tokio::net::TcpStream;

use crate::core::clients::session::ClientSession;
use crate::core::clients::Client;

pub(crate) struct MysqlClient;

#[async_trait]
impl Client for MysqlClient {
    fn name(&self) -> &'static str {
        "mysql"
    }

    fn matches(&self, target: &Target) -> bool {
        target.resolved.port() == 3306
    }

    async fn execute(
        &self,
        stream: &mut TcpStream,
        cfg: &Config,
    ) -> anyhow::Result<crate::core::engine::reader::ReadResult> {
        let mut session = ClientSession::new(cfg);
        session.read(stream, None).await?;
        Ok(session.finish())
    }
}
