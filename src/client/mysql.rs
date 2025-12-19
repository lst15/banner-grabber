use crate::model::{Config, Target};
use async_trait::async_trait;
use tokio::net::TcpStream;

use super::session::ClientSession;
use super::Client;

pub(super) struct MysqlClient;

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
        deadline: std::time::Instant,
    ) -> anyhow::Result<crate::engine::reader::ReadResult> {
        let mut session = ClientSession::new(cfg, deadline);
        let _ = session.read(stream, None).await?;
        Ok(session.finish())
    }
}
