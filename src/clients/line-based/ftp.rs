use crate::model::{Config, Target};
use async_trait::async_trait;
use tokio::net::TcpStream;

use crate::clients::session::ClientSession;
use crate::clients::Client;

pub(crate) struct FtpClient;

#[async_trait]
impl Client for FtpClient {
    fn name(&self) -> &'static str {
        "ftp"
    }

    fn matches(&self, target: &Target) -> bool {
        target.resolved.port() == 21
    }

    async fn execute(
        &self,
        stream: &mut TcpStream,
        cfg: &Config,
    ) -> anyhow::Result<crate::engine::reader::ReadResult> {
        let mut session = ClientSession::new(cfg);
        // LOGIN ANÔNIMO
        session.send(stream, b"USER anonymous\r\n").await?;
        session.read(stream, None).await?;

        session.send(stream, b"PASS anonymous\r\n").await?;
        session.read(stream, None).await?;

        // session.read(stream, None).await.expect("ERR");
        // session.send(stream, b"FEAT\r\n").await.expect("ERR");
        // session.read(stream, None).await.expect("ERR");
        // session.send(stream, b"SYST\r\n").await.expect("ERR");;
        // session.read(stream, None).await.expect("ERR");
        Ok(session.finish())
    }
}
