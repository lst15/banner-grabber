use crate::model::{Config, Target};
use async_trait::async_trait;
use base64::Engine;
use tokio::net::TcpStream;

use crate::clients::session::ClientSession;
use crate::clients::Client;

pub(crate) struct SmtpClient;

#[async_trait]
impl Client for SmtpClient {
    fn name(&self) -> &'static str {
        "smtp"
    }

    fn matches(&self, target: &Target) -> bool {
        matches!(target.resolved.port(), 25 | 587)
    }

    async fn execute(
        &self,
        stream: &mut TcpStream,
        cfg: &Config,
    ) -> anyhow::Result<crate::engine::reader::ReadResult> {
        let mut session = ClientSession::new(cfg);
        session.read(stream, None).await?;

        session.send(stream, b"EHLO banner-grabber\r\n").await?;
        session.read(stream, None).await?;

        session.send(stream, b"HELP\r\n").await?;
        session.read(stream, None).await?;

        session
            .send(stream, b"MAIL FROM:<usertest@banner-grabber>\r\n")
            .await?;
        session.read(stream, None).await?;

        session
            .send(stream, b"RCPT TO:<root@banner-grabber>\r\n")
            .await?;
        session.read(stream, None).await?;

        session.send(stream, b"EXPN root\r\n").await?;
        session.read(stream, None).await?;

        session.send(stream, b"AUTH NTLM\r\n").await?;
        session.read(stream, None).await?;

        let ntlm_blob = build_ntlm_type1_blob();
        let mut auth_line = Vec::with_capacity(ntlm_blob.len() + 2);
        auth_line.extend_from_slice(ntlm_blob.as_bytes());
        auth_line.extend_from_slice(b"\r\n");
        session.send(stream, &auth_line).await?;
        session.read(stream, None).await?;

        session.send(stream, b"QUIT\r\n").await?;
        session.read(stream, None).await?;
        Ok(session.finish())
    }
}

fn build_ntlm_type1_blob() -> String {
    let mut message = Vec::new();
    message.extend_from_slice(b"NTLMSSP\0");
    message.extend_from_slice(&1u32.to_le_bytes());
    let flags = 0x00000001u32
        | 0x00000002
        | 0x00000004
        | 0x00000200
        | 0x00008000
        | 0x00080000
        | 0x20000000
        | 0x80000000;
    message.extend_from_slice(&flags.to_le_bytes());
    message.extend_from_slice(&[0u8; 8]);
    message.extend_from_slice(&[0u8; 8]);

    base64::engine::general_purpose::STANDARD.encode(message)
}
