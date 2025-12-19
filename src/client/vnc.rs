use crate::model::{Config, Target};
use async_trait::async_trait;
use tokio::net::TcpStream;

use super::session::ClientSession;
use super::Client;

pub(super) struct VncClient;

const VNC_PORT_START: u16 = 5900;
const VNC_PORT_END: u16 = 5909;

#[async_trait]
impl Client for VncClient {
    fn name(&self) -> &'static str {
        "vnc"
    }

    fn matches(&self, target: &Target) -> bool {
        (VNC_PORT_START..=VNC_PORT_END).contains(&target.resolved.port())
    }

    async fn execute(
        &self,
        stream: &mut TcpStream,
        cfg: &Config,
    ) -> anyhow::Result<crate::engine::reader::ReadResult> {
        let mut session = ClientSession::new(cfg);

        let initial = session.read_with_result(stream, Some(b"\n")).await?;

        if let Ok(version_text) = std::str::from_utf8(&initial.bytes) {
            let version = version_text.trim_end_matches(&['\r', '\n'][..]);
            if version.starts_with("RFB ") && !version.is_empty() {
                let reply = format!("{version}\n");
                session.send(stream, reply.as_bytes()).await?;
            }
        }

        session.read(stream, None).await?;
        Ok(session.finish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Config, OutputConfig, OutputFormat, ScanMode, TargetSpec};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    #[tokio::test]
    async fn echoes_server_version_during_handshake() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(b"RFB 003.008\n").await.unwrap();
            let mut buf = [0u8; 32];
            let n = socket.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"RFB 003.008\n");
            socket.write_all(b"SecurityType\0").await.unwrap();
        });

        let cfg = Config {
            target: Some(TargetSpec {
                host: "127.0.0.1".into(),
                port: addr.port(),
            }),
            input: None,
            port_filter: None,
            concurrency: 1,
            rate: 1,
            connect_timeout: Duration::from_millis(500),
            read_timeout: Duration::from_millis(500),
            overall_timeout: Duration::from_millis(1000),
            max_bytes: 128,
            mode: ScanMode::Active,
            output: OutputConfig {
                format: OutputFormat::Pretty,
            },
        };

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let result = VncClient.execute(&mut stream, &cfg).await.unwrap();
        let printable = std::str::from_utf8(&result.bytes).unwrap();
        assert!(printable.contains("RFB 003.008"));
    }
}
