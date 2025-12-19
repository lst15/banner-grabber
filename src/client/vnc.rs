use crate::model::{Config, Target};
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

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
        let mut metadata = String::new();

        let initial = session.read_with_result(stream, Some(b"\n")).await?;

        if let Ok(version_text) = std::str::from_utf8(&initial.bytes) {
            let version = version_text.trim_end_matches(&['\r', '\n'][..]);
            metadata.push_str(&format!("Protocol Version: {version}\n"));
            if version.starts_with("RFB ") && !version.is_empty() {
                let reply = format!("{version}\n");
                session.send(stream, reply.as_bytes()).await?;

                if let Some((major, minor)) = parse_version(version) {
                    let mut security_types = Vec::new();

                    if (major, minor) >= (3, 7) {
                        let mut count = [0u8; 1];
                        read_exact_timeout(stream, &mut count, cfg.read_timeout).await?;
                        let count = count[0] as usize;

                        if count > 0 {
                            let mut buf = vec![0u8; count];
                            read_exact_timeout(stream, &mut buf, cfg.read_timeout).await?;
                            security_types.extend(buf);
                        }
                    } else {
                        let mut buf = [0u8; 4];
                        read_exact_timeout(stream, &mut buf, cfg.read_timeout).await?;
                        let security_type = u32::from_be_bytes(buf);
                        security_types.push((security_type & 0xff) as u8);
                    }

                    if !security_types.is_empty() {
                        metadata.push_str("Security Types:\n");
                        for ty in &security_types {
                            let name = security_type_name(*ty);
                            metadata.push_str(&format!("  {ty}: {name}\n"));
                        }
                    }

                    let chosen = security_types
                        .iter()
                        .copied()
                        .find(|ty| *ty == 1)
                        .or_else(|| security_types.first().copied())
                        .unwrap_or(1);

                    if (major, minor) >= (3, 7) {
                        timeout(cfg.read_timeout, stream.write_all(&[chosen])).await??;
                    }

                    let mut result = [0u8; 4];
                    read_exact_timeout(stream, &mut result, cfg.read_timeout).await?;
                    let status = u32::from_be_bytes(result);
                    if status != 0 {
                        // server may send an error message length + message
                        if let Ok(len_buf) = read_u32(stream, cfg.read_timeout).await {
                            if len_buf > 0 {
                                let mut msg = vec![0u8; len_buf as usize];
                                read_exact_timeout(stream, &mut msg, cfg.read_timeout).await?;
                                metadata.push_str("Security Failure: ");
                                metadata.push_str(&String::from_utf8_lossy(&msg));
                                metadata.push('\n');
                            }
                        }
                    }

                    timeout(cfg.read_timeout, stream.write_all(&[1u8])).await??;

                    let mut header = [0u8; 24];
                    read_exact_timeout(stream, &mut header, cfg.read_timeout).await?;

                    let width = u16::from_be_bytes(header[0..2].try_into().unwrap());
                    let height = u16::from_be_bytes(header[2..4].try_into().unwrap());
                    metadata.push_str(&format!("Geometry: {width}x{height}\n"));

                    let name_len = u32::from_be_bytes(header[20..24].try_into().unwrap()) as usize;
                    if name_len > 0 {
                        let mut name_bytes = vec![0u8; name_len];
                        read_exact_timeout(stream, &mut name_bytes, cfg.read_timeout).await?;
                        let server_name = String::from_utf8_lossy(&name_bytes);
                        metadata.push_str(&format!("Server Name: {server_name}\n"));
                    }
                }
            }
        }

        if !metadata.is_empty() {
            session.append_metadata(metadata);
        }

        Ok(session.finish())
    }
}

async fn read_exact_timeout(
    stream: &mut TcpStream,
    buf: &mut [u8],
    dur: std::time::Duration,
) -> anyhow::Result<()> {
    timeout(dur, stream.read_exact(buf)).await??;
    Ok(())
}

async fn read_u32(stream: &mut TcpStream, dur: std::time::Duration) -> anyhow::Result<u32> {
    let mut buf = [0u8; 4];
    read_exact_timeout(stream, &mut buf, dur).await?;
    Ok(u32::from_be_bytes(buf))
}

fn parse_version(version: &str) -> Option<(u16, u16)> {
    let parts: Vec<&str> = version.trim().split_whitespace().collect();
    let ver_part = parts.get(1)?;
    let nums: Vec<&str> = ver_part.split('.').collect();
    if nums.len() != 2 {
        return None;
    }
    let major = nums[0].parse::<u16>().ok()?;
    let minor = nums[1].parse::<u16>().ok()?;
    Some((major, minor))
}

fn security_type_name(ty: u8) -> &'static str {
    match ty {
        1 => "None",
        2 => "VNC Authentication",
        16 => "Tight",
        18 => "VeNCrypt",
        19 => "SASL",
        _ => "Unknown",
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
    async fn collects_vnc_metadata_during_handshake() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(b"RFB 003.008\n").await.unwrap();
            let mut buf = [0u8; 32];
            let n = socket.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"RFB 003.008\n");

            socket.write_all(&[1u8, 1u8]).await.unwrap();
            let mut selection = [0u8; 1];
            socket.read_exact(&mut selection).await.unwrap();
            assert_eq!(selection[0], 1u8);

            socket.write_all(&0u32.to_be_bytes()).await.unwrap();

            let mut client_init = [0u8; 1];
            socket.read_exact(&mut client_init).await.unwrap();
            assert_eq!(client_init[0], 1u8);

            let mut header = Vec::new();
            header.extend_from_slice(&800u16.to_be_bytes());
            header.extend_from_slice(&600u16.to_be_bytes());
            header.extend_from_slice(&[0u8; 16]);
            let name = b"Test Server";
            header.extend_from_slice(&(name.len() as u32).to_be_bytes());
            socket.write_all(&header).await.unwrap();
            socket.write_all(name).await.unwrap();
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
        assert!(printable.contains("Protocol Version: RFB 003.008"));
        assert!(printable.contains("Security Types:"));
        assert!(printable.contains("1: None"));
        assert!(printable.contains("Geometry: 800x600"));
        assert!(printable.contains("Server Name: Test Server"));
    }
}
