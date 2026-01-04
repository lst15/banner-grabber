use crate::clients::Client;
use crate::engine::reader::ReadResult;
use crate::model::{Config, ReadStopReason, Target};
use async_trait::async_trait;
use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

pub(crate) struct RpcbindClient;

const RPCBIND_PROGRAM: u32 = 100000;
const RPC_VERSION: u32 = 2;
const RPC_CALL: u32 = 0;
const RPC_REPLY: u32 = 1;
const RPC_ACCEPTED: u32 = 0;
const RPC_SUCCESS: u32 = 0;
const RPC_DUMP_PROC: u32 = 4;

#[async_trait]
impl Client for RpcbindClient {
    fn name(&self) -> &'static str {
        "rpcbind"
    }

    fn matches(&self, target: &Target) -> bool {
        target.resolved.port() == 111
    }

    async fn execute(&self, stream: &mut TcpStream, cfg: &Config) -> anyhow::Result<ReadResult> {
        let versions = [4u32, 3u32, 2u32];
        for version in versions {
            let request = build_dump_request(version);
            timeout(cfg.connect_timeout, stream.write_all(&request)).await??;

            let response = match read_rpc_message(stream, cfg).await {
                Ok(res) => res,
                Err(ReadError::Timeout) => {
                    return Ok(ReadResult {
                        bytes: Vec::new(),
                        reason: ReadStopReason::Timeout,
                        truncated: false,
                        tls_info: None,
                    })
                }
                Err(ReadError::Io(err)) => return Err(err),
            };

            match rpc_reply_success(&response) {
                Some(true) => {
                    let truncated = response.len() > cfg.max_bytes;
                    let bytes = response.into_iter().take(cfg.max_bytes).collect();
                    return Ok(ReadResult {
                        bytes,
                        reason: ReadStopReason::ConnectionClosed,
                        truncated,
                        tls_info: None,
                    });
                }
                Some(false) => continue,
                None => anyhow::bail!("failed to parse rpcbind reply"),
            }
        }

        anyhow::bail!("rpcbind dump failed for all supported versions")
    }
}

fn build_dump_request(version: u32) -> Vec<u8> {
    let xid = rand::thread_rng().gen::<u32>();
    let mut payload = Vec::with_capacity(40);
    payload.extend_from_slice(&xid.to_be_bytes());
    payload.extend_from_slice(&RPC_CALL.to_be_bytes());
    payload.extend_from_slice(&RPC_VERSION.to_be_bytes());
    payload.extend_from_slice(&RPCBIND_PROGRAM.to_be_bytes());
    payload.extend_from_slice(&version.to_be_bytes());
    payload.extend_from_slice(&RPC_DUMP_PROC.to_be_bytes());
    payload.extend_from_slice(&0u32.to_be_bytes());
    payload.extend_from_slice(&0u32.to_be_bytes());
    payload.extend_from_slice(&0u32.to_be_bytes());
    payload.extend_from_slice(&0u32.to_be_bytes());

    let length = payload.len() as u32 | 0x8000_0000;
    let mut packet = Vec::with_capacity(payload.len() + 4);
    packet.extend_from_slice(&length.to_be_bytes());
    packet.extend_from_slice(&payload);
    packet
}

fn rpc_reply_success(bytes: &[u8]) -> Option<bool> {
    let mut pos = 0;
    let (_, msg_type) = read_u32_pair(bytes, &mut pos)?;
    if msg_type != RPC_REPLY {
        return Some(false);
    }
    let reply_state = read_u32(bytes, &mut pos)?;
    if reply_state != RPC_ACCEPTED {
        return Some(false);
    }
    let _verf_flavor = read_u32(bytes, &mut pos)?;
    let verf_len = read_u32(bytes, &mut pos)? as usize;
    pos = skip_opaque(bytes, pos, verf_len)?;
    let accept_state = read_u32(bytes, &mut pos)?;
    Some(accept_state == RPC_SUCCESS)
}

fn read_u32(bytes: &[u8], pos: &mut usize) -> Option<u32> {
    let end = pos.checked_add(4)?;
    if end > bytes.len() {
        return None;
    }
    let val = u32::from_be_bytes(bytes[*pos..end].try_into().ok()?);
    *pos = end;
    Some(val)
}

fn read_u32_pair(bytes: &[u8], pos: &mut usize) -> Option<(u32, u32)> {
    let first = read_u32(bytes, pos)?;
    let second = read_u32(bytes, pos)?;
    Some((first, second))
}

fn skip_opaque(bytes: &[u8], pos: usize, len: usize) -> Option<usize> {
    let pad = (4 - (len % 4)) % 4;
    let end = pos.checked_add(len)?.checked_add(pad)?;
    if end > bytes.len() {
        return None;
    }
    Some(end)
}

enum ReadError {
    Timeout,
    Io(anyhow::Error),
}

async fn read_rpc_message(stream: &mut TcpStream, cfg: &Config) -> Result<Vec<u8>, ReadError> {
    let mut message = Vec::new();
    loop {
        let mut marker = [0u8; 4];
        match timeout(cfg.read_timeout, stream.read_exact(&mut marker)).await {
            Ok(..) => {}
            Ok(Err(err)) => return Err(ReadError::Io(err.into())),
            Err(_) => return Err(ReadError::Timeout),
        }
        let marker_val = u32::from_be_bytes(marker);
        let last_fragment = (marker_val & 0x8000_0000) != 0;
        let length = (marker_val & 0x7fff_ffff) as usize;
        if length > 0 {
            let mut fragment = vec![0u8; length];
            match timeout(cfg.read_timeout, stream.read_exact(&mut fragment)).await {
                Ok(..) => {}
                Ok(Err(err)) => return Err(ReadError::Io(err.into())),
                Err(_) => return Err(ReadError::Timeout),
            }
            message.extend_from_slice(&fragment);
        }
        if last_fragment {
            break;
        }
    }
    Ok(message)
}
