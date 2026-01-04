use crate::model::{Config, Target};
use anyhow::{anyhow, Context};
use async_trait::async_trait;
use chrono::{DateTime, SecondsFormat, TimeZone, Utc};
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::OnceLock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_openssl::SslStream;

use crate::clients::session::ClientSession;
use crate::clients::Client;

pub(crate) struct RdpClient;

#[async_trait]
impl Client for RdpClient {
    fn name(&self) -> &'static str {
        "ms-wbt-server"
    }

    fn matches(&self, target: &Target) -> bool {
        target.resolved.port() == 3389
    }

    async fn execute(
        &self,
        stream: &mut TcpStream,
        cfg: &Config,
    ) -> anyhow::Result<crate::engine::reader::ReadResult> {
        let mut session = ClientSession::new(cfg);
        let peer = stream.peer_addr().context("missing peer address for RDP probe")?;

        let protocol_results = enum_protocols(peer, cfg.read_timeout).await?;
        session.append_metadata(protocol_results);

        let cipher_results = enum_ciphers(peer, cfg.read_timeout).await?;
        session.append_metadata(cipher_results);

        let ntlm_results = ntlm_info(peer, cfg).await?;
        session.append_metadata(ntlm_results);

        Ok(session.finish())
    }
}

const PROTO_RDP: u32 = 0;
const PROTO_SSL: u32 = 1;
const PROTO_HYBRID: u32 = 2;
const PROTO_RDSTLS: u32 = 4;
const PROTO_HYBRID_EX: u32 = 8;

const CIPHER_40: u32 = 1;
const CIPHER_56: u32 = 8;
const CIPHER_128: u32 = 2;
const CIPHER_FIPS: u32 = 16;

fn rdp_neg_req(proto: u32) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&[0x03, 0x00, 0x00, 0x00]);

    let mut x224 = Vec::new();
    x224.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00]);
    x224.extend_from_slice(b"Cookie: mstshash=nmap\r\n");
    x224.extend_from_slice(&[0x01, 0x00, 0x08, 0x00]);
    x224.extend_from_slice(&proto.to_le_bytes());

    let tpdu_len = (x224.len() + 1) as u8;
    let mut tpdu = Vec::new();
    tpdu.push(tpdu_len);
    tpdu.push(0xE0);
    tpdu.extend_from_slice(&x224);

    let total_len = (tpdu.len() + 4) as u16;
    payload[2..4].copy_from_slice(&total_len.to_be_bytes());
    payload.extend_from_slice(&tpdu);
    payload
}

fn mcs_connect_initial(cipher: u32, server_proto: u32) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&[
        0x7f, 0x65, 0x82, 0x01, 0x94, 0x04, 0x01, 0x01, 0x04, 0x01, 0x01, 0x01, 0x01, 0xff,
        0x30, 0x19, 0x02, 0x01, 0x22, 0x02, 0x01, 0x02, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01,
        0x02, 0x01, 0x00, 0x02, 0x01, 0x01, 0x02, 0x02, 0xff, 0xff, 0x02, 0x01, 0x02, 0x30,
        0x19, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x02,
        0x01, 0x00, 0x02, 0x01, 0x01, 0x02, 0x02, 0x04, 0x20, 0x02, 0x01, 0x02, 0x30, 0x1c,
        0x02, 0x02, 0xff, 0xff, 0x02, 0x02, 0xfc, 0x17, 0x02, 0x02, 0xff, 0xff, 0x02, 0x01,
        0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01, 0x02, 0x02, 0xff, 0xff, 0x02, 0x01, 0x02,
        0x04, 0x82, 0x01, 0x33, 0x00, 0x05, 0x00, 0x14, 0x7c, 0x00, 0x01, 0x81, 0x2a, 0x00,
        0x08, 0x00, 0x10, 0x00, 0x01, 0xc0, 0x00, 0x44, 0x75, 0x63, 0x61, 0x81, 0x1c, 0x01,
        0xc0, 0xd8, 0x00, 0x04, 0x00, 0x08, 0x00, 0x00, 0x05, 0x20, 0x03, 0x01, 0xca, 0x03,
        0xaa, 0x09, 0x04, 0x00, 0x00, 0x28, 0x0a, 0x00, 0x00, 0x45, 0x00, 0x4d, 0x00, 0x50,
        0x00, 0x2d, 0x00, 0x4c, 0x00, 0x41, 0x00, 0x50, 0x00, 0x2d, 0x00, 0x30, 0x00, 0x30,
        0x00, 0x31, 0x00, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0xca, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x00, 0x07, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);

    data.extend_from_slice(&[0x01, 0x00]);
    data.extend_from_slice(&server_proto.to_le_bytes());
    data.extend_from_slice(&[
        0x04, 0xc0, 0x0c, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xc0,
        0x0c, 0x00,
    ]);
    data.extend_from_slice(&cipher.to_le_bytes());
    data.extend_from_slice(&[
        0x00, 0x00, 0x00, 0x00, 0x03, 0xc0, 0x2c, 0x00, 0x03, 0x00, 0x00, 0x00, 0x72, 0x64,
        0x70, 0x64, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x80, 0x63, 0x6c, 0x69, 0x70,
        0x72, 0x64, 0x72, 0x00, 0x00, 0x00, 0xa0, 0xc0, 0x72, 0x64, 0x70, 0x73, 0x6e, 0x64,
        0x00, 0x00, 0x00, 0x00, 0x00, 0xc0,
    ]);

    let mut tpdu = Vec::new();
    tpdu.push((data.len() + 1) as u8);
    tpdu.push(0xF0);
    tpdu.push(0x80);
    tpdu.extend_from_slice(&data);

    let mut packet = Vec::new();
    packet.extend_from_slice(&[0x03, 0x00]);
    let total_len = (tpdu.len() + 4) as u16;
    packet.extend_from_slice(&total_len.to_be_bytes());
    packet.extend_from_slice(&tpdu);
    packet
}

async fn connect_peer(peer: SocketAddr) -> anyhow::Result<TcpStream> {
    TcpStream::connect(peer)
        .await
        .with_context(|| format!("failed to connect to {peer}"))
}

async fn read_once(
    stream: &mut TcpStream,
    timeout: std::time::Duration,
    max_len: usize,
) -> anyhow::Result<Vec<u8>> {
    let mut buf = vec![0u8; max_len];
    let n = tokio::time::timeout(timeout, stream.read(&mut buf))
        .await
        .context("read timeout")??;
    buf.truncate(n);
    Ok(buf)
}

async fn enum_protocols(peer: SocketAddr, timeout: std::time::Duration) -> anyhow::Result<Vec<u8>> {
    let protocols = [
        ("Native RDP", PROTO_RDP),
        ("SSL", PROTO_SSL),
        ("CredSSP (NLA)", PROTO_HYBRID),
        ("RDSTLS", PROTO_RDSTLS),
        ("CredSSP with Early User Auth", PROTO_HYBRID_EX),
    ];

    let mut output = Vec::new();
    output.extend_from_slice(b"SECURITY_LAYER\n");
    for (label, proto) in protocols {
        let mut stream = connect_peer(peer).await?;
        stream.write_all(&rdp_neg_req(proto)).await?;
        let buf = read_once(&mut stream, timeout, 2048).await?;
        let result = parse_rdp_neg_response(&buf);
        let line = match result {
            NegResult::Success => format!("{label}: SUCCESS\n"),
            NegResult::Failed(Some(code)) => format!("{label}: FAILED ({code})\n"),
            NegResult::Failed(None) => format!("{label}: FAILED\n"),
            NegResult::Unknown => format!("{label}: Unknown\n"),
        };
        output.extend_from_slice(line.as_bytes());
    }
    output.extend_from_slice(b"END_SECURITY_LAYER\n");
    Ok(output)
}

async fn enum_ciphers(peer: SocketAddr, timeout: std::time::Duration) -> anyhow::Result<Vec<u8>> {
    let ciphers = [
        ("40-bit RC4", CIPHER_40),
        ("56-bit RC4", CIPHER_56),
        ("128-bit RC4", CIPHER_128),
        ("FIPS 140-1", CIPHER_FIPS),
    ];

    let mut output = Vec::new();
    output.extend_from_slice(b"ENCRYPTION\n");

    let mut level = None;
    let mut proto_version = None;

    for (label, cipher) in ciphers {
        let mut stream = connect_peer(peer).await?;
        stream.write_all(&rdp_neg_req(PROTO_RDP)).await?;
        let _ = read_once(&mut stream, timeout, 2048).await?;
        stream.write_all(&mcs_connect_initial(cipher, PROTO_RDP)).await?;
        let resp = read_once(&mut stream, timeout, 8192).await?;

        let parsed = parse_mcs_connect_response(&resp);
        if let Some(parsed_cipher) = parsed.cipher {
            if parsed_cipher == cipher as u8 {
                output.extend_from_slice(format!("{label}: SUCCESS\n").as_bytes());
            } else {
                output.extend_from_slice(format!("{label}: FAILED\n").as_bytes());
            }
        } else {
            output.extend_from_slice(format!("{label}: FAILED\n").as_bytes());
        }
        if level.is_none() {
            level = parsed.enc_level;
        }
        if proto_version.is_none() {
            proto_version = parsed.proto_version;
        }
    }

    let level_label = level.map(encode_encryption_level).unwrap_or("Unknown");
    let header = format!("ENCRYPTION\nRDP Encryption level: {level_label}\n");
    let mut combined = header.into_bytes();
    combined.extend_from_slice(&output[b"ENCRYPTION\n".len()..]);
    if let Some(proto) = proto_version {
        combined.extend_from_slice(format!("RDP Protocol Version: {proto}\n").as_bytes());
    }
    combined.extend_from_slice(b"END_ENCRYPTION\n");
    Ok(combined)
}

#[derive(Debug)]
enum NegResult {
    Success,
    Failed(Option<&'static str>),
    Unknown,
}

fn parse_rdp_neg_response(bytes: &[u8]) -> NegResult {
    if bytes.len() < 8 {
        return NegResult::Unknown;
    }
    for idx in 0..=bytes.len().saturating_sub(8) {
        let neg_type = bytes[idx];
        if neg_type != 2 && neg_type != 3 {
            continue;
        }
        if bytes[idx + 2] != 0x08 || bytes[idx + 3] != 0x00 {
            continue;
        }
        if neg_type == 2 {
            return NegResult::Success;
        }
        let failure = u32::from_le_bytes([
            bytes[idx + 4],
            bytes[idx + 5],
            bytes[idx + 6],
            bytes[idx + 7],
        ]);
        let label = match failure {
            1 => "SSL_REQUIRED_BY_SERVER",
            2 => "SSL_NOT_ALLOWED_BY_SERVER",
            3 => "SSL_CERT_NOT_ON_SERVER",
            4 => "INCONSISTENT_FLAGS",
            5 => "HYBRID_REQUIRED_BY_SERVER",
            6 => "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER",
            _ => "Unknown",
        };
        return NegResult::Failed(Some(label));
    }
    NegResult::Unknown
}

struct McsResponse {
    cipher: Option<u8>,
    enc_level: Option<u8>,
    proto_version: Option<String>,
}

fn parse_mcs_connect_response(bytes: &[u8]) -> McsResponse {
    let mut res = McsResponse {
        cipher: None,
        enc_level: None,
        proto_version: None,
    };
    if bytes.len() < 7 {
        return res;
    }
    if bytes.get(0) != Some(&0x03) {
        return res;
    }
    let total_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    let total_len = total_len.min(bytes.len());
    if bytes.get(5) != Some(&0xF0) {
        return res;
    }
    let payload = &bytes[7..total_len];
    let mut idx = 0usize;
    while idx + 4 <= payload.len() {
        let block_type = u16::from_le_bytes([payload[idx], payload[idx + 1]]);
        let block_len = u16::from_le_bytes([payload[idx + 2], payload[idx + 3]]) as usize;
        if block_len < 4 || idx + block_len > payload.len() {
            idx += 1;
            continue;
        }
        if block_type == 0x0c01 && block_len >= 8 {
            let version = u32::from_le_bytes([
                payload[idx + 4],
                payload[idx + 5],
                payload[idx + 6],
                payload[idx + 7],
            ]);
            res.proto_version = Some(map_proto_version(version));
        } else if block_type == 0x0c02 && block_len >= 9 {
            res.cipher = Some(payload[idx + 4]);
            res.enc_level = Some(payload[idx + 8]);
        }
        idx += block_len;
    }
    res
}

fn map_proto_version(version: u32) -> String {
    match version {
        0x00080001 => "RDP 4.0 server".to_string(),
        0x00080004 => "RDP 5.x, 6.x, 7.x, or 8.x server".to_string(),
        0x00080005 => "RDP 10.0 server".to_string(),
        0x00080006 => "RDP 10.1 server".to_string(),
        0x00080007 => "RDP 10.2 server".to_string(),
        0x00080008 => "RDP 10.3 server".to_string(),
        0x00080009 => "RDP 10.4 server".to_string(),
        0x0008000A => "RDP 10.5 server".to_string(),
        0x0008000B => "RDP 10.6 server".to_string(),
        0x0008000C => "RDP 10.7 server".to_string(),
        _ => "Unknown".to_string(),
    }
}

fn encode_encryption_level(level: u8) -> &'static str {
    match level {
        0 => "None",
        1 => "Low",
        2 => "Client Compatible",
        3 => "High",
        4 => "FIPS Compliant",
        _ => "Unknown",
    }
}

async fn ntlm_info(peer: SocketAddr, cfg: &Config) -> anyhow::Result<Vec<u8>> {
    let mut stream = connect_peer(peer).await?;
    stream
        .write_all(&rdp_neg_req(PROTO_SSL | PROTO_HYBRID | PROTO_HYBRID_EX))
        .await?;
    let buf = read_once(&mut stream, cfg.read_timeout, 2048).await?;
    let result = parse_rdp_neg_response(&buf);
    if !matches!(result, NegResult::Success) {
        return Ok(Vec::new());
    }

    let connector = rdp_tls_connector()?;
    let ssl = connector
        .configure()
        .context("failed to configure TLS connector")?
        .into_ssl(&peer.ip().to_string())
        .context("failed to configure TLS SNI")?;
    let mut tls_stream =
        SslStream::new(ssl, stream).context("failed to initialize TLS stream")?;
    Pin::new(&mut tls_stream)
        .connect()
        .await
        .context("TLS handshake failed for RDP NTLM probe")?;

    tls_stream
        .write_all(ntlm_negotiate_blob()?)
        .await
        .context("failed to write NTLM negotiate blob")?;

    let mut response = Vec::new();
    for _ in 0..3 {
        let mut buf = vec![0u8; 8192];
        let n = tokio::time::timeout(cfg.read_timeout, tls_stream.read(&mut buf))
            .await
            .context("TLS read timeout")??;
        if n == 0 {
            break;
        }
        response.extend_from_slice(&buf[..n]);
        if response.windows(8).any(|win| win == b"NTLMSSP\0") {
            break;
        }
    }

    let info = match parse_ntlm_challenge(&response) {
        Ok(info) => info,
        Err(_) => return Ok(Vec::new()),
    };
    if info.is_empty() {
        return Ok(Vec::new());
    }
    let mut output = Vec::new();
    output.extend_from_slice(b"NTLM_INFO\n");
    for (key, value) in info {
        output.extend_from_slice(format!("{key}: {value}\n").as_bytes());
    }
    output.extend_from_slice(b"END_NTLM_INFO\n");
    Ok(output)
}

fn ntlm_negotiate_blob() -> anyhow::Result<&'static [u8]> {
    static BLOB: OnceLock<anyhow::Result<Vec<u8>>> = OnceLock::new();
    let bytes = BLOB.get_or_init(|| {
        crate::util::hex::from_hex(
            "30 37 A0 03 02 01 60 A1 30 30 2E 30 2C A0 2A 04 28 \
             4e 54 4c 4d 53 53 50 00 01 00 00 00 B7 82 08 E2 \
             00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
             0A 00 63 45 00 00 00 0F",
        )
        .map_err(|err| anyhow!(err))
    });
    bytes.as_ref().map(Vec::as_slice).map_err(|err| anyhow!(err))
}

fn parse_ntlm_challenge(bytes: &[u8]) -> anyhow::Result<Vec<(String, String)>> {
    let sig = b"NTLMSSP\0";
    let start = bytes
        .windows(sig.len())
        .position(|win| win == sig)
        .ok_or_else(|| anyhow!("NTLMSSP signature not found"))?;
    if bytes.len() < start + 48 {
        return Err(anyhow!("NTLMSSP message too short"));
    }
    let msg_type = u32::from_le_bytes([
        bytes[start + 8],
        bytes[start + 9],
        bytes[start + 10],
        bytes[start + 11],
    ]);
    if msg_type != 2 {
        return Err(anyhow!("unexpected NTLM message type"));
    }
    let target_name_len = u16::from_le_bytes([bytes[start + 12], bytes[start + 13]]) as usize;
    let target_name_offset =
        u32::from_le_bytes([bytes[start + 16], bytes[start + 17], bytes[start + 18], bytes[start + 19]])
            as usize;
    let target_info_len = u16::from_le_bytes([bytes[start + 40], bytes[start + 41]]) as usize;
    let target_info_offset =
        u32::from_le_bytes([bytes[start + 44], bytes[start + 45], bytes[start + 46], bytes[start + 47]])
            as usize;

    let mut output = Vec::new();
    let target_name_base = start + target_name_offset;
    if target_name_base + target_name_len <= bytes.len() && target_name_len > 0 {
        if let Some(name) = decode_utf16le(&bytes[target_name_base..target_name_base + target_name_len]) {
            output.push(("Target_Name".to_string(), name));
        }
    }

    if start + 56 <= bytes.len() {
        let major = bytes[start + 48];
        let minor = bytes[start + 49];
        let build = u16::from_le_bytes([bytes[start + 50], bytes[start + 51]]);
        output.push((
            "Product_Version".to_string(),
            format!("{major}.{minor}.{build}"),
        ));
    }

    let target_info_base = start + target_info_offset;
    if target_info_base + target_info_len <= bytes.len() && target_info_len >= 4 {
        let av_pairs = &bytes[target_info_base..target_info_base + target_info_len];
        let mut idx = 0usize;
        while idx + 4 <= av_pairs.len() {
            let av_id = u16::from_le_bytes([av_pairs[idx], av_pairs[idx + 1]]);
            let av_len = u16::from_le_bytes([av_pairs[idx + 2], av_pairs[idx + 3]]) as usize;
            idx += 4;
            if av_id == 0 {
                break;
            }
            if idx + av_len > av_pairs.len() {
                break;
            }
            let value = &av_pairs[idx..idx + av_len];
            match av_id {
                0x01 => push_decoded(&mut output, "NetBIOS_Computer_Name", value),
                0x02 => push_decoded(&mut output, "NetBIOS_Domain_Name", value),
                0x03 => push_decoded(&mut output, "DNS_Computer_Name", value),
                0x04 => push_decoded(&mut output, "DNS_Domain_Name", value),
                0x05 => push_decoded(&mut output, "DNS_Tree_Name", value),
                0x07 => {
                    if value.len() == 8 {
                        let filetime = u64::from_le_bytes([
                            value[0], value[1], value[2], value[3], value[4], value[5], value[6],
                            value[7],
                        ]);
                        if let Some(ts) = filetime_to_rfc3339(filetime) {
                            output.push(("System_Time".to_string(), ts));
                        }
                    }
                }
                _ => {}
            }
            idx += av_len;
        }
    }

    Ok(output)
}

fn push_decoded(output: &mut Vec<(String, String)>, key: &str, value: &[u8]) {
    if let Some(decoded) = decode_utf16le(value) {
        if !decoded.is_empty() {
            output.push((key.to_string(), decoded));
        }
    }
}

fn decode_utf16le(bytes: &[u8]) -> Option<String> {
    if bytes.len() % 2 != 0 {
        return None;
    }
    let mut buf = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks(2) {
        buf.push(u16::from_le_bytes([chunk[0], chunk[1]]));
    }
    String::from_utf16(&buf).ok().map(|s| s.trim_end_matches('\u{0}').to_string())
}

fn filetime_to_rfc3339(filetime: u64) -> Option<String> {
    if filetime == 0 {
        return None;
    }
    let unix = (filetime / 10_000_000) as i64 - 11_644_473_600;
    let dt: DateTime<Utc> = Utc.timestamp_opt(unix, 0).single()?;
    Some(dt.to_rfc3339_opts(SecondsFormat::Secs, true))
}

fn rdp_tls_connector() -> anyhow::Result<&'static SslConnector> {
    static CONNECTOR: OnceLock<anyhow::Result<SslConnector>> = OnceLock::new();
    CONNECTOR
        .get_or_init(|| {
            let mut builder = SslConnector::builder(SslMethod::tls()).map_err(|e| anyhow!(e))?;
            builder.set_verify(SslVerifyMode::NONE);
            Ok(builder.build())
        })
        .as_ref()
        .map_err(|err| anyhow!("failed to create TLS connector: {err}"))
}
