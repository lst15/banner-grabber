use crate::model::ScanOutcome;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::OnceLock;

use super::common::decode_banner_raw_bytes;

pub(super) fn rpcbind_data(outcome: &ScanOutcome) -> Value {
    let raw_bytes = decode_banner_raw_bytes(&outcome.banner.raw_hex).unwrap_or_default();
    let programs = parse_rpcbind_dump(&raw_bytes);
    serde_json::json!({
        "programs": programs,
        "tcp_port": outcome.target.port,
    })
}

#[derive(Debug, Clone)]
struct RpcProgramEntry {
    program: u32,
    protocol: String,
    port: Option<u16>,
    versions: Vec<u32>,
}

fn parse_rpcbind_dump(bytes: &[u8]) -> Vec<Value> {
    let body = match rpc_reply_body(bytes) {
        Some(body) => body,
        None => return Vec::new(),
    };

    let entries = parse_dump_entries(body);
    let mut grouped: BTreeMap<(u32, String, Option<u16>), BTreeSet<u32>> = BTreeMap::new();
    for entry in entries {
        grouped
            .entry((entry.program, entry.protocol.clone(), entry.port))
            .or_default()
            .extend(entry.versions);
    }

    let mut results = Vec::new();
    for ((program, protocol, port), versions) in grouped {
        let service = rpc_program_name(program).unwrap_or_default();
        let versions = versions.into_iter().collect::<Vec<_>>();
        results.push(serde_json::json!({
            "program": program,
            "versions": versions,
            "port": port,
            "protocol": protocol,
            "service": service,
        }));
    }

    results
}

fn parse_dump_entries(bytes: &[u8]) -> Vec<RpcProgramEntry> {
    let mut entries = Vec::new();
    let mut pos = 0;

    loop {
        let vfollows = match read_u32(bytes, &mut pos) {
            Some(val) => val,
            None => break,
        };
        if vfollows == 0 {
            break;
        }
        let program = match read_u32(bytes, &mut pos) {
            Some(val) => val,
            None => break,
        };
        let version = match read_u32(bytes, &mut pos) {
            Some(val) => val,
            None => break,
        };
        let field = match read_u32(bytes, &mut pos) {
            Some(val) => val,
            None => break,
        };

        if field == 6 || field == 17 {
            let protocol = match field {
                6 => "tcp".to_string(),
                17 => "udp".to_string(),
                _ => format!("proto-{field}"),
            };
            let port = read_u32(bytes, &mut pos).map(|p| p as u16);
            entries.push(RpcProgramEntry {
                program,
                protocol,
                port,
                versions: vec![version],
            });
            continue;
        }

        let netid_len = field as usize;
        let (netid, next_pos) = match read_opaque(bytes, pos, netid_len) {
            Some(val) => val,
            None => break,
        };
        pos = next_pos;
        let addr_len = match read_u32(bytes, &mut pos) {
            Some(val) => val as usize,
            None => break,
        };
        let (addr, next_pos) = match read_opaque(bytes, pos, addr_len) {
            Some(val) => val,
            None => break,
        };
        pos = next_pos;
        let owner_len = match read_u32(bytes, &mut pos) {
            Some(val) => val as usize,
            None => break,
        };
        let (_, next_pos) = match read_opaque(bytes, pos, owner_len) {
            Some(val) => val,
            None => break,
        };
        pos = next_pos;

        let protocol = String::from_utf8_lossy(&netid).to_string();
        let addr = String::from_utf8_lossy(&addr).to_string();
        let port = parse_universal_addr_port(&addr);
        entries.push(RpcProgramEntry {
            program,
            protocol,
            port,
            versions: vec![version],
        });
    }

    entries
}

fn rpc_reply_body(bytes: &[u8]) -> Option<&[u8]> {
    let mut pos = 0;
    read_u32(bytes, &mut pos)?;
    let msg_type = read_u32(bytes, &mut pos)?;
    if msg_type != 1 {
        return None;
    }
    let reply_state = read_u32(bytes, &mut pos)?;
    if reply_state != 0 {
        return None;
    }
    read_u32(bytes, &mut pos)?;
    let verf_len = read_u32(bytes, &mut pos)? as usize;
    pos = skip_opaque(bytes, pos, verf_len)?;
    let accept_state = read_u32(bytes, &mut pos)?;
    if accept_state != 0 {
        return None;
    }
    Some(&bytes[pos..])
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

fn read_opaque(bytes: &[u8], pos: usize, len: usize) -> Option<(Vec<u8>, usize)> {
    let end = pos.checked_add(len)?;
    if end > bytes.len() {
        return None;
    }
    let pad = (4 - (len % 4)) % 4;
    let next = end.checked_add(pad)?;
    if next > bytes.len() {
        return None;
    }
    Some((bytes[pos..end].to_vec(), next))
}

fn skip_opaque(bytes: &[u8], pos: usize, len: usize) -> Option<usize> {
    let pad = (4 - (len % 4)) % 4;
    let end = pos.checked_add(len)?.checked_add(pad)?;
    if end > bytes.len() {
        return None;
    }
    Some(end)
}

fn parse_universal_addr_port(addr: &str) -> Option<u16> {
    let mut parts = addr.split('.').collect::<Vec<_>>();
    if parts.len() < 2 {
        return None;
    }
    let low = parts.pop()?.parse::<u16>().ok()?;
    let high = parts.pop()?.parse::<u16>().ok()?;
    if high > 255 || low > 255 {
        return None;
    }
    Some(high * 256 + low)
}

fn rpc_program_name(program: u32) -> Option<String> {
    static RPC_PROGRAMS: OnceLock<HashMap<u32, String>> = OnceLock::new();
    let programs = RPC_PROGRAMS.get_or_init(load_rpc_programs);
    programs.get(&program).cloned()
}

fn load_rpc_programs() -> HashMap<u32, String> {
    let mut programs = HashMap::new();
    programs.insert(100000, "rpcbind".to_string());

    if let Ok(contents) = std::fs::read_to_string("/etc/rpc") {
        for line in contents.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let mut parts = line.split_whitespace();
            let name = match parts.next() {
                Some(val) => val,
                None => continue,
            };
            let number = match parts.next().and_then(|val| val.parse::<u32>().ok()) {
                Some(val) => val,
                None => continue,
            };
            programs.entry(number).or_insert_with(|| name.to_string());
        }
    }

    programs
}
