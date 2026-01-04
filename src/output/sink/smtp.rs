use crate::model::ScanOutcome;
use base64::Engine;
use serde_json::Value;

use super::common::{decode_banner_raw, raw_banner_for_data};

pub(super) fn smtp_data(outcome: &ScanOutcome) -> Value {
    let banner_raw = decode_banner_raw(&outcome.banner.raw_hex)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| raw_banner_for_data(outcome));
    let lines = banner_raw
        .lines()
        .map(|line| line.trim_end_matches('\r'))
        .collect::<Vec<_>>();

    let blocks = parse_response_blocks(&lines);
    let ehlo_block = first_block_after_code(&blocks, None, 220)
        .and_then(|idx| first_block_after_code(&blocks, Some(idx), 250));
    let help_block = ehlo_block.and_then(|idx| first_block_after_code(&blocks, Some(idx), 214));
    let rcpt_block = help_block
        .and_then(|idx| blocks.get(idx + 2))
        .map(|block| block.clone());
    let expn_block = help_block
        .and_then(|idx| blocks.get(idx + 3))
        .map(|block| block.clone());
    let auth_prompt_block = help_block
        .and_then(|idx| blocks.get(idx + 4))
        .map(|block| block.clone());
    let auth_blob_block = help_block
        .and_then(|idx| blocks.get(idx + 5))
        .map(|block| block.clone());

    let ehlo_line = ehlo_block
        .and_then(|idx| blocks.get(idx))
        .map(|block| normalize_block_lines(block, 250))
        .unwrap_or_default();
    let help_line = help_block
        .and_then(|idx| blocks.get(idx))
        .map(|block| normalize_block_lines(block, 214))
        .unwrap_or_default();

    let rcpt_result = rcpt_block
        .as_ref()
        .and_then(|block| rcpt_result(block, "root"));
    let expn_result = expn_block
        .as_ref()
        .and_then(|block| expn_result(block, "root"));

    let ntlm_info = auth_blob_block
        .as_ref()
        .and_then(|block| extract_ntlm_info(block));
    let auth_prompt = auth_prompt_block
        .as_ref()
        .map(|block| block.lines.join(" "))
        .unwrap_or_default();

    serde_json::json!({
        "banner": banner_raw,
        "commands": {
            "ehlo": ehlo_line,
            "help": help_line,
        },
        "enum_users": {
            "rcpt": rcpt_result,
            "expn": expn_result,
        },
        "ntlm": {
            "prompt": auth_prompt,
            "info": ntlm_info,
        },
    })
}

#[derive(Clone)]
struct ResponseBlock {
    code: u16,
    lines: Vec<String>,
}

fn parse_response_blocks(lines: &[&str]) -> Vec<ResponseBlock> {
    let mut blocks = Vec::new();
    let mut current: Option<ResponseBlock> = None;

    for line in lines {
        if let Some((code, has_more)) = parse_response_code(line) {
            if let Some(block) = current.take() {
                blocks.push(block);
            }
            let new_block = ResponseBlock {
                code,
                lines: vec![line.to_string()],
            };
            if !has_more {
                blocks.push(new_block);
                current = None;
            } else {
                current = Some(new_block);
            }
        } else if let Some(block) = current.as_mut() {
            block.lines.push(line.to_string());
        }
    }

    if let Some(block) = current {
        blocks.push(block);
    }

    blocks
}

fn parse_response_code(line: &str) -> Option<(u16, bool)> {
    if line.len() < 3 {
        return None;
    }
    let code = line.get(0..3)?.parse::<u16>().ok()?;
    let has_more = line.as_bytes().get(3).map(|b| *b == b'-').unwrap_or(false);
    Some((code, has_more))
}

fn first_block_after_code(
    blocks: &[ResponseBlock],
    start: Option<usize>,
    code: u16,
) -> Option<usize> {
    let idx = start.map(|idx| idx + 1).unwrap_or(0);
    blocks
        .iter()
        .enumerate()
        .skip(idx)
        .find(|(_, block)| block.code == code)
        .map(|(idx, _)| idx)
}

fn normalize_block_lines(block: &ResponseBlock, code: u16) -> String {
    let prefix = format!("{code}");
    block
        .lines
        .iter()
        .map(|line| {
            line.strip_prefix(&prefix)
                .map(|rest| rest.trim_start_matches(['-', ' ']))
                .unwrap_or(line.as_str())
                .trim()
                .to_string()
        })
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(", ")
}

fn rcpt_result(block: &ResponseBlock, username: &str) -> Option<String> {
    match block.code {
        250 | 251 => Some(format!("RCPT, {username}")),
        _ => None,
    }
}

fn expn_result(block: &ResponseBlock, username: &str) -> Option<String> {
    match block.code {
        250 | 251 => Some(format!("EXPN, {username}")),
        _ => Some("Method EXPN returned a unhandled status code.".to_string()),
    }
}

fn extract_ntlm_info(block: &ResponseBlock) -> Option<Value> {
    let base64_line = block
        .lines
        .iter()
        .find_map(|line| line.strip_prefix("334 ").map(str::to_string))?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(base64_line.trim())
        .ok()?;
    parse_ntlm_type2(&bytes)
}

fn parse_ntlm_type2(bytes: &[u8]) -> Option<Value> {
    if bytes.len() < 48 || &bytes[..8] != b"NTLMSSP\0" {
        return None;
    }
    let message_type = u32::from_le_bytes(bytes.get(8..12)?.try_into().ok()?);
    if message_type != 2 {
        return None;
    }
    let target_name = parse_security_buffer(bytes, 12)
        .and_then(|slice| decode_utf16le(slice).filter(|s| !s.is_empty()));
    let target_info = parse_security_buffer(bytes, 40);
    let av_pairs = target_info
        .and_then(|slice| parse_av_pairs(slice))
        .unwrap_or_default();
    let version = parse_version(bytes);

    let mut map = serde_json::Map::new();
    if let Some(target) = target_name {
        map.insert("Target_Name".to_string(), Value::String(target));
    }
    insert_av_pair(&mut map, &av_pairs, 2, "NetBIOS_Domain_Name");
    insert_av_pair(&mut map, &av_pairs, 1, "NetBIOS_Computer_Name");
    insert_av_pair(&mut map, &av_pairs, 4, "DNS_Domain_Name");
    insert_av_pair(&mut map, &av_pairs, 3, "DNS_Computer_Name");
    insert_av_pair(&mut map, &av_pairs, 5, "DNS_Tree_Name");
    if let Some(version) = version {
        map.insert("Product_Version".to_string(), Value::String(version));
    }

    Some(Value::Object(map))
}

fn parse_security_buffer(bytes: &[u8], offset: usize) -> Option<&[u8]> {
    if bytes.len() < offset + 8 {
        return None;
    }
    let len = u16::from_le_bytes(bytes[offset..offset + 2].try_into().ok()?) as usize;
    let data_offset = u32::from_le_bytes(bytes[offset + 4..offset + 8].try_into().ok()?) as usize;
    if data_offset + len > bytes.len() {
        return None;
    }
    Some(&bytes[data_offset..data_offset + len])
}

fn parse_version(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 56 {
        return None;
    }
    let major = *bytes.get(48)?;
    let minor = *bytes.get(49)?;
    let build = u16::from_le_bytes(bytes.get(50..52)?.try_into().ok()?);
    Some(format!("{major}.{minor}.{build}"))
}

fn parse_av_pairs(bytes: &[u8]) -> Option<Vec<(u16, String)>> {
    let mut entries = Vec::new();
    let mut pos = 0;
    while pos + 4 <= bytes.len() {
        let av_id = u16::from_le_bytes(bytes[pos..pos + 2].try_into().ok()?);
        let av_len = u16::from_le_bytes(bytes[pos + 2..pos + 4].try_into().ok()?);
        pos += 4;
        if av_id == 0 {
            break;
        }
        if pos + av_len as usize > bytes.len() {
            break;
        }
        let value_bytes = &bytes[pos..pos + av_len as usize];
        let value = decode_utf16le(value_bytes).unwrap_or_default();
        entries.push((av_id, value));
        pos += av_len as usize;
    }
    Some(entries)
}

fn decode_utf16le(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 2 {
        return None;
    }
    let mut data = Vec::new();
    for chunk in bytes.chunks_exact(2) {
        data.push(u16::from_le_bytes([chunk[0], chunk[1]]));
    }
    Some(String::from_utf16_lossy(&data))
}

fn insert_av_pair(
    map: &mut serde_json::Map<String, Value>,
    pairs: &[(u16, String)],
    id: u16,
    key: &str,
) {
    if let Some((_, value)) = pairs.iter().find(|(pair_id, _)| *pair_id == id) {
        if !value.is_empty() {
            map.insert(key.to_string(), Value::String(value.clone()));
        }
    }
}
