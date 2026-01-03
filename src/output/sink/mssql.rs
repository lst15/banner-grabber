use crate::model::ScanOutcome;
use serde_json::Value;

use super::common::decode_banner_raw_bytes;

pub(super) fn mssql_data(outcome: &ScanOutcome) -> Value {
    let raw_bytes = decode_banner_raw_bytes(&outcome.banner.raw_hex).unwrap_or_default();
    let version_info = parse_mssql_prelogin_version(&raw_bytes);
    let version_json = match version_info {
        Some(info) => serde_json::json!({
            "name": info.name,
            "number": info.number,
            "product": info.product,
            "service_pack_level": info.service_pack_level,
            "post_sp_patches_applied": info.post_sp_patches_applied,
        }),
        None => serde_json::json!({
            "name": "",
            "number": "",
            "product": "",
            "service_pack_level": "",
            "post_sp_patches_applied": Value::Null,
        }),
    };

    serde_json::json!({
        "version": version_json,
        "tcp_port": outcome.target.port,
    })
}

struct MssqlVersionInfo {
    name: String,
    number: String,
    product: String,
    service_pack_level: String,
    post_sp_patches_applied: Option<bool>,
}

fn parse_mssql_prelogin_version(raw_bytes: &[u8]) -> Option<MssqlVersionInfo> {
    let payload = extract_tds_payload(raw_bytes);
    let parsed = payload
        .as_deref()
        .and_then(parse_mssql_prelogin_version_bytes)
        .or_else(|| parse_mssql_prelogin_version_any(raw_bytes))?;
    let (major, minor, build, sub_build) = parsed;
    let branded = mssql_branded_version(major, minor)?;
    let product = format!("Microsoft SQL Server {branded}");
    let (service_pack_level, post_sp_patches_applied) = mssql_service_pack_level(&branded, build);
    let number = format!("{}.{:02}.{}.{:02}", major, minor, build, sub_build);
    let name = mssql_version_name(&product, &service_pack_level, post_sp_patches_applied);

    Some(MssqlVersionInfo {
        name,
        number,
        product,
        service_pack_level,
        post_sp_patches_applied,
    })
}

fn extract_tds_payload(raw: &[u8]) -> Option<Vec<u8>> {
    let mut payload = Vec::new();
    let mut pos = 0;
    while pos + 8 <= raw.len() {
        let length = u16::from_be_bytes([raw[pos + 2], raw[pos + 3]]) as usize;
        if length < 8 || pos + length > raw.len() {
            break;
        }
        payload.extend_from_slice(&raw[pos + 8..pos + length]);
        pos += length;
    }
    if payload.is_empty() {
        None
    } else {
        Some(payload)
    }
}

fn parse_mssql_prelogin_version_bytes(payload: &[u8]) -> Option<(u8, u8, u16, u16)> {
    let mut pos = 0;
    while pos < payload.len() {
        let option_type = *payload.get(pos)?;
        pos += 1;
        if option_type == 0xff {
            break;
        }
        let offset = u16::from_be_bytes([*payload.get(pos)?, *payload.get(pos + 1)?]) as usize;
        pos += 2;
        let length = u16::from_be_bytes([*payload.get(pos)?, *payload.get(pos + 1)?]) as usize;
        pos += 2;
        let data_start = offset;
        let data_end = data_start + length;
        if data_end > payload.len() {
            return None;
        }
        if option_type == 0x00 && length >= 6 {
            let data = &payload[data_start..data_start + 6];
            let major = data[0];
            let minor = data[1];
            let build = u16::from_be_bytes([data[2], data[3]]);
            let sub_build = u16::from_be_bytes([data[4], data[5]]);
            return Some((major, minor, build, sub_build));
        }
    }
    None
}

fn parse_mssql_prelogin_version_any(bytes: &[u8]) -> Option<(u8, u8, u16, u16)> {
    if bytes.len() < 6 {
        return None;
    }
    for base in 0..bytes.len().saturating_sub(6) {
        if bytes.get(base)? != &0x00 {
            continue;
        }
        let offset = u16::from_be_bytes([*bytes.get(base + 1)?, *bytes.get(base + 2)?]) as usize;
        let length = u16::from_be_bytes([*bytes.get(base + 3)?, *bytes.get(base + 4)?]) as usize;
        if length < 6 {
            continue;
        }
        let data_start = base + offset;
        if data_start + 6 > bytes.len() {
            continue;
        }
        let data = &bytes[data_start..data_start + 6];
        let major = data[0];
        let minor = data[1];
        if !(6..=20).contains(&major) || minor > 60 {
            continue;
        }
        let build = u16::from_be_bytes([data[2], data[3]]);
        let sub_build = u16::from_be_bytes([data[4], data[5]]);
        return Some((major, minor, build, sub_build));
    }
    None
}

fn mssql_branded_version(major: u8, minor: u8) -> Option<&'static str> {
    match (major, minor) {
        (6, 0) => Some("6.0"),
        (6, 5) => Some("6.5"),
        (7, 0) => Some("7.0"),
        (8, 0) => Some("2000"),
        (9, 0) => Some("2005"),
        (10, 0) => Some("2008"),
        (10, 50) => Some("2008 R2"),
        (11, 0) => Some("2012"),
        (12, 0) => Some("2014"),
        (13, 0) => Some("2016"),
        (14, 0) => Some("2017"),
        (15, 0) => Some("2019"),
        (16, 0) => Some("2022"),
        _ => None,
    }
}

fn mssql_version_name(product: &str, service_pack_level: &str, patched: Option<bool>) -> String {
    if service_pack_level.is_empty() {
        return product.to_string();
    }
    let mut name = format!("{product} {service_pack_level}");
    if matches!(patched, Some(true)) {
        name.push('+');
    }
    name
}

fn mssql_service_pack_level(branded_version: &str, build: u16) -> (String, Option<bool>) {
    let table = match branded_version {
        "6.5" => MSSQL_SP_65,
        "7.0" => MSSQL_SP_70,
        "2000" => MSSQL_SP_2000,
        "2005" => MSSQL_SP_2005,
        "2008" => MSSQL_SP_2008,
        "2008 R2" => MSSQL_SP_2008_R2,
        "2012" => MSSQL_SP_2012,
        "2014" => MSSQL_SP_2014,
        "2016" => MSSQL_SP_2016,
        "2017" => MSSQL_SP_2017,
        "2019" => MSSQL_SP_2019,
        "2022" => MSSQL_SP_2022,
        _ => &[],
    };

    if table.is_empty() {
        return (String::new(), None);
    }

    if build < table[0].0 {
        return ("Pre-RTM".to_string(), None);
    }

    let mut last = table[0];
    for entry in table.iter() {
        if entry.0 > build {
            break;
        }
        last = *entry;
    }

    let patched = Some(build != last.0);
    (last.1.to_string(), patched)
}

const MSSQL_SP_65: &[(u16, &str)] = &[
    (201, "RTM"),
    (213, "SP1"),
    (240, "SP2"),
    (258, "SP3"),
    (281, "SP4"),
    (415, "SP5"),
    (416, "SP5a"),
    (417, "SP5/SP5a"),
];

const MSSQL_SP_70: &[(u16, &str)] = &[
    (623, "RTM"),
    (699, "SP1"),
    (842, "SP2"),
    (961, "SP3"),
    (1063, "SP4"),
];

const MSSQL_SP_2000: &[(u16, &str)] = &[
    (194, "RTM"),
    (384, "SP1"),
    (532, "SP2"),
    (534, "SP2"),
    (760, "SP3"),
    (766, "SP3a"),
    (767, "SP3/SP3a"),
    (2039, "SP4"),
];

const MSSQL_SP_2005: &[(u16, &str)] = &[
    (1399, "RTM"),
    (2047, "SP1"),
    (3042, "SP2"),
    (4035, "SP3"),
    (5000, "SP4"),
];

const MSSQL_SP_2008: &[(u16, &str)] = &[
    (1600, "RTM"),
    (2531, "SP1"),
    (4000, "SP2"),
    (5500, "SP3"),
    (6000, "SP4"),
];

const MSSQL_SP_2008_R2: &[(u16, &str)] =
    &[(1600, "RTM"), (2500, "SP1"), (4000, "SP2"), (6000, "SP3")];

const MSSQL_SP_2012: &[(u16, &str)] = &[
    (1103, "CTP1"),
    (1440, "CTP3"),
    (1750, "RC0"),
    (1913, "RC1"),
    (2100, "RTM"),
    (2316, "RTMCU1"),
    (2325, "RTMCU2"),
    (2332, "RTMCU3"),
    (2383, "RTMCU4"),
    (2395, "RTMCU5"),
    (2401, "RTMCU6"),
    (2405, "RTMCU7"),
    (2410, "RTMCU8"),
    (2419, "RTMCU9"),
    (2420, "RTMCU10"),
    (2424, "RTMCU11"),
    (3000, "SP1"),
    (3321, "SP1CU1"),
    (3339, "SP1CU2"),
    (3349, "SP1CU3"),
    (3368, "SP1CU4"),
    (3373, "SP1CU5"),
    (3381, "SP1CU6"),
    (3393, "SP1CU7"),
    (3401, "SP1CU8"),
    (3412, "SP1CU9"),
    (3431, "SP1CU10"),
    (3449, "SP1CU11"),
    (3470, "SP1CU12"),
    (3482, "SP1CU13"),
    (3486, "SP1CU14"),
    (3487, "SP1CU15"),
    (3492, "SP1CU16"),
    (5058, "SP2"),
    (5532, "SP2CU1"),
    (5548, "SP2CU2"),
    (5556, "SP2CU3"),
    (5569, "SP2CU4"),
    (5582, "SP2CU5"),
    (5592, "SP2CU6"),
    (5623, "SP2CU7"),
    (5634, "SP2CU8"),
    (5641, "SP2CU9"),
    (5644, "SP2CU10"),
    (5646, "SP2CU11"),
    (5649, "SP2CU12"),
    (5655, "SP2CU13"),
    (5657, "SP2CU14"),
    (5676, "SP2CU15"),
    (5678, "SP2CU16"),
    (6020, "SP3"),
    (6518, "SP3CU1"),
    (6523, "SP3CU2"),
    (6537, "SP3CU3"),
    (6540, "SP3CU4"),
    (6544, "SP3CU5"),
    (6567, "SP3CU6"),
    (6579, "SP3CU7"),
    (6594, "SP3CU8"),
    (6598, "SP3CU9"),
    (6607, "SP3CU10"),
    (7001, "SP4"),
];

const MSSQL_SP_2014: &[(u16, &str)] = &[
    (1524, "CTP2"),
    (2000, "RTM"),
    (2342, "RTMCU1"),
    (2370, "RTMCU2"),
    (2402, "RTMCU3"),
    (2430, "RTMCU4"),
    (2456, "RTMCU5"),
    (2480, "RTMCU6"),
    (2495, "RTMCU7"),
    (2546, "RTMCU8"),
    (2553, "RTMCU9"),
    (2556, "RTMCU10"),
    (2560, "RTMCU11"),
    (2564, "RTMCU12"),
    (2568, "RTMCU13"),
    (2569, "RTMCU14"),
    (4100, "SP1"),
    (4416, "SP1CU1"),
    (4422, "SP1CU2"),
    (4427, "SP1CU3"),
    (4436, "SP1CU4"),
    (4439, "SP1CU5"),
    (4449, "SP1CU6"),
    (4459, "SP1CU7"),
    (4468, "SP1CU8"),
    (4474, "SP1CU9"),
    (4491, "SP1CU10"),
    (4502, "SP1CU11"),
    (4511, "SP1CU12"),
    (4522, "SP1CU13"),
    (5000, "SP2"),
    (5511, "SP2CU1"),
    (5522, "SP2CU2"),
    (5538, "SP2CU3"),
    (5540, "SP2CU4"),
    (5546, "SP2CU5"),
    (5553, "SP2CU6"),
    (5556, "SP2CU7"),
    (5557, "SP2CU8"),
    (5563, "SP2CU9"),
    (5571, "SP2CU10"),
    (5579, "SP2CU11"),
    (5589, "SP2CU12"),
    (5590, "SP2CU13"),
    (5600, "SP2CU14"),
    (5605, "SP2CU15"),
    (5626, "SP2CU16"),
    (5632, "SP2CU17"),
    (5687, "SP2CU18"),
    (6024, "SP3"),
    (6205, "SP3CU1"),
    (6214, "SP3CU2"),
    (6259, "SP3CU3"),
    (6329, "SP3CU4"),
];

const MSSQL_SP_2016: &[(u16, &str)] = &[
    (200, "CTP2"),
    (300, "CTP2.1"),
    (407, "CTP2.2"),
    (500, "CTP2.3"),
    (600, "CTP2.4"),
    (700, "CTP3.0"),
    (800, "CTP3.1"),
    (900, "CTP3.2"),
    (1000, "CTP3.3"),
    (1100, "RC0"),
    (1200, "RC1"),
    (1300, "RC2"),
    (1400, "RC3"),
    (1601, "RTM"),
    (2149, "RTMCU1"),
    (2164, "RTMCU2"),
    (2186, "RTMCU3"),
    (2193, "RTMCU4"),
    (2197, "RTMCU5"),
    (2204, "RTMCU6"),
    (2210, "RTMCU7"),
    (2213, "RTMCU8"),
    (2216, "RTMCU9"),
    (4001, "SP1"),
    (4411, "SP1CU1"),
    (4422, "SP1CU2"),
    (4435, "SP1CU3"),
    (4446, "SP1CU4"),
    (4451, "SP1CU5"),
    (4457, "SP1CU6"),
    (4466, "SP1CU7"),
    (4474, "SP1CU8"),
    (4502, "SP1CU9"),
    (4514, "SP1CU10"),
    (4528, "SP1CU11"),
    (4541, "SP1CU12"),
    (4550, "SP1CU13"),
    (4560, "SP1CU14"),
    (4574, "SP1CU15"),
    (5026, "SP2"),
    (5149, "SP2CU1"),
    (5153, "SP2CU2"),
    (5216, "SP2CU3"),
    (5233, "SP2CU4"),
    (5264, "SP2CU5"),
    (5292, "SP2CU6"),
    (5337, "SP2CU7"),
    (5426, "SP2CU8"),
    (5479, "SP2CU9"),
    (5492, "SP2CU10"),
    (5598, "SP2CU11"),
    (5698, "SP2CU12"),
    (5820, "SP2CU13"),
    (5830, "SP2CU14"),
    (5850, "SP2CU15"),
    (5882, "SP2CU16"),
    (5888, "SP2CU17"),
    (6300, "SP3"),
];

const MSSQL_SP_2017: &[(u16, &str)] = &[
    (1, "CTP1"),
    (100, "CTP1.1"),
    (200, "CTP1.2"),
    (304, "CTP1.3"),
    (405, "CTP1.4"),
    (500, "CTP2.0"),
    (600, "CTP2.1"),
    (800, "RC1"),
    (900, "RC2"),
    (1000, "RTM"),
    (3006, "CU1"),
    (3008, "CU2"),
    (3015, "CU3"),
    (3022, "CU4"),
    (3023, "CU5"),
    (3025, "CU6"),
    (3026, "CU7"),
    (3029, "CU8"),
    (3030, "CU9"),
    (3037, "CU10"),
    (3038, "CU11"),
    (3045, "CU12"),
    (3048, "CU13"),
    (3076, "CU14"),
    (3162, "CU15"),
    (3223, "CU16"),
    (3238, "CU17"),
    (3257, "CU18"),
    (3281, "CU19"),
    (3294, "CU20"),
    (3335, "CU21"),
    (3356, "CU22"),
    (3381, "CU23"),
    (3391, "CU24"),
    (3401, "CU25"),
    (3411, "CU26"),
    (3421, "CU27"),
    (3430, "CU28"),
    (3436, "CU29"),
    (3451, "CU30"),
    (3456, "CU31"),
];

const MSSQL_SP_2019: &[(u16, &str)] = &[
    (1000, "CTP2.0"),
    (1100, "CTP2.1"),
    (1200, "CTP2.2"),
    (1300, "CTP2.3"),
    (1400, "CTP2.4"),
    (1500, "CTP2.5"),
    (1600, "CTP3.0"),
    (1700, "CTP3.1"),
    (1800, "CTP3.2"),
    (1900, "RC1"),
    (2000, "RTM"),
    (2070, "GDR1"),
    (4003, "CU1"),
    (4013, "CU2"),
    (4023, "CU3"),
    (4033, "CU4"),
    (4043, "CU5"),
    (4053, "CU6"),
    (4063, "CU7"),
    (4073, "CU8"),
    (4102, "CU9"),
    (4123, "CU10"),
    (4138, "CU11"),
    (4153, "CU12"),
    (4178, "CU13"),
    (4188, "CU14"),
    (4198, "CU15"),
    (4223, "CU16"),
    (4249, "CU17"),
    (4261, "CU18"),
    (4298, "CU19"),
    (4312, "CU20"),
    (4316, "CU21"),
    (4322, "CU22"),
    (4335, "CU23"),
    (4345, "CU24"),
    (4355, "CU25"),
];

const MSSQL_SP_2022: &[(u16, &str)] = &[
    (100, "CTP1.0"),
    (101, "CTP1.1"),
    (200, "CTP1.2"),
    (300, "CTP1.3"),
    (400, "CTP1.4"),
    (500, "CTP1.5"),
    (600, "CTP2.0"),
    (700, "CTP2.1"),
    (900, "RC0"),
    (950, "RC1"),
    (1000, "RTM"),
    (4003, "CU1"),
    (4015, "CU2"),
    (4025, "CU3"),
    (4035, "CU4"),
    (4045, "CU5"),
    (4055, "CU6"),
    (4065, "CU7"),
    (4075, "CU8"),
    (4085, "CU9"),
    (4095, "CU10"),
    (4105, "CU11"),
];
