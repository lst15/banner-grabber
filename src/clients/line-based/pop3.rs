use crate::model::{Config, Target};
use anyhow::Context;
use async_trait::async_trait;
use dns_lookup::lookup_addr;
use std::net::IpAddr;
use std::time::Instant;
use tokio::net::TcpStream;

use crate::clients::session::ClientSession;
use crate::clients::Client;

pub(crate) struct Pop3Client;

#[async_trait]
impl Client for Pop3Client {
    fn name(&self) -> &'static str {
        "pop3"
    }

    fn matches(&self, target: &Target) -> bool {
        target.resolved.port() == 110
    }

    async fn execute(
        &self,
        stream: &mut TcpStream,
        cfg: &Config,
    ) -> anyhow::Result<crate::engine::reader::ReadResult> {
        let mut session = ClientSession::new(cfg);

        collect_unauthenticated_metadata(&mut session, stream, cfg).await?;

        let authenticated = attempt_common_logins(&mut session, stream).await?;

        if authenticated {
            collect_authenticated_metadata(&mut session, stream).await?;
        }

        Ok(session.finish())
    }
}

async fn collect_unauthenticated_metadata(
    session: &mut ClientSession,
    stream: &mut TcpStream,
    cfg: &Config,
) -> anyhow::Result<()> {
    let mut metadata = String::from("== POP3 Unauthenticated Banner ==\n");

    let peer_addr = stream
        .peer_addr()
        .context("unable to read peer address for POP3")?;
    metadata.push_str(&format!("Connected IP: {}\n", peer_addr.ip()));
    metadata.push_str(&format!("Connected Port: {}\n", peer_addr.port()));

    let hostname = resolve_hostname(peer_addr.ip()).await;
    if let Some(host) = hostname {
        metadata.push_str(&format!("Resolved Hostname: {host}\n"));
    } else if let Some(target) = cfg.target.as_ref() {
        metadata.push_str(&format!("Provided Hostname: {}\n", target.host));
    } else {
        metadata.push_str("Hostname: <unavailable>\n");
    }

    let greeting_start = Instant::now();
    let greeting = session
        .read_with_result(stream, Some(b"\n"))
        .await
        .context("failed to read POP3 greeting")?;
    let greeting_time = greeting_start.elapsed();
    metadata.push_str(&format!(
        "Greeting Response Time: {} ms\n",
        greeting_time.as_millis()
    ));

    let banner_text = String::from_utf8_lossy(&greeting.bytes);
    metadata.push_str(&format!("Initial Banner: {}\n", banner_text.trim()));

    if let Some(hint) = extract_software_hint(&banner_text) {
        metadata.push_str(&format!("Software Hint: {}\n", hint));
    }

    session
        .send(stream, b"CAPA\r\n")
        .await
        .context("failed to query POP3 CAPA")?;
    let capability_result = session
        .read_with_result(stream, None)
        .await
        .context("failed to read POP3 CAPA response")?;
    let capability_text = String::from_utf8_lossy(&capability_result.bytes);
    let stls_supported = capability_text
        .to_ascii_uppercase()
        .lines()
        .any(|line| line.contains("STLS"));

    metadata.push_str(&format!(
        "STLS Supported: {}\n",
        if stls_supported { "yes" } else { "no" }
    ));
    metadata.push_str("CAPA (unauthenticated): ");
    metadata.push_str(capability_text.trim());
    metadata.push('\n');

    session.append_metadata(metadata);

    Ok(())
}

async fn attempt_common_logins(
    session: &mut ClientSession,
    stream: &mut TcpStream,
) -> anyhow::Result<bool> {
    let mut attempt_log = String::from("== POP3 Login Attempts ==\n");

    let common_credentials = vec![
        ("anonymous", ""),
        ("test", "test"),
        ("guest", "guest"),
        ("admin", "admin"),
        ("user", "user"),
    ];

    for (username, password) in common_credentials {
        session
            .send(stream, format!("USER {username}\r\n").as_bytes())
            .await
            .with_context(|| format!("failed to send USER for {username}"))?;
        let user_res = session
            .read_with_result(stream, None)
            .await
            .context("failed to read USER response")?;
        let user_text = String::from_utf8_lossy(&user_res.bytes);
        let user_ok = is_positive_response(&user_text);

        if !user_ok {
            attempt_log.push_str(&format!(
                "{username}:{password} => FAIL (USER) {user_text}\n"
            ));
            continue;
        }

        session
            .send(stream, format!("PASS {password}\r\n").as_bytes())
            .await
            .with_context(|| format!("failed to send PASS for {username}"))?;
        let pass_res = session
            .read_with_result(stream, None)
            .await
            .context("failed to read PASS response")?;
        let pass_text = String::from_utf8_lossy(&pass_res.bytes);
        let success = is_positive_response(&pass_text);

        attempt_log.push_str(&format!(
            "{username}:{password} => {} {pass_text}\n",
            if success { "OK" } else { "FAIL" }
        ));

        if success {
            session.append_metadata(attempt_log);
            return Ok(true);
        }
    }

    session.append_metadata(attempt_log);
    Ok(false)
}

async fn collect_authenticated_metadata(
    session: &mut ClientSession,
    stream: &mut TcpStream,
) -> anyhow::Result<()> {
    let mut metadata = String::from("== POP3 Authenticated Metadata ==\n");

    session
        .send(stream, b"STAT\r\n")
        .await
        .context("failed to send STAT")?;
    let stat_res = session
        .read_with_result(stream, None)
        .await
        .context("failed to read STAT response")?;
    let stat_text = String::from_utf8_lossy(&stat_res.bytes);

    if let Some((count, size)) = parse_stat(&stat_text) {
        metadata.push_str(&format!(
            "Messages: {}\nTotal Size: {} bytes\n",
            count, size
        ));
    } else {
        metadata.push_str(&format!("STAT Response: {}\n", stat_text.trim()));
    }

    session
        .send(stream, b"LIST\r\n")
        .await
        .context("failed to send LIST")?;
    let list_res = session
        .read_with_result(stream, None)
        .await
        .context("failed to read LIST response")?;
    let list_text = String::from_utf8_lossy(&list_res.bytes);
    metadata.push_str("LISTing:\n");
    metadata.push_str(list_text.trim());
    metadata.push('\n');

    session
        .send(stream, b"UIDL\r\n")
        .await
        .context("failed to send UIDL")?;
    let uidl_res = session
        .read_with_result(stream, None)
        .await
        .context("failed to read UIDL response")?;
    let uidl_text = String::from_utf8_lossy(&uidl_res.bytes);
    metadata.push_str("UIDL:\n");
    metadata.push_str(uidl_text.trim());
    metadata.push('\n');

    session
        .send(stream, b"CAPA\r\n")
        .await
        .context("failed to query authenticated CAPA")?;
    let capa_res = session
        .read_with_result(stream, None)
        .await
        .context("failed to read authenticated CAPA")?;
    let capa_text = String::from_utf8_lossy(&capa_res.bytes);
    metadata.push_str("Authenticated CAPA:\n");
    metadata.push_str(capa_text.trim());
    metadata.push('\n');

    session.append_metadata(metadata);

    Ok(())
}

async fn resolve_hostname(ip: IpAddr) -> Option<String> {
    tokio::task::spawn_blocking(move || lookup_addr(&ip).ok())
        .await
        .ok()
        .flatten()
}

fn extract_software_hint(banner: &str) -> Option<String> {
    banner
        .split_whitespace()
        .find(|token| {
            token.chars().any(|c| c.is_ascii_alphabetic())
                && token.chars().any(|c| c.is_ascii_digit())
                && !token.starts_with("+OK")
        })
        .map(|token| token.trim_matches(|c: char| c == '<' || c == '>' || c == '[' || c == ']'))
        .map(ToString::to_string)
}

fn is_positive_response(resp: &str) -> bool {
    resp.trim_start().starts_with("+OK")
}

fn parse_stat(resp: &str) -> Option<(u64, u64)> {
    let mut parts = resp.trim().split_whitespace();
    let status = parts.next()?;
    if !status.eq_ignore_ascii_case("+OK") {
        return None;
    }
    let count = parts.next()?.parse().ok()?;
    let size = parts.next()?.parse().ok()?;
    Some((count, size))
}
