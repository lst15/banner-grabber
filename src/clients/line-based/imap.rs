use crate::clients::session::ClientSession;
use crate::clients::Client;
use crate::model::{Config, Target};
use anyhow::Context;
use async_trait::async_trait;
use dns_lookup::lookup_addr;
use std::net::IpAddr;
use std::time::Instant;
use tokio::net::TcpStream;

/// Captured capabilities from unauthenticated queries so that login and
/// follow-up metadata can make informed decisions without re-parsing.
struct ImapCapabilityInfo {
    raw: String,
    starttls: bool,
    logindisabled: bool,
    auth_mechanisms: Vec<String>,
}

pub(crate) struct ImapClient;

#[async_trait]
impl Client for ImapClient {
    fn name(&self) -> &'static str {
        "imap"
    }

    fn matches(&self, target: &Target) -> bool {
        target.resolved.port() == 143
    }

    async fn execute(
        &self,
        stream: &mut TcpStream,
        cfg: &Config,
    ) -> anyhow::Result<crate::engine::reader::ReadResult> {
        let mut session = ClientSession::new(cfg);
        let capability = collect_unauthenticated_metadata(&mut session, stream, cfg).await?;

        let auth_user = attempt_common_logins(&mut session, stream, &capability).await?;

        if auth_user.is_some() {
            collect_authenticated_metadata(&mut session, stream).await?;
        }

        Ok(session.finish())
    }
}

/// Gather banner and metadata without authentication. This must always run
/// before any login attempts are performed.
async fn collect_unauthenticated_metadata(
    session: &mut ClientSession,
    stream: &mut TcpStream,
    cfg: &Config,
) -> anyhow::Result<ImapCapabilityInfo> {
    let mut metadata = String::new();

    let peer_addr = stream.peer_addr().context("unable to read peer address")?;
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
    let _greeting = session.read_with_result(stream, Some(b"\n")).await?;
    let greeting_time = greeting_start.elapsed();
    metadata.push_str(&format!(
        "Greeting Response Time: {} ms\n",
        greeting_time.as_millis()
    ));

    session
        .send(stream, b"a001 CAPABILITY\r\n")
        .await
        .context("failed to query CAPABILITY")?;
    let capability_result = session.read_with_result(stream, None).await?;

    let capability_info = parse_capabilities(&capability_result.bytes);
    if capability_info.starttls {
        metadata.push_str("STARTTLS Supported: yes\n");
    } else {
        metadata.push_str("STARTTLS Supported: no\n");
    }

    if capability_info.logindisabled {
        metadata.push_str("LOGIN Disabled Until TLS: yes\n");
    }

    if !capability_info.auth_mechanisms.is_empty() {
        metadata.push_str("Authentication Mechanisms: ");
        metadata.push_str(&capability_info.auth_mechanisms.join(", "));
        metadata.push('\n');
    }

    metadata.push_str("Unauthenticated CAPABILITY: ");
    metadata.push_str(&capability_info.raw);
    metadata.push('\n');

    session.append_metadata(metadata);

    Ok(capability_info)
}

/// Attempt a curated list of weak/common credentials. Each attempt is logged
/// before continuing to the authenticated phase.
async fn attempt_common_logins(
    session: &mut ClientSession,
    stream: &mut TcpStream,
    capabilities: &ImapCapabilityInfo,
) -> anyhow::Result<Option<String>> {
    let mut attempt_log = String::new();

    if capabilities.logindisabled {
        attempt_log.push_str("Login attempts skipped: LOGINDISABLED present without TLS.\n");
        session.append_metadata(attempt_log);
        return Ok(None);
    }

    let common_credentials = vec![
        ("anonymous", ""),
        ("test", "test"),
        ("guest", "guest"),
        ("admin", "admin"),
        ("user", "user"),
    ];

    for (idx, (username, password)) in common_credentials.iter().enumerate() {
        let tag = format!("aL{:03}", idx);
        let command = format!("{tag} LOGIN {username} {password}\r\n");
        session
            .send(stream, command.as_bytes())
            .await
            .with_context(|| format!("failed to send login for {username}"))?;

        let login_result = session.read_with_result(stream, None).await?;
        let login_text = String::from_utf8_lossy(&login_result.bytes);
        let success = login_text.to_ascii_uppercase().contains("OK") && login_text.contains(&tag);

        attempt_log.push_str(&format!(
            "Login attempt {username}:{password} => {}\n",
            if success { "OK" } else { "FAIL" }
        ));

        if success {
            session.append_metadata(attempt_log);
            return Ok(Some((*username).to_string()));
        }
    }

    session.append_metadata(attempt_log);
    Ok(None)
}

/// Collect authenticated-only metadata. This only runs after a successful
/// login.
async fn collect_authenticated_metadata(
    session: &mut ClientSession,
    stream: &mut TcpStream,
) -> anyhow::Result<()> {
    session
        .send(stream, b"a200 CAPABILITY\r\n")
        .await
        .context("failed to query authenticated CAPABILITY")?;
    let auth_capability = session.read_with_result(stream, None).await?;
    let auth_info = parse_capabilities(&auth_capability.bytes);

    let mut metadata = String::new();
    metadata.push_str("Authenticated CAPABILITY: ");
    metadata.push_str(&auth_info.raw);
    metadata.push('\n');

    if !auth_info.auth_mechanisms.is_empty() {
        metadata.push_str("Authenticated mechanisms: ");
        metadata.push_str(&auth_info.auth_mechanisms.join(", "));
        metadata.push('\n');
    }

    metadata.push_str("Advanced Features: ");
    let mut features = Vec::new();
    for feature in ["IDLE", "QUOTA", "XLIST", "UIDPLUS", "METADATA"] {
        if auth_info
            .raw
            .to_ascii_uppercase()
            .split_whitespace()
            .any(|item| item == feature)
        {
            features.push(feature.to_string());
        }
    }
    metadata.push_str(&if features.is_empty() {
        "<none>".to_string()
    } else {
        features.join(", ")
    });
    metadata.push('\n');

    session.append_metadata(metadata);

    session
        .send(stream, b"a201 LIST \"\" \"*\"\r\n")
        .await
        .context("failed to list mailboxes")?;
    session.read(stream, None).await?;

    Ok(())
}

fn parse_capabilities(bytes: &[u8]) -> ImapCapabilityInfo {
    let raw = String::from_utf8_lossy(bytes).to_string();
    let mut starttls = false;
    let mut logindisabled = false;
    let mut auth_mechanisms = Vec::new();

    for item in raw.split_whitespace() {
        let upper = item.to_ascii_uppercase();
        if upper == "STARTTLS" {
            starttls = true;
        }
        if upper == "LOGINDISABLED" {
            logindisabled = true;
        }
        if let Some(mech) = upper.strip_prefix("AUTH=") {
            auth_mechanisms.push(mech.to_string());
        }
    }

    ImapCapabilityInfo {
        raw,
        starttls,
        logindisabled,
        auth_mechanisms,
    }
}

async fn resolve_hostname(ip: IpAddr) -> Option<String> {
    let lookup_result = tokio::task::spawn_blocking(move || lookup_addr(&ip))
        .await
        .ok();
    lookup_result.and_then(Result::ok)
}
