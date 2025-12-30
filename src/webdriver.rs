use crate::model::{Protocol, Target};
use anyhow::Context;
use headless_chrome::{Browser, LaunchOptionsBuilder};
use std::ffi::OsStr;
use std::time::Duration;

pub async fn fetch_rendered_body(
    target: &Target,
    protocol: &Protocol,
    timeout: Duration,
) -> anyhow::Result<String> {
    let url = build_url(target, protocol);
    let handle = tokio::task::spawn_blocking(move || render_body_blocking(&url));

    tokio::time::timeout(timeout, handle)
        .await
        .context("webdriver timed out")?
        .context("webdriver task failed")?
}

fn build_url(target: &Target, protocol: &Protocol) -> String {
    let host = if target.original.host.is_empty() {
        target.resolved.ip().to_string()
    } else {
        target.original.host.clone()
    };
    let scheme = protocol.to_string();
    format!("{}://{}:{}/", scheme, host, target.resolved.port())
}

fn render_body_blocking(url: &str) -> anyhow::Result<String> {
    let launch_options = LaunchOptionsBuilder::default()
        .headless(true)
        .args(vec![OsStr::new("--ignore-certificate-errors")])
        .build()
        .context("failed to build chrome launch options")?;
    let browser = Browser::new(launch_options).context("failed to launch headless chrome")?;
    let tab = browser.new_tab().context("failed to create new tab")?;

    tab.navigate_to(url)
        .with_context(|| format!("failed to navigate to {url}"))?;
    tab.wait_until_navigated()
        .context("failed to wait for navigation")?;

    let evaluation = tab
        .evaluate("document.body ? document.body.innerHTML : ''", false)
        .context("failed to evaluate document body")?;
    Ok(evaluation
        .value
        .and_then(|value| value.as_str().map(|body| body.to_string()))
        .unwrap_or_default())
}
