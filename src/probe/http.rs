use super::Prober;
use crate::model::Target;
use std::borrow::Cow;

pub(super) struct HttpProbe;

impl Prober for HttpProbe {
    fn name(&self) -> &'static str {
        "http"
    }

    fn probe_bytes(&self) -> &'static [u8] {
        b"GET / HTTP/1.0\r\nHost: example\r\n\r\n"
    }

    fn probe_bytes_for(&self, target: &Target) -> Cow<'static, [u8]> {
        let host = &target.original.host;
        let formatted_host = if host.contains(':') {
            format!("[{}]", host)
        } else {
            host.clone()
        };

        Cow::Owned(
            format!(
                "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: banner-grabber\r\nConnection: close\r\n\r\n",
                formatted_host
            )
            .into_bytes(),
        )
    }

    fn matches(&self, target: &Target) -> bool {
        matches!(target.resolved.port(), 80 | 443 | 8000 | 8080 | 8443)
    }
}
