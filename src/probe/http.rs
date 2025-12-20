use super::Prober;
use crate::model::Target;
use std::borrow::Cow;

pub(super) struct HttpProbe;

impl Prober for HttpProbe {
    fn name(&self) -> &'static str {
        "http"
    }

    fn probe_bytes(&self) -> &'static [u8] {
        b"GET / HTTP/1.0\r\n\r\n"
    }

    fn build_probe(&self, target: &Target) -> Cow<'static, [u8]> {
        let host = target
            .original
            .host
            .split(|c| c == '\r' || c == '\n')
            .next()
            .unwrap_or("example");

        Cow::Owned(format!("GET / HTTP/1.0\r\nHost: {}\r\n\r\n", host).into_bytes())
    }

    fn matches(&self, target: &Target) -> bool {
        matches!(target.resolved.port(), 80 | 443 | 8000 | 8080 | 8443)
    }
}
