use super::{is_probably_tls_port, Prober};
use crate::model::Target;

pub(super) struct TlsProbe;

impl Prober for TlsProbe {
    fn name(&self) -> &'static str {
        "tls"
    }

    fn probe_bytes(&self) -> &'static [u8] {
        // Minimal TLS ClientHello that negotiates modern cipher suites without
        // allocating on the hot path.
        const CLIENT_HELLO: &[u8] = b"\x16\x03\x01\x00\x31\x01\x00\x00\x2d\x03\x03\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x00\x00\x02\x13\x01\x00\x00\x05\x00\xff\x01\x00\x01\x00";
        CLIENT_HELLO
    }

    fn matches(&self, target: &Target) -> bool {
        is_probably_tls_port(target.resolved.port())
    }
}
