mod fingerprint;
mod http;
mod redis;
mod registry;
mod tls;

pub use fingerprint::fingerprint;
pub use registry::{probe_for_target, ProbeRequest, Prober};

pub(super) fn is_probably_tls_port(port: u16) -> bool {
    matches!(port, 443 | 8443 | 9443 | 10443)
}
