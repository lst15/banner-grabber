use crate::core::model::{Protocol, ScanMode};
use crate::core::traits::Prober;

pub mod probes;

#[cfg(feature = "webdriver")]
pub mod webdriver;

static HTTP_PROBE: probes::HttpProbe = probes::HttpProbe;
static HTTPS_PROBE: probes::HttpsProbe = probes::HttpsProbe;
static TLS_PROBE: probes::TlsProbe = probes::TlsProbe;

pub(crate) fn probe_for_target(
    mode: &ScanMode,
    protocol: &Protocol,
) -> Option<&'static dyn Prober> {
    if matches!(mode, ScanMode::Passive) {
        return None;
    }

    match protocol {
        Protocol::Http => Some(&HTTP_PROBE as &'static dyn Prober),
        Protocol::Https => Some(&HTTPS_PROBE as &'static dyn Prober),
        Protocol::Tls => Some(&TLS_PROBE as &'static dyn Prober),
        _ => None,
    }
}
