use crate::core::clients::{Client, UdpClient};
use crate::core::model::{Protocol, ScanMode, Target};
use crate::core::traits::Prober;

#[derive(Clone, Debug)]
pub struct ClientRequest {
    #[allow(dead_code)]
    pub target: Target,
    pub mode: ScanMode,
    pub protocol: Protocol,
}

#[derive(Clone, Debug)]
pub struct ProbeRequest {
    #[allow(dead_code)]
    pub target: Target,
    pub mode: ScanMode,
    pub protocol: Protocol,
}

pub fn client_for_target(req: &ClientRequest) -> Option<&'static dyn Client> {
    if !matches!(req.mode, ScanMode::Active) {
        return None;
    }

    #[cfg(feature = "db")]
    if let Some(client) = crate::contexts::db::client_for_target(&req.mode, &req.protocol) {
        return Some(client);
    }

    #[cfg(feature = "mail")]
    if let Some(client) = crate::contexts::mail::client_for_target(&req.mode, &req.protocol) {
        return Some(client);
    }

    #[cfg(feature = "infra")]
    if let Some(client) = crate::contexts::infra::client_for_target(&req.mode, &req.protocol) {
        return Some(client);
    }

    None
}

pub fn udp_client_for_target(req: &ClientRequest) -> Option<&'static dyn UdpClient> {
    if !matches!(req.mode, ScanMode::Active) {
        return None;
    }

    #[cfg(feature = "infra")]
    if let Some(client) = crate::contexts::infra::udp_client_for_target(&req.mode, &req.protocol) {
        return Some(client);
    }

    None
}

pub fn probe_for_target(req: &ProbeRequest) -> Option<&'static dyn Prober> {
    if matches!(req.mode, ScanMode::Passive) {
        return None;
    }

    #[cfg(feature = "web")]
    if let Some(prober) = crate::contexts::web::probe_for_target(&req.mode, &req.protocol) {
        return Some(prober);
    }

    #[cfg(feature = "db")]
    if let Some(prober) = crate::contexts::db::probe_for_target(&req.mode, &req.protocol) {
        return Some(prober);
    }

    None
}
