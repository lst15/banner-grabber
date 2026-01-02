use crate::core::clients::{Client, UdpClient};
use crate::core::model::{Protocol, ScanMode};

pub mod clients;

static FTP_CLIENT: clients::FtpClient = clients::FtpClient;
static MEMCACHED_CLIENT: clients::MemcachedClient = clients::MemcachedClient;
static MQTT_CLIENT: clients::MqttClient = clients::MqttClient;
static SMB_CLIENT: clients::SmbClient = clients::SmbClient;
static SSH_CLIENT: clients::SshClient = clients::SshClient;
static TELNET_CLIENT: clients::TelnetClient = clients::TelnetClient;
static VNC_CLIENT: clients::VncClient = clients::VncClient;
static NTP_CLIENT: clients::NtpClient = clients::NtpClient;

pub(crate) fn client_for_target(
    mode: &ScanMode,
    protocol: &Protocol,
) -> Option<&'static dyn Client> {
    if !matches!(mode, ScanMode::Active) {
        return None;
    }

    match protocol {
        Protocol::Ftp => Some(&FTP_CLIENT),
        Protocol::Memcached => Some(&MEMCACHED_CLIENT),
        Protocol::Mqtt => Some(&MQTT_CLIENT),
        Protocol::Smb => Some(&SMB_CLIENT),
        Protocol::Ssh => Some(&SSH_CLIENT),
        Protocol::Telnet => Some(&TELNET_CLIENT),
        Protocol::Vnc => Some(&VNC_CLIENT),
        _ => None,
    }
}

pub(crate) fn udp_client_for_target(
    mode: &ScanMode,
    protocol: &Protocol,
) -> Option<&'static dyn UdpClient> {
    if !matches!(mode, ScanMode::Active) {
        return None;
    }

    match protocol {
        Protocol::Ntp => Some(&NTP_CLIENT),
        _ => None,
    }
}
