use crate::model::{Protocol, ScanMode, Target};

use super::ftp::FtpClient;
use super::imap::ImapClient;
use super::memcached::MemcachedClient;
use super::mongodb::MongodbClient;
use super::mqtt::MqttClient;
use super::mssql::MssqlClient;
use super::mysql::MysqlClient;
use super::pop3::Pop3Client;
use super::redis::RedisClient;
use super::smb::SmbClient;
use super::smtp::SmtpClient;
use super::ssh::SshClient;
use super::telnet::TelnetClient;
use super::vnc::VncClient;
use crate::clients::NtpClient;
use crate::clients::{Client, UdpClient};

pub struct ClientRequest {
    #[allow(dead_code)]
    pub target: Target,
    pub mode: ScanMode,
    pub protocol: Protocol,
}

static NTP_CLIENT: NtpClient = NtpClient;

static FTP_CLIENT: FtpClient = FtpClient;
static IMAP_CLIENT: ImapClient = ImapClient;
static MEMCACHED_CLIENT: MemcachedClient = MemcachedClient;
static MONGODB_CLIENT: MongodbClient = MongodbClient;
static MQTT_CLIENT: MqttClient = MqttClient;
static MSSQL_CLIENT: MssqlClient = MssqlClient;
static MYSQL_CLIENT: MysqlClient = MysqlClient;
static POP3_CLIENT: Pop3Client = Pop3Client;
static REDIS_CLIENT: RedisClient = RedisClient;
static SMTP_CLIENT: SmtpClient = SmtpClient;
static SMB_CLIENT: SmbClient = SmbClient;
static SSH_CLIENT: SshClient = SshClient;
static TELNET_CLIENT: TelnetClient = TelnetClient;
static VNC_CLIENT: VncClient = VncClient;

pub fn client_for_target(req: &ClientRequest) -> Option<&'static dyn Client> {
    if !matches!(req.mode, ScanMode::Active) {
        return None;
    }

    match req.protocol {
        Protocol::Ftp => Some(&FTP_CLIENT),
        Protocol::Imap => Some(&IMAP_CLIENT),
        Protocol::Memcached => Some(&MEMCACHED_CLIENT),
        Protocol::Mongodb => Some(&MONGODB_CLIENT),
        Protocol::Mqtt => Some(&MQTT_CLIENT),
        Protocol::Mssql => Some(&MSSQL_CLIENT),
        Protocol::Mysql => Some(&MYSQL_CLIENT),
        Protocol::Pop3 => Some(&POP3_CLIENT),
        Protocol::Redis => Some(&REDIS_CLIENT),
        Protocol::Smb => Some(&SMB_CLIENT),
        Protocol::Smtp => Some(&SMTP_CLIENT),
        Protocol::Ssh => Some(&SSH_CLIENT),
        Protocol::Telnet => Some(&TELNET_CLIENT),
        Protocol::Vnc => Some(&VNC_CLIENT),
        _ => None,
    }
}

pub fn udp_client_for_target(req: &ClientRequest) -> Option<&'static dyn UdpClient> {
    if !matches!(req.mode, ScanMode::Active) {
        return None;
    }

    match req.protocol {
        Protocol::Ntp => Some(&NTP_CLIENT),
        _ => None,
    }
}
