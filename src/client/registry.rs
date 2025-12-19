use crate::model::{ScanMode, Target};

use super::ftp::FtpClient;
use super::imap::ImapClient;
use super::memcached::MemcachedClient;
use super::mongodb::MongodbClient;
use super::mqtt::MqttClient;
use super::mssql::MssqlClient;
use super::mysql::MysqlClient;
use super::pop3::Pop3Client;
use super::postgres::PostgresClient;
use super::redis::RedisClient;
use super::smb::SmbClient;
use super::smtp::SmtpClient;
use super::ssh::SshClient;
use super::telnet::TelnetClient;
use super::Client;

pub struct ClientRequest {
    pub target: Target,
    pub mode: ScanMode,
}

static FTP_CLIENT: FtpClient = FtpClient;
static IMAP_CLIENT: ImapClient = ImapClient;
static MEMCACHED_CLIENT: MemcachedClient = MemcachedClient;
static MONGODB_CLIENT: MongodbClient = MongodbClient;
static MQTT_CLIENT: MqttClient = MqttClient;
static MSSQL_CLIENT: MssqlClient = MssqlClient;
static MYSQL_CLIENT: MysqlClient = MysqlClient;
static POP3_CLIENT: Pop3Client = Pop3Client;
static POSTGRES_CLIENT: PostgresClient = PostgresClient;
static REDIS_CLIENT: RedisClient = RedisClient;
static SMTP_CLIENT: SmtpClient = SmtpClient;
static SMB_CLIENT: SmbClient = SmbClient;
static SSH_CLIENT: SshClient = SshClient;
static TELNET_CLIENT: TelnetClient = TelnetClient;

static CLIENTS: [&dyn Client; 14] = [
    &FTP_CLIENT,
    &IMAP_CLIENT,
    &MEMCACHED_CLIENT,
    &MONGODB_CLIENT,
    &MQTT_CLIENT,
    &MSSQL_CLIENT,
    &MYSQL_CLIENT,
    &POP3_CLIENT,
    &POSTGRES_CLIENT,
    &REDIS_CLIENT,
    &SMTP_CLIENT,
    &SMB_CLIENT,
    &SSH_CLIENT,
    &TELNET_CLIENT,
];

pub fn client_for_target(req: &ClientRequest) -> Option<&'static dyn Client> {
    if !matches!(req.mode, ScanMode::Active) {
        return None;
    }

    CLIENTS
        .iter()
        .copied()
        .find(|client| client.matches(&req.target))
}
