use crate::model::{ScanMode, Target};

use super::ftp::FtpClient;
use super::mysql::MysqlClient;
use super::smtp::SmtpClient;
use super::ssh::SshClient;
use super::Client;

pub struct ClientRequest {
    pub target: Target,
    pub mode: ScanMode,
}

static FTP_CLIENT: FtpClient = FtpClient;
static SMTP_CLIENT: SmtpClient = SmtpClient;
static SSH_CLIENT: SshClient = SshClient;
static MYSQL_CLIENT: MysqlClient = MysqlClient;

static CLIENTS: [&dyn Client; 4] = [&FTP_CLIENT, &SMTP_CLIENT, &SSH_CLIENT, &MYSQL_CLIENT];

pub fn client_for_target(req: &ClientRequest) -> Option<&'static dyn Client> {
    if !matches!(req.mode, ScanMode::Active) {
        return None;
    }

    CLIENTS
        .iter()
        .copied()
        .find(|client| client.matches(&req.target))
}
