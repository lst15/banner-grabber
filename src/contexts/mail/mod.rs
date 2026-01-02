use crate::core::clients::Client;
use crate::core::model::{Protocol, ScanMode};

pub mod clients;

static IMAP_CLIENT: clients::ImapClient = clients::ImapClient;
static POP3_CLIENT: clients::Pop3Client = clients::Pop3Client;
static SMTP_CLIENT: clients::SmtpClient = clients::SmtpClient;

pub(crate) fn client_for_target(
    mode: &ScanMode,
    protocol: &Protocol,
) -> Option<&'static dyn Client> {
    if !matches!(mode, ScanMode::Active) {
        return None;
    }

    match protocol {
        Protocol::Imap => Some(&IMAP_CLIENT),
        Protocol::Pop3 => Some(&POP3_CLIENT),
        Protocol::Smtp => Some(&SMTP_CLIENT),
        _ => None,
    }
}
