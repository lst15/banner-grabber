use crate::core::clients::Client;
use crate::core::model::{Protocol, ScanMode};
use crate::core::traits::Prober;

pub mod clients;
pub mod probes;

static MONGODB_CLIENT: clients::MongodbClient = clients::MongodbClient;
static MSSQL_CLIENT: clients::MssqlClient = clients::MssqlClient;
static MYSQL_CLIENT: clients::MysqlClient = clients::MysqlClient;
static POSTGRES_CLIENT: clients::PostgresClient = clients::PostgresClient;
static REDIS_CLIENT: clients::RedisClient = clients::RedisClient;

static REDIS_PROBE: probes::RedisProbe = probes::RedisProbe;

pub(crate) fn client_for_target(
    mode: &ScanMode,
    protocol: &Protocol,
) -> Option<&'static dyn Client> {
    if !matches!(mode, ScanMode::Active) {
        return None;
    }

    match protocol {
        Protocol::Mongodb => Some(&MONGODB_CLIENT),
        Protocol::Mssql => Some(&MSSQL_CLIENT),
        Protocol::Mysql => Some(&MYSQL_CLIENT),
        Protocol::Postgres => Some(&POSTGRES_CLIENT),
        Protocol::Redis => Some(&REDIS_CLIENT),
        _ => None,
    }
}

pub(crate) fn probe_for_target(
    mode: &ScanMode,
    protocol: &Protocol,
) -> Option<&'static dyn Prober> {
    if matches!(mode, ScanMode::Passive) {
        return None;
    }

    match protocol {
        Protocol::Redis => Some(&REDIS_PROBE as &'static dyn Prober),
        _ => None,
    }
}
