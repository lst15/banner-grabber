# Banner Grabber

Async banner grabbing tool using Tokio with configurable timeouts, rate limiting, and pluggable probes.

Active mode now includes lightweight clients for common protocols (FTP, SMTP, SSH, MySQL) that can perform optional handshakes and send simple probes (for example, `FEAT`/`SYST` on FTP or `EHLO` on SMTP) to coax richer banners.

## Active clients disponíveis

Implementações atuais de active client que realizam handshakes e probes leves para extrair metadados:

- FTP: banner + `FEAT` e `SYST`.
- SMTP: banner + `EHLO`.
- SSH: banner + identificação opcional.
- MySQL: handshake inicial do servidor.
- IMAP: banner + `CAPABILITY`.
- POP3: banner + `CAPA`.
- PostgreSQL: pacote de startup para provocar `AuthenticationRequest`.
- MSSQL (TDS): handshake `PRELOGIN` expondo versão e opções.
- MongoDB: comando `isMaster` em `admin.$cmd`.
- Redis: `PING` seguido de `INFO`.
- Memcached: `version` seguido de `stats`.
- MQTT: `CONNECT` com sessão limpa e `clientId` vazio.
- Telnet: banner inicial com negociação de opções para elicitar prompts.

## Usage

Run with a single host/port:

```bash
cargo run -- --host 192.0.2.10 --port 80
```

Run against a list from a file (one target per line):

```bash
cargo run -- --input targets.txt
```

You can also provide `--port` alongside `--input` to filter the list, keeping only targets
whose port matches the value you supplied.

Optional flags you may want to tweak:

- `--concurrency <N>`: concurrent connections limit (default 64)
- `--rate <N>`: new connections per second (default 64)
- `--connect-timeout <ms>` / `--read-timeout <ms>` / `--overall-timeout <ms>`
- `--mode passive|active`: whether to send protocol-specific probes (default passive)
- `--output jsonl|pretty|csv` or `--pretty` for log-style output

## Input file format

- One target per line in the form `host:port` or `[IPv6]:port`
- Empty lines and lines starting with `#` are ignored
- Hostnames are resolved to all A/AAAA records; each address becomes a target

Example `targets.txt`:

```
# Web servers
203.0.113.5:80
[2001:db8::1]:443
example.com:25
```
