# Banner Grabber

Async banner grabbing tool using Tokio with configurable timeouts, rate limiting, and pluggable probes.

## Usage

Run with a single host/port:

```bash
cargo run -- --host 192.0.2.10 --port 80
```

Run against a list from a file (one target per line):

```bash
cargo run -- --input targets.txt
```

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
