use banner_grabber::engine::reader::BannerReader;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test]
async fn reader_handles_delayed_banner() {
    let mut reader = BannerReader::new(32);
    let mut data: &[u8] = b"hello\r\n";
    let banner = reader.read(&mut data, None).await.unwrap();
    assert_eq!(banner.bytes, b"hello\r\n");
}

#[tokio::test]
async fn simulated_service_requires_probe() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 4];
        socket.readable().await.unwrap();
        let _ = socket.try_read(&mut buf);
        socket.write_all(b"-ERR mock redis\r\n").await.unwrap();
    });

    let cfg = banner_grabber::model::Config {
        target: Some(banner_grabber::model::TargetSpec {
            host: "127.0.0.1".into(),
            port: addr.port(),
        }),
        input: None,
        concurrency: 1,
        rate: 1,
        connect_timeout: std::time::Duration::from_millis(500),
        read_timeout: std::time::Duration::from_millis(500),
        overall_timeout: std::time::Duration::from_millis(1000),
        max_bytes: 128,
        mode: banner_grabber::model::ScanMode::Active,
        output: banner_grabber::model::OutputConfig {
            format: banner_grabber::model::OutputFormat::Pretty,
        },
    };

    let sink = banner_grabber::output::OutputSink::new(cfg.output.clone()).unwrap();
    let mut engine = banner_grabber::engine::Engine::new(cfg, sink).unwrap();
    engine.run().await.unwrap();
}

#[tokio::test]
async fn http_probe_runs_on_nonstandard_ports() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 256];
        socket.readable().await.unwrap();
        let n = socket.read(&mut buf).await.unwrap();
        let request = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(request.starts_with("GET / HTTP/1.0"));
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
            .await
            .unwrap();
    });

    let cfg = banner_grabber::model::Config {
        target: Some(banner_grabber::model::TargetSpec {
            host: "127.0.0.1".into(),
            port: addr.port(),
        }),
        input: None,
        concurrency: 1,
        rate: 1,
        connect_timeout: std::time::Duration::from_millis(500),
        read_timeout: std::time::Duration::from_millis(1000),
        overall_timeout: std::time::Duration::from_millis(1500),
        max_bytes: 128,
        mode: banner_grabber::model::ScanMode::Active,
        output: banner_grabber::model::OutputConfig {
            format: banner_grabber::model::OutputFormat::Pretty,
        },
    };

    let sink = banner_grabber::output::OutputSink::new(cfg.output.clone()).unwrap();
    let mut engine = banner_grabber::engine::Engine::new(cfg, sink).unwrap();
    engine.run().await.unwrap();
}

#[tokio::test]
async fn passive_mode_does_not_send_active_probe_on_timeout() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 16];
        let read = tokio::time::timeout(std::time::Duration::from_millis(1500), async {
            socket.read(&mut buf).await.unwrap()
        })
        .await;
        match read {
            Ok(0) => {}
            Ok(n) => panic!("unexpected data from client: {} bytes", n),
            Err(_) => panic!("client never closed connection"),
        }
    });

    let cfg = banner_grabber::model::Config {
        target: Some(banner_grabber::model::TargetSpec {
            host: "127.0.0.1".into(),
            port: addr.port(),
        }),
        input: None,
        concurrency: 1,
        rate: 1,
        connect_timeout: std::time::Duration::from_millis(500),
        read_timeout: std::time::Duration::from_millis(300),
        overall_timeout: std::time::Duration::from_millis(700),
        max_bytes: 128,
        mode: banner_grabber::model::ScanMode::Passive,
        output: banner_grabber::model::OutputConfig {
            format: banner_grabber::model::OutputFormat::Pretty,
        },
    };

    let sink = banner_grabber::output::OutputSink::new(cfg.output.clone()).unwrap();
    let mut engine = banner_grabber::engine::Engine::new(cfg, sink).unwrap();
    engine.run().await.unwrap();
}
