use banner_grabber::engine::reader::BannerReader;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

#[tokio::test]
async fn reader_handles_delayed_banner() {
    let mut reader = BannerReader::new(32);
    let mut data: &[u8] = b"hello\r\n";
    let banner = reader.read(&mut data).await.unwrap();
    assert_eq!(banner, b"hello\r\n");
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
