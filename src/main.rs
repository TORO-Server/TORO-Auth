use std::sync::Arc;
use std::time::Duration;

use toro_auth::App;
use toro_auth::config::Config;

#[tokio::main]
async fn main() {
    // scratch イメージには curl が無いので、HEALTHCHECK は自分自身で行う
    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        std::process::exit(if healthcheck().await { 0 } else { 1 });
    }

    let cfg = match Config::from_env() {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("config error: {e}");
            std::process::exit(2);
        }
    };
    let (port, internal_port) = (cfg.port, cfg.internal_port);
    let app = Arc::new(App::new(cfg).expect("HTTP client"));

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .expect("bind");
    // api / mcp のトークンの確認を受ける。トンネルにもホストにも公開しない
    let internal_listener = tokio::net::TcpListener::bind(("0.0.0.0", internal_port))
        .await
        .expect("bind internal");
    eprintln!(
        "toro-auth {} listening on :{port} (internal :{internal_port})",
        env!("CARGO_PKG_VERSION")
    );

    let server = axum::serve(listener, toro_auth::routes::router(app.clone()))
        .with_graceful_shutdown(shutdown_signal());
    let internal = axum::serve(internal_listener, toro_auth::internal::router(app))
        .with_graceful_shutdown(shutdown_signal());
    let (server, internal) = tokio::join!(server, internal);
    server.expect("server");
    internal.expect("internal server");
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = term.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}

async fn healthcheck() -> bool {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".into());
    let check = async {
        let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}")).await?;
        stream
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await?;
        let mut head = [0u8; 15];
        stream.read_exact(&mut head).await?;
        Ok::<bool, std::io::Error>(head.starts_with(b"HTTP/1.1 200"))
    };
    matches!(
        tokio::time::timeout(Duration::from_secs(3), check).await,
        Ok(Ok(true))
    )
}
