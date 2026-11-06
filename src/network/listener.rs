use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info, warn};

use crate::config::ProxyConfig;
use crate::network::connection::handle_connection;
use crate::proxy::Proxy;

pub async fn run(config: Arc<ProxyConfig>, proxy: Arc<Proxy>) -> Result<()> {
    let addr: SocketAddr = config.bind_addr()?;
    let listener = TcpListener::bind(addr).await?;
    info!(%addr, "RustProxy listener started");

    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                // DDoS: проверка лимита соединений на IP
                if !proxy.ddos.check_connection(peer.ip()) {
                    warn!(%peer, "DDoS: соединение отклонено (rate limit / ban)");
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                    continue;
                }

                let config = Arc::clone(&config);
                let proxy = Arc::clone(&proxy);
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, peer, config, proxy).await {
                        warn!(%peer, "соединение закрыто с ошибкой: {e:#}");
                    }
                });
            }
            Err(e) => {
                error!(error = %e, "tcp accept failed");
            }
        }
    }
}
