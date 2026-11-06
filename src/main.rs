use anyhow::Result;
use clap::Parser;
use config::ProxyConfig;
use proxy::Proxy;
use std::sync::Arc;
use tracing::{info, subscriber};
use tracing_subscriber::{EnvFilter, FmtSubscriber};

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "RustProxy — BungeeCord-like Minecraft proxy on Rust",
    long_about = None
)]
struct Args {
    #[arg(short = 'c', long = "config", default_value = "config.toml")]
    config: String,
}

fn main() -> Result<()> {
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(EnvFilter::from_default_env())
        .finish();
    subscriber::set_global_default(subscriber)?;

    let args = Args::parse();
    let config = Arc::new(ProxyConfig::load(&args.config)?);

    let threads = config.worker_threads();
    info!(threads = %threads, "RustProxy runtime: Tokio multi-thread");

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads)
        .thread_name("rustproxy-worker-")
        .enable_all()
        .build()?;

    runtime.block_on(async move {
        let proxy = Arc::new(Proxy::new(Arc::clone(&config)).await?);
        proxy.run().await
    })
}
