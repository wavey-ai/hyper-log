use hyper_log::HyperLog;
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr};
use std::sync::Arc;
use structopt::StructOpt;
use tcp_changes::Server;
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tokio::sync::mpsc::UnboundedSender;
use tracing::{error, info};
use tracing_subscriber::{fmt, prelude::*, registry::Registry, EnvFilter};

#[derive(Debug, StructOpt)]
#[structopt(name = "hyper-log")]
struct Command {
    #[structopt(long, default_value = "4449", env = "SSL_PORT")]
    ssl_port: u16,

    #[structopt(long, env = "FULLCHAIN_PEM")]
    fullchan_pem: String,

    #[structopt(long, env = "CERT_PEM")]
    cert_pem: String,

    #[structopt(long, env = "PRIVKEY_PEM")]
    privkey_pem: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = Command::from_args();
    let ssl_port = args.ssl_port;
    let cert_pem = args.cert_pem;
    let privkey_pem = args.privkey_pem;
    let fullchain_pem = args.fullchan_pem;

    let socket_v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 4243);
    let subscriber = tracing_subscriber::registry()
        .with(EnvFilter::new("info"))
        .with(tracing_subscriber::fmt::Layer::default());

    tracing::subscriber::set_global_default(subscriber)
        .expect("failed to set global default subscriber");

    let server = HyperLog::new(
        fullchain_pem.clone(),
        cert_pem.clone(),
        privkey_pem.clone(),
        ssl_port,
    );

    let (up, fin, shutdown) = server.start(vec![socket_v4]).await.unwrap();

    fin.await;

    Ok(())
}
