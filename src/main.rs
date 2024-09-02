use discovery::{dns::discover, vlan};
use hyper_log::HyperLog;
use std::collections::HashSet;
use std::env;
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
    #[structopt(long, default_value = "4433")]
    ssl_port: u16,

    #[structopt(long, default_value = "4243")]
    tcp_port: u16,

    #[structopt(long, env = "FULLCHAIN_PEM")]
    fullchain_pem: String,

    #[structopt(long, env = "CERT_PEM")]
    cert_pem: String,

    #[structopt(long, env = "PRIVKEY_PEM")]
    privkey_pem: String,

    #[structopt(long)]
    domain: String,

    #[structopt(long)]
    prefix: String,

    #[structopt(long)]
    tags: String,

    #[structopt(long, default_value = "8.8.8.8:53")]
    dns_server: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    const ENV_FILE: &str = include_str!("../.env");

    for line in ENV_FILE.lines() {
        if let Some((key, value)) = line.split_once('=') {
            env::set_var(key.trim(), value.trim());
        }
    }

    let args = Command::from_args();
    let ssl_port = args.ssl_port;
    let cert_pem = args.cert_pem;
    let privkey_pem = args.privkey_pem;
    let fullchain_pem = args.fullchain_pem;
    let prefix = args.prefix;
    let domain = args.domain;

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

    let dns_server: SocketAddr = args.dns_server.parse()?;
    let tags: Vec<String> = args.tags.split(',').map(|s| s.to_string()).collect();
    let (up_rx, fin_rx, shutdown_rx, nodes) =
        discover(vec![], dns_server, domain.clone(), prefix.clone(), tags)
            .await
            .unwrap();

    let _ = up_rx.await;

    let (up, fin, shutdown, rx) = server.start().await.unwrap();

    for node in &nodes.all() {
        let prefix = prefix.clone();
        let domain = domain.clone();
        let domain = format!(
            "{}-{}-{}.{}",
            prefix,
            node.tag().unwrap_or(&"missing".to_string()),
            node.seq().unwrap_or(0),
            domain
        );

        rx.send((domain, node.addr(args.tcp_port))).await;
    }

    while let Ok(node) = nodes.rx().recv().await {
        let prefix = prefix.clone();
        let domain = domain.clone();
        let domain = format!(
            "{}-{}-{}.{}",
            prefix,
            node.tag().unwrap_or(&"missing".to_string()),
            node.seq().unwrap_or(0),
            domain
        );

        rx.send((domain, node.addr(args.tcp_port))).await;
    }

    fin.await;

    Ok(())
}
