use anyhow::{Context, Result};
use bytes::Bytes;
use h3::{
    quic::{self, RecvDatagramExt, SendDatagramExt, SendStreamUnframed},
    server::Connection,
};
use http::{Method, Response, StatusCode};
use http_body_util::{Full, StreamBody};
use hyper::body::Frame;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::Request;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tcp_changes::{Client, Payload};
use tls_helpers::{certs_from_base64, privkey_from_base64, tls_acceptor_from_base64};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio::time::{interval, timeout, Duration};
use tokio_stream::wrappers::ReceiverStream;
use tracing::{error, info};

pub struct HyperLog {
    fullchain_pem_base64: String,
    cert_pem_base64: String,
    privkey_pem_base64: String,
    ssl_port: u16,
}

impl HyperLog {
    pub fn new(
        fullchain_pem_base64: String,
        cert_pem_base64: String,
        privkey_pem_base64: String,
        ssl_port: u16,
    ) -> Self {
        Self {
            fullchain_pem_base64,
            cert_pem_base64,
            privkey_pem_base64,
            ssl_port,
        }
    }

    pub async fn start(
        &self,
    ) -> Result<
        (
            oneshot::Receiver<()>,
            oneshot::Receiver<()>,
            watch::Sender<()>,
            mpsc::Sender<(String, SocketAddr)>,
        ),
        Box<dyn std::error::Error + Send + Sync>,
    > {
        let (shutdown_tx, mut shutdown_rx) = watch::channel(());
        let (up_tx, up_rx) = oneshot::channel();
        let (fin_tx, fin_rx) = oneshot::channel();

        let (log_tx, _) = broadcast::channel::<(String, Payload)>(1024);
        let (new_client_tx, mut new_client_rx) = mpsc::channel::<(String, SocketAddr)>(100);

        let clients = Arc::new(Mutex::new(HashMap::new()));

        let fullchain = self.fullchain_pem_base64.to_owned();

        // Listen for new (domain, socket) tuples.
        let clients_handler = {
            let mut shutdown_signal = shutdown_rx.clone();
            let log_tx_clone = log_tx.clone();
            let clients = Arc::clone(&clients);

            async move {
                loop {
                    tokio::select! {
                        Some((domain, socket)) = new_client_rx.recv() => {
                            info!("adding domain {} with ip {}", domain, socket.ip());
                            let clients = Arc::clone(&clients);
                            {
                                let lock = clients.lock().await;
                                if lock.contains_key(&socket) {
                                    info!("Client already exists for socket: {}", socket);
                                    continue;
                                }
                            }

                            // Create a new MB client for the received domain and socket.
                            let mb = Client::new(domain.clone(), socket, fullchain.to_owned());
                            let (mut up_tcp, fin_tcp, mut shutdown_tcp, mut rx) = mb.start("HELLO").await.unwrap();
                            {
                                let mut lock = clients.lock().await;
                                lock.insert(socket, (shutdown_tcp.clone(), domain.clone()));
                            }
                            let tx_clone = log_tx_clone.clone();
                            tokio::spawn(async move {
                                while let Some(msg) = rx.recv().await {
                                    tx_clone.send((domain.clone(), msg)).ok();
                                }
                            });

                            let clients = Arc::clone(&clients);
                            // Check if the client becomes unreachable.
                            tokio::spawn(async move {
                                let mut heartbeat_interval = interval(Duration::from_secs(10));
                                loop {
                                    tokio::select! {
                                        _ = heartbeat_interval.tick() => {
                                            // Attempt to receive from the `oneshot::Receiver` with a timeout.
                                            let res = timeout(Duration::from_secs(60), &mut up_tcp).await;

                                            // Check if the timeout occurred or if the result indicates an error
                                            if let Err(_) | Ok(Err(_)) = res {
                                                error!("Client is unreachable: {}", socket);
                                                let _ = shutdown_tcp.send(());
                                                {
                                                    let mut lock = clients.lock().await;
                                                    lock.remove(&socket);
                                                }
                                                break;
                                            }
                                        }
                                    }
                                }
                            });

                        }
                        _ = shutdown_signal.changed() => {
                            break;
                        }
                    }
                }
            }
        };

        tokio::spawn(clients_handler);

        let addr = SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), self.ssl_port);
        let tls_acceptor =
            tls_acceptor_from_base64(&self.cert_pem_base64, &self.privkey_pem_base64, true, false)?;

        let ssl_port = self.ssl_port.clone();
        let srv_h1 = {
            let mut shutdown_signal = shutdown_rx.clone();
            let tx_clone = log_tx.clone();
            async move {
                let addr = SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), ssl_port);
                let incoming = TcpListener::bind(&addr).await.unwrap();
                let service =
                    service_fn(move |req| handle_request_h1(req, tx_clone.clone(), ssl_port));

                loop {
                    tokio::select! {
                            _ = shutdown_signal.changed() => {
                                break;
                            }
                            result = incoming.accept() => {
                                let (tcp_stream, _remote_addr) = result.unwrap();
                                let tls_acceptor = tls_acceptor.clone();
                                let service = service.clone();

                                tokio::spawn(async move {
                                    let tls_stream = match tls_acceptor.accept(tcp_stream).await {
                                        Ok(tls_stream) => tls_stream,
                                        Err(err) => {
                                            eprintln!("failed to perform tls handshake: {err:#}");
                                            return;
                                        }
                                    };
                                    if let Err(err) = http1::Builder::new()
                                        .serve_connection(TokioIo::new(tls_stream), service)
                                        .await
                                    {
                                        println!("Error serving connection: {:?}", err);

                                    }
                            });
                        }
                    }
                }
            }
        };

        tokio::spawn(srv_h1);

        let endpoint = {
            let certs = certs_from_base64(&self.cert_pem_base64)?;
            let key = privkey_from_base64(&self.privkey_pem_base64)?;
            let mut tls_config = rustls::ServerConfig::builder()
                .with_safe_default_cipher_suites()
                .with_safe_default_kx_groups()
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .unwrap();

            tls_config.max_early_data_size = u32::MAX;
            let alpn: Vec<Vec<u8>> = vec![b"h3".to_vec()];
            tls_config.alpn_protocols = alpn;

            let server_config = quinn::ServerConfig::with_crypto(Arc::new(tls_config));
            quinn::Endpoint::server(server_config, addr).unwrap()
        };

        let srv = {
            let mut shutdown_signal = shutdown_rx.clone();
            let tx_clone = log_tx.clone();
            async move {
                loop {
                    tokio::select! {
                        _ = shutdown_signal.changed() => {
                            break;
                        }
                        res = endpoint.accept() => {
                            if let Some(new_conn) = res {
                                info!("New connection being attempted");

                                let tx_clone = tx_clone.clone();
                                tokio::spawn(async move {
                                    match new_conn.await {
                                        Ok(conn) => {
                                            let h3_conn = h3::server::builder()
                                                .build(h3_quinn::Connection::new(conn))
                                                .await
                                                .unwrap();

                                            tokio::spawn(async move {
                                                if let Err(err) = handle_connection(h3_conn, tx_clone).await {
                                                    error!("Failed to handle connection: {err:?}");
                                                }
                                            });

                                        }
                                        Err(err) => {
                                            error!("accepting connection failed: {:?}", err);
                                        }

                                    }
                                });
                            }
                        }
                    }
                }
            }
        };

        tokio::spawn(srv);

        tokio::spawn(async move {
            let _ = up_tx.send(());
        });

        let clients = Arc::clone(&clients);
        tokio::spawn(async move {
            let _ = shutdown_rx.changed().await;
            let mut clients = clients.lock().await;
            for (_, shutdown_tcp) in clients.drain() {
                let _ = shutdown_tcp.0.send(());
            }
            fin_tx.send(()).unwrap();
        });

        Ok((up_rx, fin_rx, shutdown_tx, new_client_tx))
    }
}

type Data = Result<Frame<Bytes>, Infallible>;
type ResponseBody = StreamBody<ReceiverStream<Data>>;

async fn handle_request_h1(
    req: Request<impl hyper::body::Body>,
    tcp_tx: broadcast::Sender<(String, Payload)>,
    ssl_port: u16,
) -> Result<Response<ResponseBody>, Infallible> {
    let uri = req.uri().clone();
    let query_params = uri.query().unwrap_or("");
    let t_seconds: Option<u64> = query_params.split('&').find_map(|param| {
        let mut parts = param.split('=');
        if parts.next() == Some("t") {
            parts.next()?.parse().ok()
        } else {
            None
        }
    });

    let mut tcp_rx = tcp_tx.subscribe();

    let (tx, rx) = mpsc::channel::<Data>(10);
    let mut heartbeat_interval = interval(Duration::from_secs(30));
    let time_elapsed: Duration = Duration::from_secs(0);

    tokio::spawn(async move {
        let mut time_elapsed = Duration::from_secs(0);

        loop {
            tokio::select! {
                _ = heartbeat_interval.tick() => {
                    let heartbeat_message = format!(
                        "heartbeat {}\n",
                        SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .expect("time error")
                            .as_secs()
                    );
                    if tx
                        .send(Ok(Frame::data(Bytes::from(heartbeat_message))))
                        .await
                        .is_err()
                    {
                        break;
                    }

                    if let Some(t) = t_seconds {
                        if time_elapsed >= Duration::from_secs(t) {
                            break;
                        }
                    }
            }
                Ok(msg) = tcp_rx.recv() => {
                    let data = prepend_tag(msg.0, msg.1.val);
                    let  _ = tx.send(Ok(Frame::data(Bytes::from(data)))).await;
                    let  _ = tx.send(Ok(Frame::data(Bytes::from(&b"\n"[..])))).await;
                }
            }
        }
    });

    let stream = ReceiverStream::new(rx);
    let body = StreamBody::new(stream);

    let result = Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/plain")
        .header("transfer-encoding", "chunked")
        .header(
            "alt-srv",
            format!("h3=\":{}\"; ma=3600; persist=1", ssl_port),
        )
        .body(body)
        .unwrap());
    result
}

async fn handle_connection(
    mut conn: Connection<h3_quinn::Connection, Bytes>,
    mut tx: broadcast::Sender<(String, Payload)>,
) -> Result<()> {
    loop {
        match conn.accept().await {
            Ok(Some((req, mut stream))) => {
                return match req.method() {
                    &Method::GET => {
                        let response = http::Response::builder()
                            .status(StatusCode::OK)
                            .header("content-type", "text/event-stream")
                            .body(())?;

                        match stream.send_response(response).await {
                            Ok(_) => {}
                            Err(err) => {
                                error!("unable to send response to connection peer: {:?}", err);
                            }
                        }

                        let mut heartbeat_interval = interval(Duration::from_secs(1));
                        let time_elapsed: Duration = Duration::from_secs(0);
                        let mut rx = tx.subscribe();
                        loop {
                            tokio::select! {
                                _ = heartbeat_interval.tick() => {
                                    let heartbeat_message = Bytes::from(format!("heartbeat {}\n", SystemTime::now().duration_since(UNIX_EPOCH).expect("time error").as_secs()));
                                    if let Err(err) = stream.send_data(heartbeat_message.clone()).await {
                                        error!("Failed to send heartbeat: {:?}", err);
                                        break;
                                    }
                                }
                                Ok(msg) = rx.recv() => {
                                    let data = prepend_tag(msg.0, msg.1.val);
                                    if let Err(err) = stream.send_data(data).await {
                                        error!("Failed to send data: {:?}", err);
                                        break;
                                    }
                                }
                            }
                        }

                        Ok(())
                    }
                    _ => Ok(()),
                }
            }
            Ok(None) => {
                break;
            }
            Err(err) => {
                error!("error on accept {}", err);
                break;
            }
        }
    }

    Ok(())
}

fn prepend_tag(tag: String, data: Bytes) -> Bytes {
    let mut msg_bytes = tag.into_bytes();
    msg_bytes.push(b' ');
    let mut new_data = msg_bytes;
    new_data.extend_from_slice(&data);
    new_data.into()
}
