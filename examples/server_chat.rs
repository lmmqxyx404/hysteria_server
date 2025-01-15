use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::Context;
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use hysteria_server::tls::load_pem;

use structopt::StructOpt;
use tokio::{fs::File, io::AsyncWriteExt};
use tracing::{error, info};

use h3::{error::ErrorLevel, quic::BidiStream, server::RequestStream};
use h3_quinn::quinn::{self, crypto::rustls::QuicServerConfig};

#[derive(StructOpt, Debug)]
#[structopt(name = "server")]
struct Opt {
    /// 根目录，不指定则返回一个固定 OK
    #[structopt(
        name = "dir",
        short,
        long,
        help = "Root directory of the files to serve. \
                If omitted, server will respond OK."
    )]
    pub root: Option<PathBuf>,

    /// 监听地址，默认 [::1]:4433
    #[structopt(
        short,
        long,
        // note: 注意这是一个 IPv6 地址，如果你的系统不支持 IPv6，可以改成 IPv4 地址
        // default_value = "[::1]:4433",
        default_value = "127.0.0.1:4433",
        help = "What address:port to listen for new connections"
    )]
    pub listen: SocketAddr,

    #[structopt(flatten)]
    pub certs: Certs,
}

#[derive(StructOpt, Debug)]
pub struct Certs {
    /// 证书文件（PEM 或 DER）
    #[structopt(
        long,
        short,
        default_value = "examples/cert.pem",
        help = "Certificate for TLS. If present, `--key` is mandatory."
    )]
    pub cert: PathBuf,

    /// 私钥文件（PEM 或 DER）
    #[structopt(
        long,
        short,
        default_value = "examples/key.pem",
        help = "Private key for the certificate."
    )]
    pub key: PathBuf,
}

static ALPN: &[u8] = b"h3";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::FULL)
        .with_writer(std::io::stderr)
        .with_max_level(tracing::Level::INFO)
        .init();

    // 解析命令行参数
    let opt = Opt::from_args();

    // 如果有 --dir，则作为静态文件目录；否则为 None
    let root = if let Some(r) = opt.root {
        if !r.is_dir() {
            return Err(format!("{}: is not a readable directory", r.display()).into());
        } else {
            info!("serving {}", r.display());
            Arc::new(Some(r))
        }
    } else {
        Arc::new(None)
    };

    // 加载证书和私钥
    let (certs, key) =
        load_pem(&opt.certs.cert, &opt.certs.key).context("failed to load cert or key")?;

    // 构建 TLS 配置
    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?; // 这里 certs 类型通常是 Vec<rustls::Certificate>
    tls_config.max_early_data_size = u32::MAX;
    tls_config.alpn_protocols = vec![ALPN.into()];

    // 构建 quinn 服务端
    let server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls_config)?));
    let endpoint = quinn::Endpoint::server(server_config, opt.listen)?;
    info!("listening on {}", opt.listen);

    // 不断接受新的 QUIC 连接
    while let Some(new_conn) = endpoint.accept().await {
        let root_for_conn = root.clone();

        tokio::spawn(async move {
            match new_conn.await {
                Ok(conn) => {
                    info!("new connection established: {:?}", conn.remote_address());

                    // 对每个连接，都并行处理:
                    // 1) HTTP/3 请求
                    // 2) 原生 QUIC bidirectional 流
                    if let Err(e) = handle_connection(conn, root_for_conn).await {
                        error!("connection handler error: {}", e);
                    }
                }
                Err(err) => {
                    error!("accepting connection failed: {:?}", err);
                }
            }
        });
    }

    endpoint.wait_idle().await;
    Ok(())
}

/// 在同一个 quinn::Connection 上，同时处理：
/// - HTTP/3 协议 (handle_http3)
/// - 原生 QUIC 双向流 (handle_raw_bi)
async fn handle_connection(
    conn: quinn::Connection,
    root: Arc<Option<PathBuf>>,
) -> Result<(), Box<dyn std::error::Error>> {
    // 分别 spawn 两个任务并发跑
    let conn_for_h3 = conn.clone();
    let root_for_h3 = root.clone();

    // 每个连接独有的“是否已认证”标记
    let authed_conn = Arc::new(tokio::sync::Mutex::new(false));
    let asd = authed_conn.clone();
    let (tx_authed, mut rx_authed) = tokio::sync::mpsc::channel::<bool>(100);

    let h3_handle = tokio::spawn(async move {
        info!("handled in h3_handle");
        if let Err(e) = handle_http3(conn_for_h3, root_for_h3, tx_authed).await {
            error!("HTTP/3 handling error: {}", e);
        }
    });

    let conn_for_raw = conn.clone();
    let qwe = authed_conn.clone();

    match rx_authed.recv().await {
        Some(true) => {
            // 客户端已经认证成功了 -> 再启动 handle_raw_bi
            info!("connection is authed, now handle raw QUIC streams");
            let authed_for_raw = authed_conn.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_raw_bi(conn, authed_for_raw).await {
                    error!("Raw QUIC handling error: {}", e);
                }
            });
        }
        Some(false) => {
            // 客户端认证失败 或者 handle_http3 里没有发信号就退出
            info!("no raw QUIC will be handled, because not authed");
        }
        None => {
            info!("can not accept anything");
        }
    };

    /* let raw_handle = tokio::spawn(async move {
        info!("handled in raw_handle");
        if let Err(e) = handle_raw_bi(conn_for_raw, qwe).await {
            error!("Raw QUIC handling error: {}", e);
        }
    }); */

    // 等待二者结束（正常情况下 HTTP/3 不会轻易退出，除非连接被关闭）
    // let _ = tokio::join!(h3_handle, raw_handle);
    Ok(())
}

/// 处理 HTTP/3 协议：构造 h3::server::Connection，循环 accept() HTTP/3 请求
async fn handle_http3(
    conn: quinn::Connection,
    root_dir: Arc<Option<PathBuf>>,
    tx_authed: tokio::sync::mpsc::Sender<bool>,
) -> Result<(), Box<dyn std::error::Error>> {
    // 初始化 h3::server::Connection
    info!("some thing occured");
    let mut h3_conn = match h3::server::Connection::new(h3_quinn::Connection::new(conn)).await {
        Ok(h3c) => h3c,
        Err(e) => {
            error!("Error during HTTP/3 handshake: {:?}", e);
            return Err(e.into());
        }
    };
    // if let Some(tx) = tx_authed.take() {

    // 不断接受新的 HTTP/3 请求
    loop {
        match h3_conn.accept().await {
            Ok(Some((req, stream))) => {
                info!(
                    "new HTTP/3 request: {} {:?}",
                    req.uri().path(),
                    req.method()
                );

                let root_for_req = root_dir.clone();
                // let authed_conn_for_req = authed_conn.clone();
                // 每个请求丢进一个任务单独处理
                // **仅在第一次请求时发送 tx_authed**

                if let Err(e) = handle_request(req, stream, root_for_req, tx_authed.clone()).await {
                    error!("handling request failed: {}", e);
                }
            }
            Ok(None) => {
                // 没有更多请求了，对端关闭了 HTTP/3 连接
                info!("client closed HTTP/3 connection");
                break;
            }
            Err(err) => {
                error!("error on accept H3: {}", err);
                match err.get_error_level() {
                    ErrorLevel::ConnectionError => {
                        // 连接级别错误 -> 退出循环
                        break;
                    }
                    ErrorLevel::StreamError => {
                        // 流级别错误 -> 继续接受下一个请求
                        continue;
                    }
                }
            }
        }
    }

    Ok(())
}

/// 原生 QUIC 双向流处理：循环 accept_bi()，收到数据后转发给指定 TCP 服务器，再把服务器返回数据转给客户端
async fn handle_raw_bi(
    conn: quinn::Connection,
    _authed_conn: Arc<tokio::sync::Mutex<bool>>, // 如果还需要认证，可自行扩展逻辑
) -> Result<(), Box<dyn std::error::Error>> {
    // 不断 accept_bi()，处理多条双向流
    loop {
        match conn.accept_bi().await {
            Ok((wstream, mut rstream)) => {
                info!("(raw QUIC) got a new bidirectional stream");

                // 为每个 QUIC bidirectional stream 启一个任务去转发
                tokio::spawn(async move {
                    // 1) 连接到远程 TCP 服务器
                    let remote_addr = "cp.cloudflare.com:80";
                    match tokio::net::TcpStream::connect(remote_addr).await {
                        Ok(tcp_stream) => {
                            if let Err(e) = bridge_quic_to_tcp(rstream, wstream, tcp_stream).await {
                                error!("bridge error: {}", e);
                            }
                        }
                        Err(e) => {
                            error!("connect to {} failed: {}", remote_addr, e);
                            // 如果需要，可以给客户端发回一个提示或直接关闭。
                        }
                    }
                });
            }
            // 对端把连接关掉
            Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                info!("(raw QUIC) connection closed by peer");
                return Ok(());
            }
            Err(e) => {
                error!("(raw QUIC) accept_bi failed: {}", e);
                return Err(e.into());
            }
        }
    }
}

/// 桥接函数：把 QUIC 的双向流 (rstream, wstream) 与 TCP 流 (tcp_stream) 互相转发
async fn bridge_quic_to_tcp(
    mut rstream: quinn::RecvStream,
    mut wstream: quinn::SendStream,
    tcp_stream: tokio::net::TcpStream,
) -> Result<(), Box<dyn std::error::Error>> {
    // use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // 拆分 TCP 流为读取端、写入端
    let (mut tcp_read, mut tcp_write) = tokio::io::split(tcp_stream);

    // 为了并发转发，可以再拆分成两个方向：
    // 1) client->server: rstream => tcp_write
    // 2) server->client: tcp_read => wstream

    // ============== 1) Client -> Server ==============
    let client_to_server = tokio::spawn(async move {
        if let Err(e) = tokio::io::copy(&mut rstream, &mut tcp_write).await {
            error!("copy from QUIC to TCP failed: {}", e);
        }
        // client 发送完毕/或者发生错误后，shutdown TCP 的写端
        let _ = tcp_write.shutdown().await;
    });

    // ============== 2) Server -> Client ==============
    let server_to_client = tokio::spawn(async move {
        if let Err(e) = tokio::io::copy(&mut tcp_read, &mut wstream).await {
            error!("copy from TCP to QUIC failed: {}", e);
        }
        // 服务器发完毕/或者发生错误后，QUIC 端可 finish
        let _ = wstream.finish();
    });

    // 同时等待两个方向都结束
    let _ = tokio::try_join!(client_to_server, server_to_client)?;
    Ok(())
}

/// 是否是 Hysteria 认证请求 (示例)
fn is_hysteria_auth_request(req: &Request<()>) -> bool {
    // 你自己的判断逻辑，这里简单判断一下
    req.method() == http::Method::POST && req.uri().path() == "/auth"
}

/// 伪造一个 do_auth，用于演示
fn do_auth() -> bool {
    true
}

/// 处理每个 HTTP/3 请求
async fn handle_request<T>(
    req: Request<()>,
    mut stream: RequestStream<T, Bytes>,
    serve_root: Arc<Option<PathBuf>>,
    // authed_conn: Arc<tokio::sync::Mutex<bool>>,
    tx_authed: tokio::sync::mpsc::Sender<bool>,
) -> Result<(), Box<dyn std::error::Error>>
where
    T: BidiStream<Bytes>,
{
    // let mut guard = authed_conn.lock().await;
    // let is_authed = *guard;

    // ========== 1. 如果是 Hysteria 认证 ==========
    if is_hysteria_auth_request(&req) {
        if do_auth() {
            // *guard = true;
            // drop(guard);

            let resp = Response::builder()
                .status(StatusCode::from_u16(233).unwrap())
                .header("Hysteria-UDP", "true")
                .header("Hysteria-CC-RX", "auto")
                .header("Hysteria-Padding", "random-or-whatever")
                .body(())
                .unwrap();
            stream.send_response(resp).await?;
            info!("Hysteria auth success: responded 233");
            // tx_authed.send(true); // 通知外面
            stream.finish().await?;
            return Ok(tx_authed.send(true).await?);
        } else {
            let resp = Response::builder().status(403).body(()).unwrap();
            stream.send_response(resp).await?;
            info!("Hysteria auth fail: responded 403");
            return Ok(stream.finish().await?);
        }
    }

    // ========== 2. 如果已经认证了 && path=/tcp => 做 TCP 隧道 (示例) ==========
    // 此处仅演示，留给你自行扩展
    // if is_authed && req.uri().path() == "/tcp" {
    if req.uri().path() == "/tcp" {
        info!("client wants a TCP tunnel (already authed). you'd do logic here...");
        // 省略：演示如何 echo/或转发
        let resp = Response::builder().status(StatusCode::OK).body(()).unwrap();
        let mut send_stream = stream.send_response(resp).await?;
        // ...
        // 需要后面自己处理 stream.split() -> body 与 send_stream 互相转发
        return Ok(());
    }

    // drop(guard); // 解锁

    // ========== 3. 否则按“文件服务器/静态资源”逻辑处理 ==========
    let (status, file_to_serve) = match serve_root.as_deref() {
        None => (StatusCode::OK, None),
        Some(root) => {
            if req.uri().path().contains("..") {
                (StatusCode::NOT_FOUND, None)
            } else {
                let path = root.join(req.uri().path().trim_start_matches('/'));
                match File::open(&path).await {
                    Ok(f) => (StatusCode::OK, Some(f)),
                    Err(e) => {
                        error!("failed to open {}: {:?}", path.display(), e);
                        (StatusCode::NOT_FOUND, None)
                    }
                }
            }
        }
    };

    let resp = Response::builder().status(status).body(())?;
    let mut send_stream = stream.send_response(resp).await?;

    /* if let Some(mut f) = file_to_serve {
        // 把文件内容一口气写给 response body
        let mut buf = [0u8; 8192];
        loop {
            let n = f.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            send_stream
                .send_data(Bytes::copy_from_slice(&buf[..n]))
                .await?;
        }
    }
    send_stream.finish().await?; */

    Ok(())
}
