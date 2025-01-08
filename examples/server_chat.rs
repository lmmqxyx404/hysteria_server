use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use anyhow::Context;
use bytes::{Bytes, BytesMut};
use http::{Request, Response, StatusCode};
use hysteria_server::tls::load_pem;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use structopt::StructOpt;
use tokio::{fs::File, io::AsyncReadExt};
use tracing::{error, info, trace_span};

use h3::{error::ErrorLevel, quic::BidiStream, server::RequestStream};
use h3_quinn::quinn::{self, crypto::rustls::QuicServerConfig};

// ------------------- CLI/配置项 -------------------
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
        default_value = "[::1]:4433",
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
    let (certs, key) = load_pem(&opt.certs.cert, &opt.certs.key)?;

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    tls_config.max_early_data_size = u32::MAX;
    tls_config.alpn_protocols = vec![ALPN.into()];

    // 构建 quinn 服务端
    let server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls_config)?));
    let endpoint = quinn::Endpoint::server(server_config, opt.listen)?;
    info!("listening on {}", opt.listen);

    // 存放“当前连接是否已通过 Hysteria 认证”的标记
    // 在本示例里，每条新建连接都会走一次 new_conn.await -> handle
    // 因此这个标记应当放到“连接级别”而非“全局”
    // （但此处为了示例，写在最外层也行，每个连接都拿一个新的Arc<Mutex<bool>>）
    while let Some(new_conn) = endpoint.accept().await {
        trace_span!("New connection being attempted");

        let root_dir = root.clone();

        tokio::spawn(async move {
            match new_conn.await {
                Ok(conn) => {
                    info!("new connection established");
                    // 用 h3::server::Connection 来管理 HTTP/3 流
                    let mut h3_conn =
                        match h3::server::Connection::new(h3_quinn::Connection::new(conn.clone())).await {
                            Ok(h3c) => h3c,
                            Err(e) => {
                                error!("Error during HTTP/3 handshake: {:?}", e);
                                return;
                            }
                        };

                    // 每条连接独有的“是否认证通过”标记
                    let authed_conn = Arc::new(tokio::sync::Mutex::new(false));
                    let conn = conn.clone();
                    let pclone=authed_conn.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_conn(conn.clone(), pclone).await {
                            error!("handling request failed: {}", e);
                        }
                    });
                    // let asd: quinn::Connection = h3_conn.inner.conn.into();
                    // 不断接受新的 HTTP/3 请求
                    loop {
                        match h3_conn.accept().await {
                            Ok(Some((req, stream))) => {
                                info!("new request: {:#?} {}", req, req.uri().path());

                                let root_dir = root_dir.clone();
                                let authed_conn = authed_conn.clone();

                                tokio::spawn(async move {
                                    if let Err(e) =
                                        handle_request(req, stream, root_dir, authed_conn).await
                                    {
                                        error!("handling request failed: {}", e);
                                    }
                                });
                            }

                            // 没有更多请求了，客户端关闭了流
                            Ok(None) => {
                                break;
                            }

                            // 出现了 HTTP/3 协议错误
                            Err(err) => {
                                error!("error on accept: {}", err);
                                match err.get_error_level() {
                                    ErrorLevel::ConnectionError => break,
                                    ErrorLevel::StreamError => continue,
                                }
                            }
                        }
                    }
                }
                Err(err) => {
                    error!("accepting connection failed: {:?}", err);
                }
            }
        });
    }

    // 优雅关闭
    endpoint.wait_idle().await;
    Ok(())
}

/// 判断是否为 Hysteria 验证请求
fn is_hysteria_auth_request(req: &Request<()>) -> bool {
    // 这里简单判断 PATH 是否 "/hysteria-auth"
    // 你也可以更灵活地看 Host, Method, Headers, etc.
    let res = req.method() == http::Method::POST && req.uri().path() == "/auth";
    info!("res is {res}");
    return true;
}

fn do_auth() -> bool {
    true
}

/// 处理每个 HTTP/3 请求:
/// - 如果是 /hysteria-auth, 做认证
/// - 如果已认证 && path=/tcp, 进行TCP隧道（演示）
/// - 否则按文件服务器逻辑处理
async fn handle_request<T>(
    req: Request<()>,
    mut stream: RequestStream<T, Bytes>,
    serve_root: Arc<Option<PathBuf>>,
    authed_conn: Arc<tokio::sync::Mutex<bool>>,
) -> Result<(), Box<dyn std::error::Error>>
where
    T: BidiStream<Bytes>,
{
    info!("started handle request");
    let mut guard = authed_conn.lock().await;
    let is_authed = *guard;

    // ================ 1. 若是 Hysteria 认证请求 ================
    if is_hysteria_auth_request(&req) {
        if do_auth() {
            // 认证成功 -> 记录在这个连接的标记上
            *guard = true;
            drop(guard); // 解锁

            // 返回 233 (HyOK) 状态码 + Hysteria-UDP/Hysteria-CC-RX 等头
            let resp = Response::builder()
                .status(StatusCode::from_u16(233).unwrap())
                .header("Hysteria-UDP", "true")
                .header("Hysteria-CC-RX", "auto")
                .header("Hysteria-Padding", "random-or-whatever")
                .body(())
                .unwrap();

            stream.send_response(resp).await?;
            info!("Hysteria auth success: responded 233");
            return Ok(stream.finish().await?);
        } else {
            // 验证失败
            let resp = Response::builder().status(403).body(()).unwrap();
            stream.send_response(resp).await?;
            info!("Hysteria auth fail: responded 403");
            return Ok(stream.finish().await?);
        }
    }

    // ================ 2. 如果连接已认证 && path = "/tcp" => 做TCP隧道 ================
    // 这只是一个演示：客户端可以在已经认证后发送 `POST /tcp` 并带上要连接的目标
    // （比如 X-Target: example.com:80）来请求代理
    if is_authed {
        info!("prepare to deal with accepted data");
        let (send, mut recv) = stream.split();
        match recv.recv_data().await {
            Ok(res) => {
                let res = res.unwrap();
                // res.into()
                // println!("")
                // let asd = res.into();
                // info!("res is {:?}", asd);
                todo!()
            }
            Err(e) => return Err(Box::new(e)),
        }
        /* let target = match req.headers().get("X-Target") {
            Some(h) => h.to_str().unwrap_or_default(),
            None => {
                // 缺少目标，就返回400
                let resp = Response::builder().status(400).body(()).unwrap();
                stream.send_response(resp).await?;
                return Ok(stream.finish().await?);
            }
        };

        let resp = Response::builder().status(StatusCode::OK).body(()).unwrap();
        let mut send_stream = stream.send_response(resp).await?; */

        // 准备与目标服务器建立 TCP 连接
        /* match tokio::net::TcpStream::connect(target).await {
            Ok(remote_tcp) => {
                // 分割成读写
                let (mut remote_r, mut remote_w) = tokio::io::split(remote_tcp);

                // h3::server::RequestStream split:
                // - req_body (client -> server) =>  stream.body_mut()
                // - resp_body (server -> client) => send_stream
                // 但 h3 不像 HTTP/1/2 那样可无限写 response body，需要注意
                // 这里只是示例，展示思路
                let (mut req_body, mut resp_body) = stream.split();

                // 并行复制
                let client_to_tcp = tokio::io::copy(&mut req_body, &mut remote_w);
                let tcp_to_client = tokio::io::copy(&mut remote_r, &mut send_stream);

                let (res1, res2) = tokio::join!(client_to_tcp, tcp_to_client);
                if let Err(e) = res1 {
                    error!("Error copying client->TCP: {:?}", e);
                }
                if let Err(e) = res2 {
                    error!("Error copying TCP->client: {:?}", e);
                }

                info!("TCP bridging finished for target: {}", target);
                // 最后 finish
                send_stream.finish().await?;
            }
            Err(e) => {
                error!("Failed to connect target {}: {:?}", target, e);
                let resp = Response::builder().status(502).body(()).unwrap();
                stream.send_response(resp).await?;
                stream.finish().await?;
            }
        }
        return Ok(()); */
    }

    drop(guard); // 解锁

    // ================ 3. 否则走原先的“文件服务器/静态资源”逻辑 ================
    let (status, file_to_serve) = match serve_root.as_deref() {
        None => (StatusCode::OK, None),
        Some(root) => {
            if req.uri().path().contains("..") {
                // 简单防止跨目录
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

    Ok(())
}

async fn handle_conn(
    conn: quinn::Connection,
    state: Arc<tokio::sync::Mutex<bool>>,
) -> Result<(), Box<dyn std::error::Error>> {
    todo!()
}
