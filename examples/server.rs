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

#[derive(StructOpt, Debug)]
#[structopt(name = "server")]
struct Opt {
    #[structopt(
        name = "dir",
        short,
        long,
        help = "Root directory of the files to serve. \
                If omitted, server will respond OK."
    )]
    pub root: Option<PathBuf>,

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
    #[structopt(
        long,
        short,
        // default_value = "examples/server.cert",
        default_value = "examples/cert.pem",
        help = "Certificate for TLS. If present, `--key` is mandatory."
    )]
    pub cert: PathBuf,

    #[structopt(
        long,
        short,
        // default_value = "examples/server.key",
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

    // process cli arguments

    let opt = Opt::from_args();

    let root = if let Some(root) = opt.root {
        if !root.is_dir() {
            return Err(format!("{}: is not a readable directory", root.display()).into());
        } else {
            info!("serving {}", root.display());
            Arc::new(Some(root))
        }
    } else {
        Arc::new(None)
    };

    let Certs { cert, key } = opt.certs;

    // create quinn server endpoint and bind UDP socket

    let (certs, key) = load_pem(&cert, &key).unwrap();

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    tls_config.max_early_data_size = u32::MAX;
    tls_config.alpn_protocols = vec![ALPN.into()];

    let server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls_config)?));
    let endpoint = quinn::Endpoint::server(server_config, opt.listen)?;

    info!("listening on {}", opt.listen);

    // handle incoming connections and requests
    let authed_conn = Arc::new(Mutex::new(false));
    while let Some(new_conn) = endpoint.accept().await {
        trace_span!("New connection being attempted");

        let root = root.clone();
        let authed_clone = authed_conn.clone();

        tokio::spawn(async move {
            match new_conn.await {
                Ok(conn) => {
                    info!("new connection established");
                    let mut h3_conn = h3::server::Connection::new(h3_quinn::Connection::new(conn))
                        .await
                        .unwrap();
                    loop {
                        match h3_conn.accept().await {
                            Ok(Some((req, stream))) => {
                                info!("new request: {:#?} {:#?}", req, req.uri().host().unwrap());

                                let root = root.clone();

                                tokio::spawn(async {
                                    if let Err(e) = handle_request(req, stream, root).await {
                                        error!("handling request failed: {}", e);
                                    }
                                });
                            }

                            // indicating no more streams to be received
                            Ok(None) => {
                                break;
                            }

                            Err(err) => {
                                error!("error on accept {}", err);
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

    // shut down gracefully
    // wait for connections to be closed before exiting
    endpoint.wait_idle().await;

    Ok(())
}

async fn handle_request<T>(
    req: Request<()>,
    mut stream: RequestStream<T, Bytes>,
    serve_root: Arc<Option<PathBuf>>,
) -> Result<(), Box<dyn std::error::Error>>
where
    T: BidiStream<Bytes>,
{
    // let arc = *authed.lock();
    // 1. 首先检查是否为 Hysteria 验证请求
    if is_hysteria_auth_request(&req) {
        // 2. 如果是，进行验证
        if do_auth(&req) {
            // 验证通过，按照文档要求返回 233，带上相应的头部
            let resp = Response::builder()
                // 注意：hyper 本身没有对 233 这个状态码的内置常量，
                // 我们可以用 from_u16 自定义
                .status(StatusCode::from_u16(233).unwrap())
                // 如果你需要包含 reason phrase（如 "HyOK"），可以在 HTTP/1.1 模式下这样做：
                // .status("233 HyOK") 或者在 HTTP/2/3 中就只会展示数字状态码
                .header("Hysteria-UDP", "true") // 示例：服务器支持 UDP relay
                .header("Hysteria-CC-RX", "auto") // 示例：服务器让客户端自行调整接收速率
                .header("Hysteria-Padding", "random") // 可选，随便填点乱数据做混淆
                .body(())?; // Response body 为空即可

            // 发送响应
            match stream.send_response(resp).await {
                Ok(_) => {
                    info!("Hysteria auth success: sent 233 to client");
                }
                Err(err) => {
                    error!("Unable to send Hysteria auth success response: {:?}", err);
                }
            }

            // 根据文档，验证通过后就开始处理代理逻辑，因此此处结束当前请求处理
            return Ok(stream.finish().await?);
        } else {
            // 验证失败：要么像普通 Web 服务器一样返回 404/401/200 等常规响应，
            // 要么在反向代理模式下把请求转发给上游，下边演示直接返回 404。
            let resp = Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(())
                .unwrap();

            match stream.send_response(resp).await {
                Ok(_) => {
                    info!("Hysteria auth failed: responded with 404");
                }
                Err(err) => {
                    error!("Unable to send Hysteria auth failed response: {:?}", err);
                }
            }

            // 结束处理
            return Ok(stream.finish().await?);
        }
    }

    // 如果不是 Hysteria 验证请求，则按原先逻辑处理“文件内容”或其他逻辑
    let (status, to_serve) = match serve_root.as_deref() {
        None => (StatusCode::OK, None),
        Some(_) if req.uri().path().contains("..") => (StatusCode::NOT_FOUND, None),
        Some(root) => {
            let to_serve = root.join(req.uri().path().strip_prefix('/').unwrap_or(""));
            match File::open(&to_serve).await {
                Ok(file) => (StatusCode::OK, Some(file)),
                Err(e) => {
                    error!("failed to open: \"{}\": {}", to_serve.to_string_lossy(), e);
                    (StatusCode::NOT_FOUND, None)
                }
            }
        }
    };

    let resp = Response::builder().status(status).body(())?; // 正常返回空 Body 或可根据情况返回一些头部

    match stream.send_response(resp).await {
        Ok(_) => {
            info!("successfully responded to connection");
        }
        Err(err) => {
            error!("unable to send response to connection peer: {:?}", err);
        }
    }

    // 如果可以打开文件，就流式发送文件内容
    if let Some(mut file) = to_serve {
        loop {
            let mut buf = BytesMut::with_capacity(4096 * 10);
            if file.read_buf(&mut buf).await? == 0 {
                break;
            }
            stream.send_data(buf.freeze()).await?;
        }
    }

    Ok(stream.finish().await?)
}

/// 判断是否为 Hysteria 验证请求的示例逻辑，请自行替换
fn is_hysteria_auth_request(req: &Request<()>) -> bool {
    // 例如，判断路径是否为 "/hysteria-auth" 或者根据 Header 中的某些字段来判断
    req.uri().path() == "/hysteria-auth"
}

/// 执行鉴权的示例逻辑，请自行替换
fn do_auth(req: &Request<()>) -> bool {
    // 例如检查 req.headers() 中是否带有正确的 Token
    // 这里只是模拟一下，返回 true 表示验证通过
    true
}
