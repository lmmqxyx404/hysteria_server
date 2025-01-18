use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::Context;
use hysteria_server::{connection::handle_connection, tls::load_pem};

use structopt::StructOpt;
use tracing::{error, info};

use h3_quinn::quinn::{self, crypto::rustls::QuicServerConfig};

#[derive(StructOpt, Debug)]
#[structopt(name = "server")]
struct Opt {
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
        // let root_for_conn = root.clone();

        tokio::spawn(async move {
            match new_conn.await {
                Ok(conn) => {
                    info!("new connection established: {:?}", conn.remote_address());

                    // 对每个连接，都并行处理:
                    // 1) HTTP/3 请求
                    // 2) 原生 QUIC bidirectional 流
                    if let Err(e) = handle_connection(conn).await {
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
