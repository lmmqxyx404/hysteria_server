use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};

use futures::future;
use rustls::pki_types::CertificateDer;
use structopt::StructOpt;
use tokio::io::AsyncWriteExt;
use tracing::{error, info};

use h3_quinn::quinn;

static ALPN: &[u8] = b"h3";

#[derive(StructOpt, Debug)]
#[structopt(name = "server")]
struct Opt {
    #[structopt(
        long,
        short,
        default_value = "examples/ca.cert",
        help = "Certificate of CA who issues the server certificate"
    )]
    pub ca: PathBuf,

    #[structopt(name = "keylogfile", long)]
    pub key_log_file: bool,

    #[structopt(default_value = "https://localhost:4433/cert.pem")]
    pub uri: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::FULL)
        .with_writer(std::io::stderr)
        .with_max_level(tracing::Level::INFO)
        .init();

    let mut opt = Opt::from_args();
    // todo
    // opt.uri = "https://lmmqxyx.us.kg:443".to_string();
    // DNS lookup

    let uri = opt.uri.parse::<http::Uri>()?;

    if uri.scheme() != Some(&http::uri::Scheme::HTTPS) {
        Err("uri scheme must be 'https'")?;
    }

    let auth = uri.authority().ok_or("uri must have a host")?.clone();

    let port = auth.port_u16().unwrap_or(443);

    let addr = tokio::net::lookup_host((auth.host(), port))
        .await?
        .next()
        .ok_or("dns found no addresses")?;
    // let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4433);

    info!("DNS lookup for {:?}: {:?}", uri, addr);

    // create quinn client endpoint

    // load CA certificates stored in the system
    let mut roots = rustls::RootCertStore::empty();
    match rustls_native_certs::load_native_certs() {
        Ok(certs) => {
            for cert in certs {
                if let Err(e) = roots.add(cert) {
                    error!("failed to parse trust anchor: {}", e);
                }
            }
        }
        Err(e) => {
            error!("couldn't load any default trust roots: {}", e);
        }
    };

    // load certificate of CA who issues the server certificate
    // NOTE that this should be used for dev only
    /* if let Err(e) = roots.add(CertificateDer::from(std::fs::read(opt.ca)?)) {
        error!("failed to parse trust anchor: {}", e);
    } */
    let file = std::fs::File::open(std::path::Path::new("examples/cert.pem"))
        .expect(format!("cannot open {}", "examples/cert.pem").as_str());
    let mut br = std::io::BufReader::new(file);
    let cetrs: Vec<CertificateDer<'_>> =
        rustls_pemfile::certs(&mut br).collect::<Result<_, _>>()?;
    let certificate = CertificateDer::from(cetrs[0].clone());

    if let Err(e) = roots.add(certificate) {
        error!("failed to parse trust anchor: {}", e);
    }
    let mut tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    tls_config.enable_early_data = true;
    tls_config.alpn_protocols = vec![ALPN.into()];

    // optional debugging support
    if opt.key_log_file {
        // Write all Keys to a file if SSLKEYLOGFILE is set
        // WARNING, we enable this for the example, you should think carefully about enabling in your own code
        tls_config.key_log = Arc::new(rustls::KeyLogFile::new());
    }

    let mut client_endpoint = h3_quinn::quinn::Endpoint::client("[::]:0".parse().unwrap())?;

    let client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)?,
    ));
    client_endpoint.set_default_client_config(client_config);

    let conn = client_endpoint
        .connect(addr, "hello.world.example")?
        .await?;
    // todo
    // let conn = client_endpoint.connect(addr, auth.host())?.await?;

    info!("QUIC connection established");

    // create h3 client

    // h3 is designed to work with different QUIC implementations via
    // a generic interface, that is, the [`quic::Connection`] trait.
    // h3_quinn implements the trait w/ quinn to make it work with h3.
    let quinn_conn = h3_quinn::Connection::new(conn.clone());

    let (mut driver, mut send_request) = h3::client::new(quinn_conn).await?;

    let drive = async move {
        future::poll_fn(|cx| driver.poll_close(cx)).await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    };

    // In the following block, we want to take ownership of `send_request`:
    // the connection will be closed only when all `SendRequest`s instances
    // are dropped.
    //
    //             So we "move" it.
    //                  vvvv
    let request = async move {
        info!("sending request ...");
        // todo
        // let req = http::Request::builder().uri(uri).body(())?;
        let req = http::Request::post("https://hysteria/auth")
            .header(
                "Hysteria-Auth",
                "ddb573cb-55f8-4d8d-a609-bd444b14b19b:ddb573cb-55f8-4d8d-a609-bd444b14b19b",
            )
            .header("Hysteria-CC-RX", "0")
            .header("Hysteria-Padding", "sssddddffff")
            .body(())
            .unwrap();
        // sending request results in a bidirectional stream,
        // which is also used for receiving response
        let mut stream = send_request.send_request(req).await?;

        // finish on the sending side
        stream.finish().await?;

        info!("receiving response ...");

        let resp = stream.recv_response().await?;

        info!("response: {:?} {}", resp.version(), resp.status());
        info!("headers are : {:#?}", resp.headers());

        // `recv_data()` must be called after `recv_response()` for
        // receiving potential response body
        /* loop {
            match stream.recv_data().await {
                Ok(mut chunk) => {
                    let mut out = tokio::io::stdout();
                    out.write_all_buf(&mut chunk).await?;
                    out.flush().await?;
                }
                Err(e) => return Err(e),
            }
        } */
        /* while let Some(mut chunk) = stream.recv_data().await? {
            let mut out = tokio::io::stdout();
            out.write_all_buf(&mut chunk).await?;
            out.flush().await?;
        } */
        let (mut tx, mut rx) = conn.clone().open_bi().await?;
        // let buf=
        let mut proxy_data = [
            0x48, 0x45, 0x41, 0x44, 0x20, 0x2F, 0x67, 0x65, 0x6E, 0x65, 0x72, 0x61, 0x74, 0x65,
            0x5F, 0x32, 0x30, 0x34, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2F, 0x31, 0x2E, 0x31, 0x0D,
            0x0A, 0x48, 0x6F, 0x73, 0x74, 0x3A, 0x20, 0x63, 0x70, 0x2E, 0x63, 0x6C, 0x6F, 0x75,
            0x64, 0x66, 0x6C, 0x61, 0x72, 0x65, 0x2E, 0x63, 0x6F, 0x6D, 0x0D, 0x0A, 0x55, 0x73,
            0x65, 0x72, 0x2D, 0x41, 0x67, 0x65, 0x6E, 0x74, 0x3A, 0x20, 0x47, 0x6F, 0x2D, 0x68,
            0x74, 0x74, 0x70, 0x2D, 0x63, 0x6C, 0x69, 0x65, 0x6E, 0x74, 0x2F, 0x31, 0x2E, 0x31,
            0x0D, 0x0A, 0x0D, 0x0A,
        ];

        let res = tx.write_all(&proxy_data).await.unwrap();
        info!("dealed with tx and rx");
        /* match rx.read_to_end(1000).await {
            Ok(res) => {
                info!("{:?}", res);
            }
            Err(e) => {
                return Err(e);
            }
        } */
        let mut buf = [0u8; 1024];
        loop {
            match rx.read(&mut buf).await {
                Ok(n) => {
                    // 业务处理
                    if let Some(n) = n {
                        info!("received {} bytes: {:?}", n, &buf[..n]);
                    } else {
                        break;
                    }
                }
                Err(e) => {
                    // 出错就停止
                    error!("bi-stream read error: {}", e);
                    break;
                }
            }
        }
        Ok::<_, Box<dyn std::error::Error>>(())
    };

    let (req_res, drive_res) = tokio::join!(request, drive);
    req_res?;
    drive_res?;

    // wait for the connection to be closed before exiting
    client_endpoint.wait_idle().await;

    Ok(())
}
