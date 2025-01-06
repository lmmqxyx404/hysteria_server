// use rustls::ServerConfig;

use std::{
    env,
    fs::{self, File},
    io::BufReader,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{bail, Context, Result};
use quinn::{crypto::rustls::QuicServerConfig, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls_pemfile::pkcs8_private_keys;

/// 简易地生成一个自签证书的 QUIC 服务器配置
pub fn make_server_config() -> anyhow::Result<ServerConfig> {
    // rustls::crypto::init();
    let current_dir = env::current_dir()?;
    println!("当前工作目录: {:?}", current_dir);

    // 示例相对路径
    // let relative_path = Path::new("./basic_config/cert.der");

    let mut cert_path = current_dir.join("./basic_config/cert.pem").canonicalize()?;
    let mut key_path = current_dir.join("./basic_config/key.pem").canonicalize()?;
    cert_path = String::from("E://Rust//hysteria_server//basic_config//cert.pem").into();
    key_path = String::from("E://Rust//hysteria_server//basic_config//key.pem").into();
    println!("{:?} {:?}", cert_path, key_path);

    let (certs, key) = load_pem(&cert_path, &key_path).unwrap();

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    let mut server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto)?));

    Ok(server_config)
}

pub fn load_pem(
    cert_path: &PathBuf,
    key_path: &PathBuf,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let key = fs::read(key_path).context("failed to read private key")?;
    let key = if key_path.extension().is_some_and(|x| x == "der") {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key))
    } else {
        rustls_pemfile::private_key(&mut &*key)
            .context("malformed PKCS #1 private key")?
            .ok_or_else(|| anyhow::Error::msg("no private keys found"))?
    };
    let cert_chain = fs::read(cert_path).context("failed to read certificate chain")?;
    let cert_chain = if cert_path.extension().is_some_and(|x| x == "der") {
        vec![CertificateDer::from(cert_chain)]
    } else {
        rustls_pemfile::certs(&mut &*cert_chain)
            .collect::<Result<_, _>>()
            .context("invalid PEM-encoded certificate")?
    };

    Ok((cert_chain, key))
}

#[test]
fn test_read_file() {
    let cert_path: PathBuf =
        String::from("E://Rust//hysteria_server//basic_config//cert.pem").into();
    let key_path: PathBuf = String::from("E://Rust//hysteria_server//basic_config//key.pem").into();
    let res = load_pem(&cert_path, &key_path).unwrap();
    // assert_eq!(1, asd.len());
    // let res2 = PrivateKeyDer::try_from(asd).unwrap();
}
