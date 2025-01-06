use http::Request;
use hysteria_server::tls::make_server_config;
use rustls::crypto::CryptoProvider;

use std::{net::SocketAddr, sync::Arc};
use tokio::sync::Mutex;

use bytes::Bytes;
use h3::{quic::BidiStream, server};
use h3_quinn::Connection;
// use http::{Request, Response};
use quinn::{Endpoint, ServerConfig};
use rand::distributions::Alphanumeric;
use rand::Rng;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // CryptoProvider::install_default();
    // 1. 创建并启动 QUIC 服务器
    let server_config = make_server_config()?;
    let bind_addr: SocketAddr = "0.0.0.0:4433".parse()?;
    // let (endpoint, mut incoming) = Endpoint::server(server_config, bind_addr)?;
    let endpoint = Endpoint::server(server_config.into(), bind_addr)?;
    println!("Server listening on {}", bind_addr);

    // 设置一个预共享密码(示例)
    let shared_passwd = Arc::new("my-secret".to_string());

    // 2. 接受新的 QUIC 连接，然后交给 handle_connection
    while let Some(conn) = endpoint.accept().await {
        match conn.await {
            Ok(quinn_conn) => {
                let pwd = shared_passwd.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(&quinn_conn, pwd).await {
                        eprintln!("Connection error: {:?}", e);
                    }
                });
            }
            Err(e) => eprintln!("accept error: {:?}", e),
        }
    }

    endpoint.wait_idle().await;
    Ok(())
}

/// 处理每一个 QUIC 连接，并在其上构建 HTTP/3 协议
async fn handle_connection(
    quinn_conn: &quinn::Connection,
    shared_passwd: Arc<String>,
) -> anyhow::Result<()> {
    // 1. 将 quinn 的连接封装为 h3_quinn::Connection
    let h3_conn = h3_quinn::Connection::new(quinn_conn.clone());

    // 2. 构建 HTTP/3 server (h3::server::Connection)
    let mut h3_server = server::builder()
        .enable_datagram(true) // 是否启用 QUIC DATAGRAM
        .build::<_, Bytes>(h3_conn)
        .await?;

    // 记录当前连接是否已经完成认证
    let is_authenticated = Arc::new(Mutex::new(false));

    // 3. 不断接收 HTTP/3 请求
    while let Some((request, stream)) = h3_server.accept().await? {
        let pwd = shared_passwd.clone();
        let auth_flag = is_authenticated.clone();
        tokio::spawn(async move {
            todo!()
            /* if let Err(e) = handle_request(request, stream, pwd, auth_flag).await {
                eprintln!("Request error: {:?}", e);
            } */
        });
    }

    Ok(())
}

/// 识别并处理客户端的认证请求 (POST /auth)，否则当做普通 HTTP/3 请求
async fn handle_request(
    request: Request<()>,
    mut stream: impl BidiStream<Bytes>,
    shared_passwd: Arc<String>,
    is_authenticated: Arc<Mutex<bool>>,
) -> anyhow::Result<()> {
    let method = request.method().clone();
    let uri = request.uri().clone();

    // 提取客户端请求头
    let headers = request.headers();

    // ============= A. 判断是否是 POST /auth =============
    let is_auth_req = (method == http::Method::POST) && uri.path() == "/auth";

    // 如果是认证请求，且尚未通过认证，则进行校验
    let mut guard = is_authenticated.lock().await;
    if is_auth_req && !*guard {
        // 取出 Hysteria-Auth
        let client_pass = headers
            .get("Hysteria-Auth")
            .map(|val| val.to_str().unwrap_or_default())
            .unwrap_or_default();

        // 取出 Hysteria-CC-RX (客户端发送的接收速率, 这里不一定用得上)
        let _cc_rx_client = headers
            .get("Hysteria-CC-RX")
            .map(|val| val.to_str().unwrap_or("0"))
            .unwrap_or("0");

        // 验证密码
        if client_pass == shared_passwd.as_str() {
            // 通过认证
            *guard = true;

            // 根据你自己的逻辑设置 cc_rx/server_udp
            let cc_rx_server = "0"; // 0 = unlimited
            let support_udp = "false"; // 你也可以设为 "true" 表示支持 UDP
            todo!()
            // 必须返回 HTTP 状态码 233，带上相应头
            // 同时可加上 Hysteria-Padding
            /* let resp = Response::builder()
                .status(233)
                .header("Hysteria-CC-RX", cc_rx_server)
                .header("Hysteria-UDP", support_udp)
                .header("Hysteria-Padding", random_padding(64..=128))
                .body(())
                .unwrap();

            // 写回响应
            stream.send_response(resp).await?;
            Ok(()) */
        } else {
            // 密码不正确，返回一个非 233 的状态码（如 403 或 401）
            todo!()
            // let resp = Response::builder().status(403).body(()).unwrap();
            // stream.send_response(resp).await?;
            // Ok(())
        }
    }
    // 如果已通过认证，则可在此处理后续「代理请求」等逻辑
    else if *guard {
        todo!()
        // 在已认证状态下，可以返回任意内容，或进入代理模式
        // 这里简单返回 200
        /* let resp = Response::builder()
            .status(200)
            .header("content-type", "text/plain")
            .body(())
            .unwrap();
        stream.send_response(resp).await?; */
        // 然后你可以在 stream 上继续读写 body 数据
        // Ok(())
    }
    // 其他情况(没走 /auth, 或者已经是普通请求且没认证)
    else {
        todo!()
        // 当成普通 HTTP/3 请求返回
        /* let resp = Response::builder()
            .status(200)
            .header("content-type", "text/plain")
            .body(())
            .unwrap();
        stream.send_response(resp).await?;
        Ok(()) */
    }
}

/// 生成随机填充字符串
fn random_padding(range: std::ops::RangeInclusive<u32>) -> String {
    use rand::distributions::Alphanumeric;
    let mut rng = rand::thread_rng();
    let len = rng.gen_range(range) as usize;
    rng.sample_iter(Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}
