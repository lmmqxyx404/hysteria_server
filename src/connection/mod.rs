use std::sync::Arc;

use handle_stream::handle_raw_bi;
use tracing::{error, info};

use bytes::Bytes;
use h3::{error::ErrorLevel, quic::BidiStream, server::RequestStream};
use http::{Request, Response, StatusCode};

mod transfer;

mod handle_stream;

/// 在同一个 quinn::Connection 上，同时处理：
/// - HTTP/3 协议 (handle_http3)
/// - 原生 QUIC 双向流 (handle_raw_bi)
pub async fn handle_connection(conn: quinn::Connection) -> Result<(), Box<dyn std::error::Error>> {
    // 分别 spawn 两个任务并发跑
    let conn_for_h3 = conn.clone();
    // let root_for_h3 = root.clone();

    // 每个连接独有的“是否已认证”标记
    let authed_conn = Arc::new(tokio::sync::Mutex::new(false));

    let (tx_authed, mut rx_authed) = tokio::sync::mpsc::channel::<bool>(100);

    let h3_handle = tokio::spawn(async move {
        info!("handled in h3_handle");
        if let Err(e) = handle_http3(conn_for_h3, tx_authed).await {
            error!("HTTP/3 handling error: {}", e);
        }
    });

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
    let _ = tokio::join!(h3_handle);
    Ok(())
}

/// 处理 HTTP/3 协议：构造 h3::server::Connection，循环 accept() HTTP/3 请求
async fn handle_http3(
    conn: quinn::Connection,
    tx_authed: tokio::sync::mpsc::Sender<bool>,
) -> Result<(), Box<dyn std::error::Error>> {
    // 初始化 h3::server::Connection
    info!("some thing occured");
    // tokio::time::sleep(std::time::Duration::from_secs(20)).await;
    let mut h3_conn = match h3::server::Connection::new(h3_quinn::Connection::new(conn)).await {
        Ok(h3c) => h3c,
        Err(e) => {
            error!("Error during HTTP/3 handshake: {:?}", e);
            return Err(e.into());
        }
    };
    // if let Some(tx) = tx_authed.take() {
    info!("some thing occured2");
    // h3_conn.accept_with_frame(stream, frame)
    // 不断接受新的 HTTP/3 请求
    loop {
        match h3_conn.accept().await {
            Ok(Some((req, stream))) => {
                info!(
                    "new HTTP/3 request: {} {:?}",
                    req.uri().path(),
                    req.method()
                );
                // let authed_conn_for_req = authed_conn.clone();
                // 每个请求丢进一个任务单独处理
                // **仅在第一次请求时发送 tx_authed**

                if let Err(e) = handle_request(req, stream, tx_authed.clone()).await {
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

    // authed_conn: Arc<tokio::sync::Mutex<bool>>,
    tx_authed: tokio::sync::mpsc::Sender<bool>,
) -> Result<(), Box<dyn std::error::Error>>
where
    T: BidiStream<Bytes>,
{
    // let mut guard = authed_conn.lock().await;
    // let is_authed = *guard;

    // ========== 1. 如果是 Hysteria 认证 ==========
    if is_hysteria_auth_request(&req) && do_auth() {
        // *guard = true;
        // drop(guard);
        let resp = Response::builder()
            .status(StatusCode::from_u16(233).unwrap())
            .header("Hysteria-UDP", "false")
            .header("Hysteria-CC-RX", "0")
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
    // ========== 2. 如果已经认证了 && path=/tcp => 做 TCP 隧道 (示例) ==========
    // 此处仅演示，留给你自行扩展
    /* if req.uri().path() == "/tcp" {
        info!("client wants a TCP tunnel (already authed). you'd do logic here...");
        // 省略：演示如何 echo/或转发
        let resp = Response::builder().status(StatusCode::OK).body(()).unwrap();
        let mut send_stream = stream.send_response(resp).await?;
        // ...
        // 需要后面自己处理 stream.split() -> body 与 send_stream 互相转发
        return Ok(());
    } */
}

/*
pub async fn handle_single_bstream(
    wstream: quinn::SendStream,
    mut rstream: quinn::RecvStream,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut initial_buf = [0u8; 8];
    let n = match rstream.read(&mut initial_buf).await? {
        Some(n) => n, // 实际读到的字节数
        None => {
            // 客户端在还没发数据就关了写端
            info!("client sent no data before closing");
            return Ok(());
        }
    };
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
*/
