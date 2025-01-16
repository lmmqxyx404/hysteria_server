use tokio::io::AsyncWriteExt;
use tracing::{error, info};

/// 桥接函数：把 QUIC 的双向流 (rstream, wstream) 与 TCP 流 (tcp_stream) 互相转发
pub async fn bridge_quic_to_tcp(
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
