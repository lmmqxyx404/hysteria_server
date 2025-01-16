use std::{io::ErrorKind, sync::Arc};

use bytes::BytesMut;
use quinn_proto::{coding::Codec, VarInt};

use tracing::{error, info};
use transfer::bridge_quic_to_tcp;

use tokio_util::codec::{Decoder, Encoder};

mod transfer;

/// 原生 QUIC 双向流处理：循环 accept_bi()，收到数据后转发给指定 TCP 服务器，再把服务器返回数据转给客户端
pub async fn handle_raw_bi(
    conn: quinn::Connection,
    _authed_conn: Arc<tokio::sync::Mutex<bool>>, // 如果还需要认证，可自行扩展逻辑
) -> Result<(), Box<dyn std::error::Error>> {
    // 不断 accept_bi()，处理多条双向流
    loop {
        match conn.accept_bi().await {
            Ok((wstream, mut rstream)) => {
                info!("(raw QUIC) got a new bidirectional stream");
                // handle_single_bstream().await;
                let mut initial_buf = [0u8; 2];

                /* let res = rstream.read_to_end(2).await?;
                info!("res is {:?}", res); */

                let n = match rstream.read(&mut initial_buf).await? {
                    Some(n) => n, // 实际读到的字节数
                    None => {
                        // 客户端在还没发数据就关了写端
                        info!("client sent no data before closing");
                        return Ok(());
                    }
                };
                info!("n is {:?}, initial is {:?}", n, initial_buf); // 为每个 QUIC bidirectional stream 启一个任务去转发
                if !(initial_buf[0] == 68 && initial_buf[1] == 0x01) {
                    error!("(raw QUIC) accept_bi failed: {:?}", initial_buf);
                    // 正常来说应该是返回一个错误码给客户端，这里简单处理直接关闭连接
                    return Err(Box::new(std::io::Error::from(ErrorKind::InvalidData)));
                }
                let mut addr_len = [0u8; 1];
                let n = rstream.read(&mut addr_len).await.unwrap().unwrap();

                info!("n is {:?}, initial is {:?}", n, addr_len); // 为每个 QUIC bidirectional stream 启一个任务去转发
                let mut addr = BytesMut::from_iter(vec![0; addr_len[0] as usize]);
                rstream.read_exact(&mut addr).await.unwrap();
                info!("addr is {:?}", addr);

                // addr
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
