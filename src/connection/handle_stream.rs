use std::{io::ErrorKind, sync::Arc};

use bytes::BytesMut;
use tracing::{error, info};

use crate::{connection::transfer::bridge_quic_to_tcp, utils::bytes_to_ascii_characters};

/// 原生 QUIC 双向流处理：循环 accept_bi()，收到数据后转发给指定 TCP 服务器，再把服务器返回数据转给客户端
pub async fn handle_raw_bi(
    conn: quinn::Connection,
    _authed_conn: Arc<tokio::sync::Mutex<bool>>, // 如果还需要认证，可自行扩展逻辑
) -> Result<(), Box<dyn std::error::Error>> {
    // 不断 accept_bi()，处理多条双向流
    loop {
        match conn.accept_bi().await {
            Ok((mut wstream, mut rstream)) => {
                tokio::spawn(async move {
                    // 这时候就该 spawn 出去一个任务，去处理这个双向流了
                    info!("(raw QUIC) got a new bidirectional stream");
                    // handle_single_bstream().await;
                    let mut initial_buf = [0u8; 2];
                    /* let res = rstream.read_to_end(2).await?;
                    info!("res is {:?}", res); */
                    rstream.read_exact(&mut initial_buf).await.unwrap();

                    info!("n is , initial is {:?}", initial_buf); // 为每个 QUIC bidirectional stream 启一个任务去转发
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

                    let remote_addr = bytes_to_ascii_characters(&addr);
                    info!(remote_addr);
                    let mut padd_len = BytesMut::from_iter(vec![0; 2]);
                    rstream.read_exact(&mut padd_len).await.unwrap();
                    info!("padd_len is {:?}", padd_len);
                    // VarInt::decode(&mut padd_len);
                    padd_len[0] = padd_len[0] & 0x3f;
                    let padd_len_num = u16::from_be_bytes(padd_len[0..2].try_into().unwrap());
                    info!("padd_len is {:?}", padd_len_num);
                    let mut padd_buf = BytesMut::from_iter(vec![0; padd_len_num as usize]);
                    rstream.read_exact(&mut padd_buf).await.unwrap();

                    wstream.write(&[0x00, 0x00, 0x00]).await.unwrap();

                    // 1) 连接到远程 TCP 服务器
                    // let remote_addr = "cp.cloudflare.com:80";
                    match tokio::net::TcpStream::connect(&remote_addr).await {
                        Ok(tcp_stream) => {
                            info!("started to send data to remote");
                            if let Err(e) = bridge_quic_to_tcp(rstream, wstream, tcp_stream).await {
                                error!("bridge error: {}", e);
                            }
                            return Ok(());
                        }
                        Err(e) => {
                            error!("connect to {} failed: {}", &remote_addr, e);
                            return Ok(());
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
