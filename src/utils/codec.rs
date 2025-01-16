use std::io;

use bytes::{Buf, BufMut, BytesMut};
use quinn::VarInt;
use quinn_proto::coding::Codec;
use tokio_util::codec::{Decoder, Encoder};
use tracing::info;

pub struct Hy2TcpCodec;

pub trait ServerSide {}

impl ServerSide for Hy2TcpCodec {}

impl Decoder for Hy2TcpCodec
where
    Hy2TcpCodec: ServerSide,
{
    type Item = BytesMut;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<BytesMut>, io::Error> {
        if buf.len() < 8 {
            return Ok(None);
        }
        let len = u64::from_be_bytes(buf[0..8].try_into().unwrap()) as usize;
        if buf.len() < len + 8 {
            return Ok(None);
        }
        let data = buf.split_to(len + 8);
        Ok(Some(data))
    }
}

impl Encoder<BytesMut> for Hy2TcpCodec
where
    Hy2TcpCodec: ServerSide,
{
    type Error = io::Error;

    fn encode(&mut self, data: BytesMut, buf: &mut BytesMut) -> Result<(), io::Error> {
        let len = data.len() as u64;
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(&data);
        Ok(())
    }
}

#[test]
fn hy2_server_resp_parse() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::FULL)
        .with_writer(std::io::stderr)
        .with_max_level(tracing::Level::INFO)
        .init();

    let mut src = BytesMut::from(&[0x04, 0x01, 0x61, 0x62, 0x63, 0x00][..]);
    info!("{:02x}", &src);
    /* let msg = Hy2TcpCodec.decode(&mut src).unwrap().unwrap();
    assert!(msg.status == 0);
    assert!(msg.msg == "abc");

    let mut src = BytesMut::from(&[0x01, 0x00, 0x00][..]);
    let msg = Hy2TcpCodec.decode(&mut src).unwrap().unwrap();
    assert!(msg.status == 0x1);
    assert!(msg.msg == ""); */
}

#[test]
fn test_varint() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::FULL)
        .with_writer(std::io::stderr)
        .with_max_level(tracing::Level::INFO)
        .init();

    let mut buf = BytesMut::new();
    let mut len = 0x4401;
    // buf.put_var(len);
    buf.put_u16(len);
    let a = VarInt::decode(&mut buf).unwrap();
    let mut bsd = BytesMut::new();
    VarInt::encode(&a, &mut bsd);
    info!("{:02x?}  {:02x}", a, bsd);
}
