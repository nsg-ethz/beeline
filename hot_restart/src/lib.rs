//! The HTTP/2 framing of the client and the backend of script/hot_restart_bench.sh, without TLS.
//!
//! Both write one frame per write, the data plane parses every write on its own.
use std::io::{self, Write};

pub const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

pub const DATA: u8 = 0x0;
pub const HEADERS: u8 = 0x1;
pub const RST_STREAM: u8 = 0x3;
pub const SETTINGS: u8 = 0x4;
pub const PING: u8 = 0x6;
pub const GOAWAY: u8 = 0x7;

pub const END_STREAM: u8 = 0x1;
pub const ACK: u8 = 0x1;
pub const END_HEADERS: u8 = 0x4;

pub struct Frame {
    pub typ: u8,
    pub flags: u8,
    pub stream: u32,
    pub payload: Vec<u8>,
}

/// Writes a frame with a single write.
pub fn send(w: &mut impl Write, typ: u8, flags: u8, stream: u32, payload: &[u8]) -> io::Result<()> {
    let mut frame = Vec::with_capacity(9 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
    frame.extend_from_slice(&[typ, flags]);
    frame.extend_from_slice(&stream.to_be_bytes());
    frame.extend_from_slice(payload);
    w.write_all(&frame)
}

/// Removes the first complete frame from the buffer.
pub fn pop_frame(buf: &mut Vec<u8>) -> Option<Frame> {
    if buf.len() < 9 {
        return None;
    }
    let len = u32::from_be_bytes([0, buf[0], buf[1], buf[2]]) as usize;
    if buf.len() < 9 + len {
        return None;
    }
    let frame = Frame {
        typ: buf[3],
        flags: buf[4],
        stream: u32::from_be_bytes(buf[5..9].try_into().unwrap()) & 0x7FFF_FFFF,
        payload: buf[9..9 + len].to_vec(),
    };
    buf.drain(..9 + len);
    Some(frame)
}

/// Acks SETTINGS and PING, true if the frame was one of them.
pub fn control(w: &mut impl Write, frame: &Frame) -> io::Result<bool> {
    if frame.typ == SETTINGS && frame.flags & ACK == 0 {
        send(w, SETTINGS, ACK, 0, &[])?;
    } else if frame.typ == PING && frame.flags & ACK == 0 {
        send(w, PING, ACK, 0, &frame.payload)?;
    }
    Ok(frame.typ == SETTINGS || frame.typ == PING)
}
