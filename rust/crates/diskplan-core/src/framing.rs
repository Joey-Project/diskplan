use std::io::{self, Read, Write};

use thiserror::Error;

pub const MAX_FRAME_LENGTH: usize = 16 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum FrameError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("truncated frame prefix: received {received} of 4 bytes")]
    TruncatedPrefix { received: usize },
    #[error("frame payload length {length} exceeds maximum {maximum}")]
    Oversized { length: usize, maximum: usize },
    #[error("truncated frame payload: received {received} of {expected} bytes")]
    TruncatedPayload { expected: usize, received: usize },
}

pub fn read_frame<R: Read>(reader: &mut R) -> Result<Option<Vec<u8>>, FrameError> {
    let mut prefix = [0_u8; 4];
    let prefix_read = read_until_eof(reader, &mut prefix)?;
    if prefix_read == 0 {
        return Ok(None);
    }
    if prefix_read != prefix.len() {
        return Err(FrameError::TruncatedPrefix {
            received: prefix_read,
        });
    }

    let length = u32::from_be_bytes(prefix) as usize;
    if length > MAX_FRAME_LENGTH {
        return Err(FrameError::Oversized {
            length,
            maximum: MAX_FRAME_LENGTH,
        });
    }

    let mut payload = vec![0_u8; length];
    let payload_read = read_until_eof(reader, &mut payload)?;
    if payload_read != length {
        return Err(FrameError::TruncatedPayload {
            expected: length,
            received: payload_read,
        });
    }
    Ok(Some(payload))
}

pub fn write_frame<W: Write>(writer: &mut W, payload: &[u8]) -> Result<(), FrameError> {
    if payload.len() > MAX_FRAME_LENGTH {
        return Err(FrameError::Oversized {
            length: payload.len(),
            maximum: MAX_FRAME_LENGTH,
        });
    }
    writer.write_all(&(payload.len() as u32).to_be_bytes())?;
    writer.write_all(payload)?;
    writer.flush()?;
    Ok(())
}

fn read_until_eof<R: Read>(reader: &mut R, buffer: &mut [u8]) -> io::Result<usize> {
    let mut offset = 0;
    while offset < buffer.len() {
        match reader.read(&mut buffer[offset..]) {
            Ok(0) => break,
            Ok(count) => offset += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_eof_is_not_a_truncated_frame() {
        assert!(read_frame(&mut &[][..]).unwrap().is_none());
    }

    #[test]
    fn reports_truncated_prefix_and_payload_separately() {
        assert!(matches!(
            read_frame(&mut &[0_u8, 0, 0][..]),
            Err(FrameError::TruncatedPrefix { received: 3 })
        ));
        assert!(matches!(
            read_frame(&mut &[0_u8, 0, 0, 3, 1, 2][..]),
            Err(FrameError::TruncatedPayload {
                expected: 3,
                received: 2
            })
        ));
    }

    #[test]
    fn rejects_oversized_frame_before_allocating_payload() {
        let length = (MAX_FRAME_LENGTH as u32 + 1).to_be_bytes();
        assert!(matches!(
            read_frame(&mut &length[..]),
            Err(FrameError::Oversized { .. })
        ));
    }

    #[test]
    fn writes_big_endian_length() {
        let mut bytes = Vec::new();
        write_frame(&mut bytes, b"abc").unwrap();
        assert_eq!(bytes, b"\0\0\0\x03abc");
    }
}
