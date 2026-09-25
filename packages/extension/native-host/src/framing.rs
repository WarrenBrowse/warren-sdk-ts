//! Native messaging framing: a `u32` length in native byte order, then that
//! many bytes of UTF-8 JSON. Native order is little-endian on every target
//! this helper ships for, so the prefix is written little-endian explicitly.

use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt};
use zeroize::Zeroizing;

/// Chromium kills a host whose message to the browser reaches 1 MiB.
pub const MAX_OUTBOUND_BYTES: usize = 1024 * 1024;

/// The largest request accepted from the browser. Every request is a few
/// hundred bytes; a length beyond this is a corrupt stream, not a message.
pub const MAX_INBOUND_BYTES: usize = 1024 * 1024;

/// Why a frame could not be read or written.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FrameError {
    /// The length prefix announces more than the cap allows.
    #[error("native messaging frame of {0} bytes exceeds the cap")]
    TooLarge(usize),
    /// The stream ended inside a frame.
    #[error("native messaging stream ended inside a frame")]
    Truncated,
    /// The stream could not be read.
    #[error("native messaging stream is unreadable")]
    Io(#[source] std::io::Error),
    /// The message could not be serialized.
    #[error("the message cannot be serialized")]
    Encode(#[source] serde_json::Error),
}

/// Encodes one message. A message at or above the outbound cap is refused.
///
/// # Errors
///
/// [`FrameError::TooLarge`] when the JSON reaches [`MAX_OUTBOUND_BYTES`],
/// [`FrameError::Encode`] when it cannot be serialized.
pub fn encode_frame(message: &Value) -> Result<Vec<u8>, FrameError> {
    let json = serde_json::to_vec(message).map_err(FrameError::Encode)?;
    if json.len() >= MAX_OUTBOUND_BYTES {
        return Err(FrameError::TooLarge(json.len()));
    }
    let length = u32::try_from(json.len()).map_err(|_| FrameError::TooLarge(json.len()))?;
    let mut frame = Vec::with_capacity(4 + json.len());
    frame.extend_from_slice(&length.to_le_bytes());
    frame.extend_from_slice(&json);
    Ok(frame)
}

/// Encodes `message`, or, when it is too large to cross, the error answer the
/// request it replied to gets instead. An oversized unsolicited event is
/// dropped (`None`): the browser would kill the host for it.
#[must_use]
pub fn encode_or_refuse(message: &Value) -> Option<Vec<u8>> {
    match encode_frame(message) {
        Ok(frame) => Some(frame),
        Err(_) => {
            let id = message.get("id")?.clone();
            encode_frame(&serde_json::json!({
                "id": id,
                "ok": false,
                "code": "host",
                "message": "the answer exceeds the native messaging size cap",
            }))
            .ok()
        }
    }
}

/// Reads the next frame's payload. `Ok(None)` is a clean end of stream at a
/// frame boundary, the browser closing the port. The payload may carry a
/// mnemonic, so it is wiped when dropped.
///
/// # Errors
///
/// [`FrameError::TooLarge`] for a length above [`MAX_INBOUND_BYTES`],
/// [`FrameError::Truncated`] when the stream ends mid-frame, and
/// [`FrameError::Io`] when it cannot be read.
pub async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Option<Zeroizing<Vec<u8>>>, FrameError> {
    let mut prefix = [0u8; 4];
    let mut filled = 0;
    while filled < prefix.len() {
        let read = reader
            .read(&mut prefix[filled..])
            .await
            .map_err(FrameError::Io)?;
        if read == 0 {
            return if filled == 0 {
                Ok(None)
            } else {
                Err(FrameError::Truncated)
            };
        }
        filled += read;
    }
    let length = u32::from_le_bytes(prefix) as usize;
    if length > MAX_INBOUND_BYTES {
        return Err(FrameError::TooLarge(length));
    }
    let mut payload = Zeroizing::new(vec![0u8; length]);
    reader
        .read_exact(&mut payload)
        .await
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::UnexpectedEof => FrameError::Truncated,
            _ => FrameError::Io(e),
        })?;
    Ok(Some(payload))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn frame_of(json: &str) -> Vec<u8> {
        let mut frame = (json.len() as u32).to_le_bytes().to_vec();
        frame.extend_from_slice(json.as_bytes());
        frame
    }

    #[test]
    fn encodes_a_little_endian_length_then_the_json() {
        let frame = encode_frame(&json!({ "a": 1 })).unwrap();
        assert_eq!(&frame[..4], &7u32.to_le_bytes());
        assert_eq!(&frame[4..], br#"{"a":1}"#);
    }

    #[test]
    fn refuses_a_message_at_the_outbound_cap() {
        let blob = "x".repeat(MAX_OUTBOUND_BYTES);
        assert!(matches!(
            encode_frame(&json!({ "blob": blob })),
            Err(FrameError::TooLarge(_))
        ));
    }

    #[test]
    fn an_oversized_answer_becomes_an_error_for_its_request() {
        let blob = "x".repeat(MAX_OUTBOUND_BYTES);
        let frame = encode_or_refuse(&json!({ "id": 4, "ok": true, "blob": blob })).unwrap();
        let answer: Value = serde_json::from_slice(&frame[4..]).unwrap();
        assert_eq!(answer["id"], 4);
        assert_eq!(answer["ok"], false);
        assert_eq!(answer["code"], "host");
    }

    #[test]
    fn an_oversized_event_is_dropped() {
        let blob = "x".repeat(MAX_OUTBOUND_BYTES);
        assert!(encode_or_refuse(&json!({ "type": "state", "blob": blob })).is_none());
    }

    #[tokio::test]
    async fn reads_frames_split_and_concatenated_then_a_clean_end() {
        let mut stream = frame_of(r#"{"type":"hello"}"#);
        stream.extend(frame_of(r#"{"type":"status"}"#));
        // A reader that hands the bytes over three at a time splits the
        // prefix and the payload across reads.
        let mut reader = ChunkReader {
            chunks: stream.chunks(3).map(<[u8]>::to_vec).collect(),
        };
        let one = read_frame(&mut reader).await.unwrap().unwrap();
        let two = read_frame(&mut reader).await.unwrap().unwrap();
        assert_eq!(&one[..], br#"{"type":"hello"}"#);
        assert_eq!(&two[..], br#"{"type":"status"}"#);
        assert!(read_frame(&mut reader).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn refuses_a_length_above_the_inbound_cap() {
        let absurd = (64u32 * 1024 * 1024).to_le_bytes();
        let mut reader = &absurd[..];
        assert!(matches!(
            read_frame(&mut reader).await,
            Err(FrameError::TooLarge(_))
        ));
    }

    #[tokio::test]
    async fn a_stream_ending_mid_frame_is_truncated() {
        let mut stream = frame_of(r#"{"type":"hello"}"#);
        stream.truncate(9);
        let mut reader = &stream[..];
        assert!(matches!(
            read_frame(&mut reader).await,
            Err(FrameError::Truncated)
        ));
        let mut prefix_only = &[1u8, 0][..];
        assert!(matches!(
            read_frame(&mut prefix_only).await,
            Err(FrameError::Truncated)
        ));
    }

    /// An in-memory reader that hands over one chunk per read, so a frame's
    /// prefix and payload arrive split across reads.
    struct ChunkReader {
        chunks: std::collections::VecDeque<Vec<u8>>,
    }

    impl AsyncRead for ChunkReader {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            if let Some(chunk) = self.chunks.pop_front() {
                let n = chunk.len().min(buf.remaining());
                buf.put_slice(&chunk[..n]);
                if n < chunk.len() {
                    self.chunks.push_front(chunk[n..].to_vec());
                }
            }
            std::task::Poll::Ready(Ok(()))
        }
    }
}
