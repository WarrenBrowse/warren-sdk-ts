//! The native messaging loop: frames in, session, frames out. Requests are
//! served concurrently, as the TypeScript host does, so a `status` is answered
//! while a connect is still dialing. The tunnel lives exactly as long as the
//! browser's end of the pipe: end of stream, a corrupt frame or a signal tears
//! it down before the loop returns.

use std::future::Future;
use std::sync::Arc;

use futures_util::StreamExt;
use futures_util::stream::FuturesUnordered;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use crate::framing::{self, FrameError};
use crate::protocol::{Decoded, decode_request};
use crate::session::{HostBackend, HostSession};

/// How long requests received before the end may still run.
const DRAIN: std::time::Duration = std::time::Duration::from_secs(3);

/// Why the loop ended.
#[derive(Debug, PartialEq, Eq)]
pub enum HostExit {
    /// The browser closed the pipe.
    EndOfStream,
    /// A frame was corrupt: the stream cannot be trusted any further.
    CorruptStream,
    /// The process was asked to stop.
    Signalled,
}

/// Serves the session over `reader`/`writer` until the browser leaves,
/// `stop` resolves, or the stream turns corrupt. The session is closed (its
/// tunnel torn down) before this returns.
pub async fn serve<B, R, W, S>(backend: B, reader: R, writer: W, stop: S) -> HostExit
where
    B: HostBackend,
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
    S: Future<Output = ()>,
{
    let (out_tx, out_rx) = mpsc::unbounded_channel::<Value>();
    let writer_task = tokio::spawn(write_frames(writer, out_rx));
    let session = HostSession::new(
        backend,
        Arc::new(move |message| {
            // The writer only stops when the pipe is gone, and then there is
            // nobody left to answer.
            let _ = out_tx.send(message);
        }),
    );

    // A dedicated reader task: a read cancelled half-way by `select!` would
    // lose the bytes it had consumed.
    let (in_tx, mut in_rx) = mpsc::channel::<Result<Option<Zeroizing<Vec<u8>>>, FrameError>>(16);
    let reader_task = tokio::spawn(read_frames(reader, in_tx));

    let mut inflight = FuturesUnordered::new();
    tokio::pin!(stop);
    let exit = loop {
        tokio::select! {
            frame = in_rx.recv() => match frame {
                Some(Ok(Some(payload))) => match decode_request(&payload) {
                    Decoded::Request(envelope) => inflight.push(session.handle(envelope)),
                    Decoded::Ignored => {}
                    Decoded::Corrupt => break HostExit::CorruptStream,
                },
                Some(Ok(None)) | None => break HostExit::EndOfStream,
                Some(Err(_)) => break HostExit::CorruptStream,
            },
            Some(()) = inflight.next(), if !inflight.is_empty() => {}
            () = &mut stop => break HostExit::Signalled,
        }
    };
    reader_task.abort();
    // Tear down first, then let the requests already received finish: a
    // connect still dialing lands on a closed session and shuts its tunnel
    // down, and the quick answers still reach the pipe. Bounded, because the
    // process is about to end and takes every tunnel with it anyway.
    session.close().await;
    let _ = tokio::time::timeout(DRAIN, async { while inflight.next().await.is_some() {} }).await;
    drop(inflight);
    drop(session);
    // Let the answers already queued reach the pipe before returning.
    let _ = writer_task.await;
    exit
}

async fn read_frames<R: AsyncRead + Unpin>(
    mut reader: R,
    frames: mpsc::Sender<Result<Option<Zeroizing<Vec<u8>>>, FrameError>>,
) {
    loop {
        let frame = framing::read_frame(&mut reader).await;
        let last = !matches!(frame, Ok(Some(_)));
        if frames.send(frame).await.is_err() || last {
            return;
        }
    }
}

async fn write_frames<W: AsyncWrite + Unpin>(
    mut writer: W,
    mut messages: mpsc::UnboundedReceiver<Value>,
) {
    while let Some(message) = messages.recv().await {
        let Some(frame) = framing::encode_or_refuse(&message) else {
            continue;
        };
        if writer.write_all(&frame).await.is_err() || writer.flush().await.is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use serde_json::json;
    use tokio::io::{AsyncReadExt, DuplexStream};
    use tokio::sync::Notify;
    use warren_sdk::product::Channel;

    use super::*;
    use crate::protocol::{Endpoints, ExitLocation};
    use crate::session::{ConnectOptions, HostError, HostTunnel, Listeners, StateSink, TunnelInit};

    #[derive(Clone, Default)]
    struct Fake {
        shutdowns: Arc<AtomicUsize>,
        mnemonics: Arc<Mutex<Vec<String>>>,
        /// When set, a connect announces itself on `dialing` and then waits
        /// for this before it lands.
        gate: Option<Arc<Notify>>,
        dialing: Arc<Notify>,
    }

    struct FakeTunnel {
        shutdowns: Arc<AtomicUsize>,
        gate: Option<Arc<Notify>>,
        dialing: Arc<Notify>,
    }

    impl HostTunnel for FakeTunnel {
        async fn connect(&mut self, _options: ConnectOptions) -> Result<Listeners, HostError> {
            if let Some(gate) = &self.gate {
                self.dialing.notify_one();
                gate.notified().await;
            }
            Ok(Listeners {
                endpoints: Endpoints {
                    socks5: "127.0.0.1:1080".into(),
                    http: None,
                },
                username: "warren".into(),
                password: Zeroizing::new("secret".into()),
                exit: None,
            })
        }

        async fn shutdown(self) {
            self.shutdowns.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl HostBackend for Fake {
        type Tunnel = FakeTunnel;

        async fn create_tunnel(
            &self,
            mnemonic: Zeroizing<String>,
            _on_state: StateSink,
            _init: TunnelInit,
        ) -> Result<FakeTunnel, HostError> {
            self.mnemonics.lock().unwrap().push(mnemonic.to_string());
            Ok(FakeTunnel {
                shutdowns: Arc::clone(&self.shutdowns),
                gate: self.gate.clone(),
                dialing: Arc::clone(&self.dialing),
            })
        }

        async fn list_exits(&self, _: Option<Channel>) -> Result<Vec<ExitLocation>, HostError> {
            Ok(Vec::new())
        }

        async fn account_expiry(
            &self,
            _: Zeroizing<String>,
            _: Option<Channel>,
        ) -> Result<u64, HostError> {
            Ok(1)
        }
    }

    fn frame(message: &Value) -> Vec<u8> {
        framing::encode_frame(message).unwrap()
    }

    async fn read_message(out: &mut DuplexStream) -> Value {
        let payload = framing::read_frame(out).await.unwrap().expect("a frame");
        serde_json::from_slice(&payload).unwrap()
    }

    /// Starts `serve` over in-memory pipes; returns the browser's ends.
    fn start(
        fake: Fake,
        stop: impl Future<Output = ()> + Send + 'static,
    ) -> (
        DuplexStream,
        DuplexStream,
        tokio::task::JoinHandle<HostExit>,
    ) {
        let (browser_in, host_in) = tokio::io::duplex(64 * 1024);
        let (host_out, browser_out) = tokio::io::duplex(64 * 1024);
        let task = tokio::task::spawn_local(serve(fake, host_in, host_out, stop));
        (browser_in, browser_out, task)
    }

    async fn run_local<F: Future>(f: F) -> F::Output {
        tokio::task::LocalSet::new().run_until(f).await
    }

    #[tokio::test]
    async fn answers_over_the_pipe_and_tears_down_when_the_browser_leaves() {
        run_local(async {
            let fake = Fake::default();
            let (mut to_host, mut from_host, task) = start(fake.clone(), std::future::pending());
            to_host
                .write_all(&frame(
                    &json!({ "id": 1, "type": "hello", "protocol": 3, "channel": "beta" }),
                ))
                .await
                .unwrap();
            assert_eq!(read_message(&mut from_host).await["datapath"], "ready");
            to_host
                .write_all(&frame(
                    &json!({ "id": 2, "type": "connect", "mnemonic": "m" }),
                ))
                .await
                .unwrap();
            let answer = read_message(&mut from_host).await;
            assert_eq!(answer["auth"]["password"], "secret");
            drop(to_host);
            assert_eq!(task.await.unwrap(), HostExit::EndOfStream);
            assert_eq!(fake.shutdowns.load(Ordering::SeqCst), 1);
            assert_eq!(*fake.mnemonics.lock().unwrap(), ["m"]);
        })
        .await;
    }

    #[tokio::test]
    async fn a_corrupt_frame_ends_the_host_fail_closed() {
        run_local(async {
            let fake = Fake::default();
            let (mut to_host, mut from_host, task) = start(fake.clone(), std::future::pending());
            to_host
                .write_all(&frame(
                    &json!({ "id": 1, "type": "connect", "mnemonic": "m" }),
                ))
                .await
                .unwrap();
            read_message(&mut from_host).await;
            to_host
                .write_all(&(64u32 * 1024 * 1024).to_le_bytes())
                .await
                .unwrap();
            assert_eq!(task.await.unwrap(), HostExit::CorruptStream);
            assert_eq!(fake.shutdowns.load(Ordering::SeqCst), 1);
            // The host's end is closed: nothing more comes out.
            let mut rest = Vec::new();
            from_host.read_to_end(&mut rest).await.unwrap();
            assert!(rest.is_empty());
        })
        .await;
    }

    #[tokio::test]
    async fn a_payload_that_is_not_json_ends_the_host() {
        run_local(async {
            let fake = Fake::default();
            let (mut to_host, _from_host, task) = start(fake, std::future::pending());
            let mut bad = 5u32.to_le_bytes().to_vec();
            bad.extend_from_slice(b"{nope");
            to_host.write_all(&bad).await.unwrap();
            assert_eq!(task.await.unwrap(), HostExit::CorruptStream);
        })
        .await;
    }

    #[tokio::test]
    async fn a_connect_still_dialing_when_the_browser_leaves_never_stays_up() {
        run_local(async {
            let gate = Arc::new(Notify::new());
            let fake = Fake {
                gate: Some(Arc::clone(&gate)),
                ..Fake::default()
            };
            let (mut to_host, from_host, task) = start(fake.clone(), std::future::pending());
            to_host
                .write_all(&frame(
                    &json!({ "id": 1, "type": "connect", "mnemonic": "m" }),
                ))
                .await
                .unwrap();
            fake.dialing.notified().await;
            drop(to_host);
            // Let the loop see the end of stream and close the session before
            // the tunnel lands.
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            gate.notify_one();
            assert_eq!(task.await.unwrap(), HostExit::EndOfStream);
            assert_eq!(fake.shutdowns.load(Ordering::SeqCst), 1);
            drop(from_host);
        })
        .await;
    }

    #[tokio::test]
    async fn a_stop_signal_tears_the_tunnel_down() {
        run_local(async {
            let fake = Fake::default();
            let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
            let (mut to_host, mut from_host, task) = start(fake.clone(), async {
                let _ = stop_rx.await;
            });
            to_host
                .write_all(&frame(
                    &json!({ "id": 1, "type": "connect", "mnemonic": "m" }),
                ))
                .await
                .unwrap();
            read_message(&mut from_host).await;
            stop_tx.send(()).unwrap();
            assert_eq!(task.await.unwrap(), HostExit::Signalled);
            assert_eq!(fake.shutdowns.load(Ordering::SeqCst), 1);
        })
        .await;
    }
}
