//! One browser connection worth of helper logic: request dispatch and the
//! tunnel lifecycle, independent of stdio and of the engine so it is tested
//! against a fake backend. Mirrors `packages/extension/src/host/session.ts`.

use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use serde_json::Value;
use warren_sdk::product::Channel;
use zeroize::Zeroizing;

use crate::protocol::{
    self, ConnectRequest, Endpoints, EntryQuery, Envelope, ExitLocation, ExitQuery, HostState,
    PROTOCOL_VERSION, Request,
};

/// A failure answered to the extension: a stable code it can dispatch on and
/// a message that carries no identity material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostError {
    /// Machine-readable code (`tunnel`, `api`, `discovery`, `protocol`, ...).
    pub code: String,
    /// Redacted, human-readable message.
    pub message: String,
}

impl HostError {
    /// Builds an error from a code and an already redacted message.
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

/// Where the session's messages go (the stdout writer in production).
pub type Outbox = Arc<dyn Fn(Value) + Send + Sync>;

/// Receives every lifecycle transition of one tunnel.
pub type StateSink = Arc<dyn Fn(HostState) + Send + Sync>;

/// Tunnel options that cannot wait for connect.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TunnelInit {
    /// DAITA on the tunnel, when the extension said.
    pub daita: Option<bool>,
    /// The channel the extension named at hello, if it did.
    pub channel: Option<Channel>,
}

/// Per-connect options.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConnectOptions {
    /// Exit selection.
    pub selector: Option<ExitQuery>,
    /// Multihop entry selection.
    pub entry_selector: Option<EntryQuery>,
    /// Also open the HTTP listener.
    pub http_proxy: Option<bool>,
}

/// What a connected tunnel hands back: its listeners and the credentials
/// they demand.
pub struct Listeners {
    /// The listener addresses.
    pub endpoints: Endpoints,
    /// Username clients present.
    pub username: String,
    /// Per-session password clients present.
    pub password: Zeroizing<String>,
}

/// One tunnel, as the session drives it.
pub trait HostTunnel {
    /// Dials the tunnel and opens its listeners.
    fn connect(
        &mut self,
        options: ConnectOptions,
    ) -> impl Future<Output = Result<Listeners, HostError>>;
    /// Tears it down. Never fails: a tunnel that cannot be told to stop still
    /// dies with the process.
    fn shutdown(self) -> impl Future<Output = ()>;
}

/// The engine behind the session.
pub trait HostBackend {
    /// The tunnel type this backend builds.
    type Tunnel: HostTunnel + Send + 'static;
    /// Builds one tunnel for the account behind `mnemonic`.
    fn create_tunnel(
        &self,
        mnemonic: Zeroizing<String>,
        on_state: StateSink,
        init: TunnelInit,
    ) -> impl Future<Output = Result<Self::Tunnel, HostError>>;
    /// The verified relay-list locations of `channel` (the build's own when
    /// `None`).
    fn list_exits(
        &self,
        channel: Option<Channel>,
    ) -> impl Future<Output = Result<Vec<ExitLocation>, HostError>>;
    /// The subscription expiry of the account behind `mnemonic`, unix seconds.
    fn account_expiry(
        &self,
        mnemonic: Zeroizing<String>,
        channel: Option<Channel>,
    ) -> impl Future<Output = Result<u64, HostError>>;
}

struct Inner<T> {
    state: HostState,
    endpoints: Option<Endpoints>,
    tunnel: Option<T>,
    connecting: bool,
    /// Set once the browser is gone: no tunnel may come up after that.
    closed: bool,
    channel: Option<Channel>,
    /// Bumped by every connect and every teardown. A connect that finishes
    /// under another generation was cancelled, and a state event from an older
    /// generation describes a tunnel that is gone.
    generation: u64,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The helper logic of one browser connection.
pub struct HostSession<B: HostBackend> {
    backend: B,
    outbox: Outbox,
    inner: Arc<Mutex<Inner<B::Tunnel>>>,
}

impl<B: HostBackend> HostSession<B> {
    /// A session answering through `outbox`.
    pub fn new(backend: B, outbox: Outbox) -> Self {
        Self {
            backend,
            outbox,
            inner: Arc::new(Mutex::new(Inner {
                state: HostState::Disconnected,
                endpoints: None,
                tunnel: None,
                connecting: false,
                closed: false,
                channel: None,
                generation: 0,
            })),
        }
    }

    /// Handles one request. Never fails: every error becomes an answer.
    pub async fn handle(&self, envelope: Envelope) {
        let Envelope { id, request } = envelope;
        match request {
            Request::Hello { protocol, channel } => self.hello(&id, protocol, channel),
            Request::Status => {
                let inner = lock(&self.inner);
                let answer = protocol::status_answer(&id, inner.state, inner.endpoints.as_ref());
                drop(inner);
                self.send(answer);
            }
            Request::Connect(request) => self.connect(&id, request).await,
            Request::Disconnect => {
                self.teardown().await;
                self.send(protocol::disconnect_answer(&id));
            }
            Request::Exits => {
                let channel = lock(&self.inner).channel;
                match self.backend.list_exits(channel).await {
                    Ok(locations) => self.send(protocol::exits_answer(&id, &locations)),
                    Err(e) => self.fail(&id, &e.code, &e.message),
                }
            }
            Request::Account { mnemonic } => {
                let channel = lock(&self.inner).channel;
                match self.backend.account_expiry(mnemonic, channel).await {
                    Ok(expires_at) => self.send(protocol::account_answer(&id, expires_at)),
                    Err(e) => self.fail(&id, &e.code, &e.message),
                }
            }
            Request::Refused(reason) => self.fail(&id, "protocol", reason),
        }
    }

    /// Tears a live tunnel down, cancels one still connecting, and refuses
    /// every later connect: the browser is gone, so nothing may carry its
    /// traffic any more.
    pub async fn close(&self) {
        lock(&self.inner).closed = true;
        self.teardown().await;
    }

    fn hello(&self, id: &Value, protocol: Option<Value>, channel: Option<Value>) {
        let speaks_ours = protocol
            .as_ref()
            .and_then(Value::as_f64)
            .is_some_and(|v| v == PROTOCOL_VERSION as f64);
        if !speaks_ours {
            return self.fail(id, "protocol", "unsupported protocol version");
        }
        let channel = match channel {
            None => None,
            Some(value) => match value.as_str().and_then(protocol::parse_channel) {
                Some(channel) => Some(channel),
                None => return self.fail(id, "protocol", "unknown release channel"),
            },
        };
        lock(&self.inner).channel = channel;
        self.send(protocol::hello_answer(id));
    }

    async fn connect(&self, id: &Value, request: ConnectRequest) {
        let (generation, channel) = {
            let mut inner = lock(&self.inner);
            if inner.closed {
                drop(inner);
                return self.fail(id, "tunnel", "the helper is shutting down");
            }
            if inner.connecting || inner.tunnel.is_some() {
                drop(inner);
                return self.fail(id, "already_connected", "a session is already up");
            }
            inner.connecting = true;
            inner.generation += 1;
            (inner.generation, inner.channel)
        };
        let ConnectRequest {
            mnemonic,
            selector,
            entry_selector,
            http_proxy,
            daita,
        } = request;
        let init = TunnelInit { daita, channel };
        let options = ConnectOptions {
            selector,
            entry_selector,
            http_proxy,
        };

        let outcome = match self
            .backend
            .create_tunnel(mnemonic, self.state_sink(generation), init)
            .await
        {
            Err(e) => Err((None, e)),
            Ok(mut tunnel) => match tunnel.connect(options).await {
                Err(e) => Err((Some(tunnel), e)),
                Ok(l) if l.username.is_empty() || l.password.is_empty() => Err((
                    Some(tunnel),
                    HostError::new("protocol", "the tunnel reported no listener credentials"),
                )),
                Ok(listeners) => Ok((tunnel, listeners)),
            },
        };

        // Settle the outcome under the lock; a tunnel that must not live
        // comes back out of it and is shut down after the lock is released.
        let (discard, answer) = {
            let mut inner = lock(&self.inner);
            inner.connecting = false;
            let current = inner.generation == generation;
            match outcome {
                Ok((tunnel, listeners)) if current => {
                    inner.tunnel = Some(tunnel);
                    // Only the addresses stay, for status: the credentials
                    // cross the channel once, in this answer.
                    inner.endpoints = Some(listeners.endpoints.clone());
                    inner.state = HostState::Connected;
                    let answer = protocol::connect_answer(
                        id,
                        &listeners.endpoints,
                        &listeners.username,
                        &listeners.password,
                    );
                    (None, answer)
                }
                // A disconnect (or the browser leaving) landed while this
                // tunnel was being built: it must not outlive that.
                Ok((tunnel, _)) => (
                    Some(tunnel),
                    protocol::error_answer(id, "tunnel", "disconnected while connecting"),
                ),
                // Fail-closed: never leave a half-built tunnel running.
                Err((tunnel, error)) => {
                    if current {
                        inner.state = HostState::Disconnected;
                    }
                    (
                        tunnel,
                        protocol::error_answer(id, &error.code, &error.message),
                    )
                }
            }
        };
        if let Some(tunnel) = discard {
            tunnel.shutdown().await;
        }
        self.send(answer);
    }

    fn state_sink(&self, generation: u64) -> StateSink {
        let inner = Arc::clone(&self.inner);
        let outbox = Arc::clone(&self.outbox);
        Arc::new(move |state| {
            let mut guard = lock(&inner);
            if guard.generation != generation {
                return;
            }
            guard.state = state;
            drop(guard);
            outbox(protocol::state_event(state));
        })
    }

    async fn teardown(&self) {
        let tunnel = {
            let mut inner = lock(&self.inner);
            inner.generation += 1;
            inner.endpoints = None;
            inner.state = HostState::Disconnected;
            inner.tunnel.take()
        };
        if let Some(tunnel) = tunnel {
            tunnel.shutdown().await;
        }
    }

    fn send(&self, message: Value) {
        (self.outbox)(message);
    }

    fn fail(&self, id: &Value, code: &str, message: &str) {
        self.send(protocol::error_answer(id, code, message));
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use serde_json::json;
    use tokio::sync::Notify;

    use super::*;
    use crate::protocol::{Decoded, decode_request};

    const M: &str = "test mnemonic";

    /// What the fake saw, shared with the test after the session consumed it.
    #[derive(Default)]
    struct Seen {
        mnemonics: Mutex<Vec<String>>,
        inits: Mutex<Vec<TunnelInit>>,
        connects: Mutex<Vec<ConnectOptions>>,
        exits_channels: Mutex<Vec<Option<Channel>>>,
        account_channels: Mutex<Vec<Option<Channel>>>,
        shutdowns: AtomicUsize,
        sinks: Mutex<Vec<StateSink>>,
    }

    #[derive(Clone, Default)]
    struct Fake {
        seen: Arc<Seen>,
        create_error: Option<HostError>,
        connect_error: Option<HostError>,
        username: Option<String>,
        password: Option<String>,
        /// When set, connect waits for this before answering.
        gate: Option<Arc<Notify>>,
        exits: Option<Result<Vec<ExitLocation>, HostError>>,
        account: Option<Result<u64, HostError>>,
    }

    struct FakeTunnel {
        fake: Fake,
        on_state: StateSink,
    }

    impl HostTunnel for FakeTunnel {
        async fn connect(&mut self, options: ConnectOptions) -> Result<Listeners, HostError> {
            lock(&self.fake.seen.connects).push(options);
            if let Some(gate) = &self.fake.gate {
                gate.notified().await;
            }
            if let Some(e) = &self.fake.connect_error {
                return Err(e.clone());
            }
            (self.on_state)(HostState::Connected);
            Ok(Listeners {
                endpoints: listeners(),
                username: self
                    .fake
                    .username
                    .clone()
                    .unwrap_or_else(|| "warren".into()),
                password: Zeroizing::new(
                    self.fake
                        .password
                        .clone()
                        .unwrap_or_else(|| "session-secret".into()),
                ),
            })
        }

        async fn shutdown(self) {
            self.fake.seen.shutdowns.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl HostBackend for Fake {
        type Tunnel = FakeTunnel;

        async fn create_tunnel(
            &self,
            mnemonic: Zeroizing<String>,
            on_state: StateSink,
            init: TunnelInit,
        ) -> Result<FakeTunnel, HostError> {
            lock(&self.seen.mnemonics).push(mnemonic.to_string());
            lock(&self.seen.inits).push(init);
            lock(&self.seen.sinks).push(Arc::clone(&on_state));
            if let Some(e) = &self.create_error {
                return Err(e.clone());
            }
            Ok(FakeTunnel {
                fake: self.clone(),
                on_state,
            })
        }

        async fn list_exits(
            &self,
            channel: Option<Channel>,
        ) -> Result<Vec<ExitLocation>, HostError> {
            lock(&self.seen.exits_channels).push(channel);
            self.exits.clone().unwrap_or(Ok(Vec::new()))
        }

        async fn account_expiry(
            &self,
            mnemonic: Zeroizing<String>,
            channel: Option<Channel>,
        ) -> Result<u64, HostError> {
            lock(&self.seen.mnemonics).push(mnemonic.to_string());
            lock(&self.seen.account_channels).push(channel);
            self.account.clone().unwrap_or(Ok(1))
        }
    }

    fn listeners() -> Endpoints {
        Endpoints {
            socks5: "127.0.0.1:1080".into(),
            http: Some("127.0.0.1:8118".into()),
        }
    }

    struct Harness {
        session: HostSession<Fake>,
        sent: Arc<Mutex<Vec<Value>>>,
        seen: Arc<Seen>,
    }

    impl Harness {
        fn new(fake: Fake) -> Self {
            let sent = Arc::new(Mutex::new(Vec::new()));
            let sink = Arc::clone(&sent);
            let seen = Arc::clone(&fake.seen);
            let session = HostSession::new(fake, Arc::new(move |m| lock(&sink).push(m)));
            Self {
                session,
                sent,
                seen,
            }
        }

        async fn send(&self, json: Value) {
            match decode_request(json.to_string().as_bytes()) {
                Decoded::Request(envelope) => self.session.handle(envelope).await,
                _ => panic!("not a request: {json}"),
            }
        }

        fn sent(&self) -> Vec<Value> {
            lock(&self.sent).clone()
        }

        fn last(&self) -> Value {
            self.sent().last().cloned().expect("a message was sent")
        }

        fn shutdowns(&self) -> usize {
            self.seen.shutdowns.load(Ordering::SeqCst)
        }
    }

    fn hello(id: u64) -> Value {
        json!({ "id": id, "type": "hello", "protocol": PROTOCOL_VERSION })
    }

    fn connect(id: u64) -> Value {
        json!({ "id": id, "type": "connect", "mnemonic": M })
    }

    #[tokio::test]
    async fn answers_hello_with_the_protocol_and_a_ready_datapath() {
        let h = Harness::new(Fake::default());
        h.send(hello(1)).await;
        assert_eq!(
            h.last(),
            json!({ "id": 1, "ok": true, "type": "hello", "protocol": 3, "datapath": "ready" })
        );
    }

    #[tokio::test]
    async fn refuses_every_other_protocol_version() {
        // 1 cannot answer its listeners, 2 does not name its channel.
        for version in [json!(1), json!(2), json!(42), json!("3"), Value::Null] {
            let h = Harness::new(Fake::default());
            h.send(json!({ "id": 1, "type": "hello", "protocol": version }))
                .await;
            assert_eq!(h.last()["code"], "protocol", "version {version}");
            assert_eq!(h.last()["ok"], false);
        }
    }

    #[tokio::test]
    async fn refuses_a_hello_naming_a_channel_it_does_not_know() {
        for channel in [json!("staging"), Value::Null, json!(7)] {
            let h = Harness::new(Fake::default());
            h.send(json!({ "id": 1, "type": "hello", "protocol": 3, "channel": channel }))
                .await;
            assert_eq!(h.last()["code"], "protocol", "channel {channel}");
        }
    }

    #[tokio::test]
    async fn reaches_the_api_of_the_channel_the_extension_names_at_hello() {
        let h = Harness::new(Fake::default());
        h.send(json!({ "id": 1, "type": "hello", "protocol": 3, "channel": "beta" }))
            .await;
        h.send(json!({ "id": 2, "type": "exits" })).await;
        h.send(json!({ "id": 3, "type": "account", "mnemonic": M }))
            .await;
        h.send(connect(4)).await;
        assert_eq!(*lock(&h.seen.exits_channels), vec![Some(Channel::Beta)]);
        assert_eq!(*lock(&h.seen.account_channels), vec![Some(Channel::Beta)]);
        assert_eq!(
            lock(&h.seen.inits)[0],
            TunnelInit {
                daita: None,
                channel: Some(Channel::Beta)
            }
        );
    }

    #[tokio::test]
    async fn names_no_channel_when_the_extension_named_none() {
        let h = Harness::new(Fake::default());
        h.send(hello(1)).await;
        h.send(connect(2)).await;
        assert_eq!(lock(&h.seen.inits)[0].channel, None);
    }

    #[tokio::test]
    async fn connects_with_the_per_request_mnemonic_and_forwards_state_events() {
        let h = Harness::new(Fake::default());
        h.send(
            json!({ "id": 2, "type": "connect", "mnemonic": M, "selector": { "country": "NL" } }),
        )
        .await;
        assert_eq!(*lock(&h.seen.mnemonics), vec![M.to_owned()]);
        assert_eq!(
            lock(&h.seen.connects)[0].selector,
            Some(ExitQuery {
                country: Some("NL".into()),
                ..ExitQuery::default()
            })
        );
        assert_eq!(
            h.sent(),
            vec![
                json!({ "type": "state", "state": "connected" }),
                json!({ "id": 2, "ok": true, "type": "connect",
                        "endpoints": { "socks5": "127.0.0.1:1080", "http": "127.0.0.1:8118" },
                        "auth": { "username": "warren", "password": "session-secret" } }),
            ]
        );
    }

    #[tokio::test]
    async fn fails_the_connect_and_tears_down_when_it_hands_over_no_credentials() {
        let h = Harness::new(Fake {
            password: Some(String::new()),
            ..Fake::default()
        });
        h.send(connect(3)).await;
        assert_eq!(h.last()["code"], "protocol");
        assert_eq!(h.shutdowns(), 1);
        h.send(json!({ "id": 4, "type": "status" })).await;
        assert_eq!(h.last()["state"], "disconnected");
    }

    #[tokio::test]
    async fn maps_a_tunnel_failure_to_its_code_and_tears_the_tunnel_down() {
        let h = Harness::new(Fake {
            connect_error: Some(HostError::new("api", "server returned status 402")),
            ..Fake::default()
        });
        h.send(connect(3)).await;
        assert_eq!(
            h.last(),
            json!({ "id": 3, "ok": false, "code": "api", "message": "server returned status 402" })
        );
        assert_eq!(h.shutdowns(), 1);
    }

    #[tokio::test]
    async fn keeps_the_code_of_a_tunnel_that_could_not_be_built() {
        let h = Harness::new(Fake {
            create_error: Some(HostError::new("identity", "invalid mnemonic")),
            ..Fake::default()
        });
        h.send(connect(1)).await;
        assert_eq!(h.last()["code"], "identity");
        assert_eq!(h.shutdowns(), 0);
    }

    #[tokio::test]
    async fn rejects_a_second_connect_while_connected() {
        let h = Harness::new(Fake::default());
        h.send(connect(1)).await;
        h.send(connect(2)).await;
        assert_eq!(h.last()["id"], 2);
        assert_eq!(h.last()["code"], "already_connected");
    }

    #[tokio::test]
    async fn status_reflects_the_lifecycle_and_disconnect_shuts_the_tunnel_down() {
        let h = Harness::new(Fake::default());
        h.send(json!({ "id": 1, "type": "status" })).await;
        assert_eq!(h.last()["state"], "disconnected");
        h.send(connect(2)).await;
        h.send(json!({ "id": 3, "type": "status" })).await;
        assert_eq!(
            h.last(),
            json!({ "id": 3, "ok": true, "type": "status", "state": "connected",
                    "endpoints": { "socks5": "127.0.0.1:1080", "http": "127.0.0.1:8118" } })
        );
        h.send(json!({ "id": 4, "type": "disconnect" })).await;
        assert_eq!(
            h.last(),
            json!({ "id": 4, "ok": true, "type": "disconnect" })
        );
        assert_eq!(h.shutdowns(), 1);
        h.send(json!({ "id": 5, "type": "status" })).await;
        assert_eq!(h.last()["state"], "disconnected");
    }

    #[tokio::test]
    async fn answers_an_unknown_request_with_a_protocol_error() {
        let h = Harness::new(Fake::default());
        h.send(json!({ "id": 9, "type": "reboot" })).await;
        assert_eq!(
            h.last(),
            json!({ "id": 9, "ok": false, "code": "protocol", "message": "unknown request type" })
        );
    }

    #[tokio::test]
    async fn forwards_the_entry_selector_and_http_proxy_to_the_tunnel_connect() {
        let h = Harness::new(Fake::default());
        h.send(json!({ "id": 20, "type": "connect", "mnemonic": M,
                       "selector": { "country": "DE" }, "entrySelector": { "country": "NL" },
                       "httpProxy": true }))
            .await;
        let seen = lock(&h.seen.connects)[0].clone();
        assert_eq!(
            seen.entry_selector,
            Some(EntryQuery {
                country: Some("NL".into()),
                city: None
            })
        );
        assert_eq!(seen.http_proxy, Some(true));
    }

    #[tokio::test]
    async fn passes_the_daita_flag_through_to_the_tunnel_factory() {
        let h = Harness::new(Fake::default());
        h.send(json!({ "id": 12, "type": "connect", "mnemonic": M, "daita": true }))
            .await;
        assert_eq!(lock(&h.seen.inits)[0].daita, Some(true));
    }

    #[tokio::test]
    async fn lists_exit_locations_from_the_discovery_source() {
        let locations = vec![
            ExitLocation {
                country: "NL".into(),
                city: "Amsterdam".into(),
                active: true,
            },
            ExitLocation {
                country: "SG".into(),
                city: "Singapore".into(),
                active: false,
            },
        ];
        let h = Harness::new(Fake {
            exits: Some(Ok(locations)),
            ..Fake::default()
        });
        h.send(json!({ "id": 7, "type": "exits" })).await;
        assert_eq!(
            h.last(),
            json!({ "id": 7, "ok": true, "type": "exits", "locations": [
                { "country": "NL", "city": "Amsterdam", "active": true },
                { "country": "SG", "city": "Singapore", "active": false },
            ] })
        );
    }

    #[tokio::test]
    async fn maps_an_exits_failure_to_a_typed_error() {
        let h = Harness::new(Fake {
            exits: Some(Err(HostError::new("discovery", "relay list expired"))),
            ..Fake::default()
        });
        h.send(json!({ "id": 8, "type": "exits" })).await;
        assert_eq!(h.last()["code"], "discovery");
    }

    #[tokio::test]
    async fn reports_the_account_subscription_using_the_per_request_mnemonic() {
        let h = Harness::new(Fake {
            account: Some(Ok(1_790_000_000)),
            ..Fake::default()
        });
        h.send(json!({ "id": 10, "type": "account", "mnemonic": M }))
            .await;
        assert_eq!(*lock(&h.seen.mnemonics), vec![M.to_owned()]);
        assert_eq!(
            h.last(),
            json!({ "id": 10, "ok": true, "type": "account", "expiresAt": 1_790_000_000u64 })
        );
    }

    #[tokio::test]
    async fn maps_an_account_failure_to_a_typed_error() {
        let h = Harness::new(Fake {
            account: Some(Err(HostError::new("server", "server returned status 404"))),
            ..Fake::default()
        });
        h.send(json!({ "id": 11, "type": "account", "mnemonic": M }))
            .await;
        assert_eq!(h.last()["code"], "server");
    }

    #[tokio::test]
    async fn close_tears_down_a_live_tunnel() {
        let h = Harness::new(Fake::default());
        h.send(connect(1)).await;
        h.session.close().await;
        assert_eq!(h.shutdowns(), 1);
    }

    #[tokio::test]
    async fn refuses_a_connect_once_closed() {
        let h = Harness::new(Fake::default());
        h.session.close().await;
        h.send(connect(1)).await;
        assert_eq!(h.last()["code"], "tunnel");
        assert!(lock(&h.seen.mnemonics).is_empty(), "no tunnel was built");
    }

    #[tokio::test]
    async fn a_disconnect_during_a_connect_tears_the_tunnel_down_when_it_lands() {
        let gate = Arc::new(Notify::new());
        let h = Harness::new(Fake {
            gate: Some(Arc::clone(&gate)),
            ..Fake::default()
        });
        tokio::join!(h.send(connect(1)), async {
            // The connect is parked at the gate: disconnect, then let it land.
            tokio::task::yield_now().await;
            h.send(json!({ "id": 2, "type": "disconnect" })).await;
            gate.notify_one();
        });
        assert_eq!(h.shutdowns(), 1);
        let connect_answer = h.sent().into_iter().find(|m| m["id"] == 1).unwrap();
        assert_eq!(connect_answer["ok"], false);
        assert_eq!(connect_answer["code"], "tunnel");
        h.send(json!({ "id": 3, "type": "status" })).await;
        assert_eq!(h.last()["state"], "disconnected");
        // A fresh connect is accepted afterwards.
        gate.notify_one();
        h.send(connect(4)).await;
        assert_eq!(h.last()["ok"], true);
    }

    #[tokio::test]
    async fn drops_state_events_from_a_torn_down_tunnel() {
        let h = Harness::new(Fake::default());
        h.send(connect(1)).await;
        h.send(json!({ "id": 2, "type": "disconnect" })).await;
        let stale = Arc::clone(&lock(&h.seen.sinks)[0]);
        let before = h.sent().len();
        stale(HostState::Reconnecting);
        assert_eq!(h.sent().len(), before);
        h.send(json!({ "id": 3, "type": "status" })).await;
        assert_eq!(h.last()["state"], "disconnected");
    }
}
