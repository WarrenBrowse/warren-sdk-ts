//! napi-rs binding of the Warren engine's non-root proxy datapath.
//!
//! The connect/shutdown race is delegated to [`lifecycle`], kept generic
//! and unit-tested without a live tunnel. This module wires the engine
//! (`warren-sdk`) to it and exposes the napi surface consumed by the TS
//! facade.

mod lifecycle;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use napi::threadsafe_function::{ErrorStrategy, ThreadsafeFunction, ThreadsafeFunctionCallMode};
use napi::JsFunction;
use napi_derive::napi;

use warren_sdk::api::ClientError;
use warren_sdk::discovery::{CircuitPolicy, VerifiedExit};
use warren_sdk::identity::WarrenIdentity;
use warren_sdk::net::{ForwardedPort, MapProto, ProxyConfig};
use warren_sdk::transport::{FatalCause, MultihopMetricsSnapshot};
use warren_sdk::{
    BuildError, Circuit, ConnectionState, FileGenerationStore, FileServerKeyStore, ProxyHandle,
    SdkError, SupervisedForwardedPort, SupervisedProxyHandle, TunnelState, WarrenClient,
};

use lifecycle::{BeginConnectError, FinishConnect, SessionSlot};

type Client = WarrenClient<warren_sdk::api::ReqwestTransport>;

// ---------------------------------------------------------------------------
// Errors: every engine failure crosses the boundary as `"<kind>: message"`,
// never a raw engine `Display` that could embed an endpoint/IP/pubkey the
// engine has not already redacted. `kind` is a stable JS-dispatchable
// prefix mirroring the sibling SDKs' sealed `WarrenError` hierarchy (identity,
// api, discovery, tunnel, config, unsupported): split the reason on the first
// `": "` to get `(kind, message)` on the JS side.
// ---------------------------------------------------------------------------

fn err(kind: &str, message: impl std::fmt::Display) -> napi::Error {
    napi::Error::from_reason(format!("{kind}: {message}"))
}

/// Maps a [`ClientError`] to a redacted napi error. The server-status body is
/// never surfaced (server-controlled, may echo identity material); only the
/// status code and the engine's own redaction-safe `Display` cross over.
fn map_client_error(e: ClientError) -> napi::Error {
    match e {
        ClientError::ServerStatus { status, .. } => {
            err("api", format_args!("server returned status {status}"))
        }
        other => err("api", other),
    }
}

/// Maps an [`SdkError`] to a redacted napi error, picking `kind` from the
/// variant's category. Every arm's message is the engine's own `Display`,
/// documented no-log-safe on `SdkError` (fixed strings or transparent wraps of
/// equally-safe errors); the API case defers to [`map_client_error`] so a
/// server status stays structured instead of stringified twice.
fn map_sdk_error(e: SdkError) -> napi::Error {
    match e {
        SdkError::Api(inner) => map_client_error(inner),
        SdkError::Discovery(_)
        | SdkError::MultihopDirectory(_)
        | SdkError::Selector(_)
        | SdkError::NoMultihopDirectory
        | SdkError::StaleMultihopDirectory
        | SdkError::RolledBackMultihopDirectory { .. }
        | SdkError::NoMultihopExit
        | SdkError::StaleRelayList
        | SdkError::RolledBackRelayList { .. } => err("discovery", e),
        SdkError::ExitDnsDisabled => err("unsupported", e),
        SdkError::UnknownDaitaMachine { .. }
        | SdkError::EmptyDaitaPool
        | SdkError::DaitaConfig(_) => err("config", e),
        SdkError::Build(inner) => map_build_error(inner),
        // Tunnel/transport/datapath failures (handshake, multihop, listener
        // bind, TUN setup, NAT-PMP): no identity material in their Display.
        SdkError::Tunnel(_)
        | SdkError::Multihop(_)
        | SdkError::Proxy(_)
        | SdkError::Tun(_)
        | SdkError::PortForward(_) => err("tunnel", e),
        // `SdkError` is `#[non_exhaustive]`: an engine-added variant we do not
        // yet special-case still crosses over, generically categorized.
        _ => err("tunnel", e),
    }
}

fn map_build_error(e: BuildError) -> napi::Error {
    err("config", e)
}

/// Parses a 64-hex-char Ed25519 pubkey; a redacted `config` error on failure
/// (the offending string is not echoed back, only its length category).
fn hex32(s: &str) -> napi::Result<[u8; 32]> {
    let bytes = hex::decode(s).map_err(|_| err("config", "invalid hex pubkey"))?;
    <[u8; 32]>::try_from(bytes).map_err(|_| err("config", "pubkey must be 32 bytes"))
}

// ---------------------------------------------------------------------------
// Constructor options
// ---------------------------------------------------------------------------

/// Optional client knobs beyond the required mnemonic/apiBase/serverPubkeyPin,
/// mirroring [`warren_sdk::WarrenClientBuilder`] and the sibling SDKs'
/// `WarrenClientConfig`.
#[napi(object)]
#[derive(Default)]
pub struct WarrenProxyOptions {
    /// Anti-censorship fallback hostnames tried when the primary `apiBase` is
    /// unreachable.
    pub alternative_hosts: Option<Vec<String>>,
    /// Offline multihop-directory ROOT Ed25519 pubkey pin (64-hex). Anchors the
    /// operational certificate to a pinned root instead of trust-on-first-use.
    pub multihop_root_pin_hex: Option<String>,
    /// Enables the DAITA uplink traffic-analysis defense on multihop tunnels.
    pub daita: Option<bool>,
    /// Pins DAITA to a named curated-pool machine; implies `daita`.
    pub daita_machine: Option<String>,
    /// Requests a dual-stack IPv6 allocation from exits that grant one.
    pub request_ipv6: Option<bool>,
    /// Directory to persist the anti-rollback floors and the TOFU server pin
    /// across restarts (`FileGenerationStore`/`FileServerKeyStore`). Without it
    /// they live in memory only.
    pub state_dir: Option<String>,
}

// ---------------------------------------------------------------------------
// Connect-time options
// ---------------------------------------------------------------------------

/// Exit selection for `connect()`. All fields optional; an all-`None` query
/// picks the first cross-checked multihop exit.
#[napi(object)]
#[derive(Default)]
pub struct ExitQuery {
    /// Exact exit Ed25519 pubkey (64-hex), matching the warrend IPC connect
    /// message. Takes priority; combine with `country`/`city` to also require
    /// they match (normally redundant with an exact pubkey).
    pub exit_pubkey_hex: Option<String>,
    /// ISO 3166-1 alpha-2 country filter.
    pub country: Option<String>,
    /// City filter.
    pub city: Option<String>,
}

/// Multihop **entry** hop selection for `connect()`: which country/city the
/// circuit enters the Warren fleet through. The entry is always a node
/// distinct from the exit (unlinkability rule); a query only matching the
/// exit's own node fails the connect rather than silently degrading.
#[napi(object)]
#[derive(Default)]
pub struct EntryQuery {
    /// ISO 3166-1 alpha-2 country filter.
    pub country: Option<String>,
    /// City filter.
    pub city: Option<String>,
}

/// Per-connect knobs.
#[napi(object)]
#[derive(Default)]
pub struct ConnectOptions {
    /// Exit selection; `None` picks the first cross-checked exit.
    pub selector: Option<ExitQuery>,
    /// Multihop entry selection. `None` keeps the default circuit (the
    /// exit's own co-located relay). Ignored when failover candidates are
    /// set (failover rotation manages its own dialing).
    pub entry_selector: Option<EntryQuery>,
    /// Prioritized exit pubkey candidates (64-hex each) for failover: the
    /// datapath sticks with the first that connects and rotates past a broken
    /// one, wrapping around the list. When non-empty, `selector` is ignored and
    /// the self-healing datapath is always used (failover needs it).
    pub failover_exit_pubkey_hexes: Option<Vec<String>>,
    /// Also bind a local HTTP CONNECT proxy alongside SOCKS5.
    pub http_proxy: Option<bool>,
    /// Resolve DNS over the tunnel at this IPv4 address instead of the exit
    /// gateway forwarder. Needed for an exit that runs no DNS forwarder.
    pub dns_server: Option<String>,
    /// Self-healing datapath that keeps the local listeners stable across
    /// reconnects (default `true`, the recommended path). `false` uses the
    /// one-shot datapath instead, which additionally exposes live
    /// [`WarrenProxy::metrics`] and an async, grant-awaiting
    /// [`WarrenProxy::forward_port`] (the self-healing datapath tracks no
    /// per-session metrics upstream, and its forwarded ports establish in the
    /// background instead of awaiting the grant).
    pub supervised: Option<bool>,
}

/// The bound proxy listener addresses returned by `connect()`.
#[napi(object)]
pub struct ConnectEndpoints {
    /// The SOCKS5 listener address (`ip:port`).
    pub socks5: String,
    /// The HTTP CONNECT listener address, if `httpProxy` was requested.
    pub http: Option<String>,
}

/// A point-in-time snapshot of the multihop session counters. Only available
/// on the one-shot datapath (`connect({ supervised: false })`); `null` on the
/// self-healing datapath, which the engine does not currently instrument with
/// live counters.
#[napi(object)]
pub struct MetricsSnapshot {
    /// Total inner IP bytes sealed and sent (approximate: widened to `f64`).
    pub bytes_sent: f64,
    /// Total inner IP bytes received and opened.
    pub bytes_recv: f64,
    /// Total IP packets sent.
    pub packets_sent: f64,
    /// Total IP packets received.
    pub packets_recv: f64,
    /// Total DAITA cover-traffic frames sent.
    pub cover_packets_sent: f64,
    /// Current HPKE epoch (rotates on rekey).
    pub epoch: u32,
    /// Seconds since the session was established.
    pub uptime_secs: f64,
}

impl From<MultihopMetricsSnapshot> for MetricsSnapshot {
    fn from(s: MultihopMetricsSnapshot) -> Self {
        // widened to f64 for the JS side; a session would need to move
        // exabytes for this to lose precision.
        Self {
            bytes_sent: s.bytes_sent as f64,
            bytes_recv: s.bytes_recv as f64,
            packets_sent: s.packets_sent as f64,
            packets_recv: s.packets_recv as f64,
            cover_packets_sent: s.cover_packets_sent as f64,
            epoch: s.epoch,
            uptime_secs: s.uptime_secs as f64,
        }
    }
}

/// Transport selector for a forwarded port.
#[napi(string_enum)]
pub enum MapProtoJs {
    Tcp,
    Udp,
}

impl From<MapProtoJs> for MapProto {
    fn from(p: MapProtoJs) -> Self {
        match p {
            MapProtoJs::Tcp => MapProto::Tcp,
            MapProtoJs::Udp => MapProto::Udp,
        }
    }
}

/// Why the self-healing supervisor gave up (state `"failed"` with a definitive
/// cause), mirroring [`warren_sdk::transport::FatalCause`] across the boundary so
/// the JS side can distinguish an unauthorized account, a device-limit rejection
/// and an opaque policy refusal instead of collapsing them to one "tunnel failed"
/// kind and retrying a fatal forever. The engine owns this classification; this
/// binding maps, it never re-decides.
///
/// Read via [`WarrenProxy::fatal_cause`]. A `"failed"` reached by mere retry
/// exhaustion (a transient failure that never resolved) carries NO fatal cause,
/// so the accessor returns `null` there: a present cause is precisely the "no
/// redial or other exit will help, tell the user" signal.
#[napi(string_enum)]
pub enum FatalCauseJs {
    /// The identity has no active subscription, or is not in the exit allowlist.
    /// The user must provision or renew; retrying reproduces it.
    NotAuthorized,
    /// The account already holds its maximum simultaneous devices.
    DeviceLimit,
    /// The exit closed with the opaque policy-rejection code and no sealed cause
    /// arrived: definitive, but the specific reason is unknown to the client.
    PolicyRefused,
}

impl From<FatalCause> for FatalCauseJs {
    fn from(cause: FatalCause) -> Self {
        match cause {
            FatalCause::NotAuthorized => FatalCauseJs::NotAuthorized,
            FatalCause::DeviceLimit => FatalCauseJs::DeviceLimit,
            FatalCause::PolicyRefused => FatalCauseJs::PolicyRefused,
            // `FatalCause` is `#[non_exhaustive]`: an engine-added fatal we do not
            // yet name still crosses as a definitive refusal (never a false
            // "retryable"), matching the FFI's mapping.
            _ => FatalCauseJs::PolicyRefused,
        }
    }
}

// ---------------------------------------------------------------------------
// The live proxy session and its napi wrappers
// ---------------------------------------------------------------------------

/// The running datapath, whichever backend `connect()` chose.
enum ProxySession {
    /// One-shot multihop datapath: exposes metrics, no self-healing.
    Plain(ProxyHandle),
    /// Self-healing datapath: stable address across reconnects, no metrics.
    Supervised(SupervisedProxyHandle),
}

impl ProxySession {
    fn socks5_addr(&self) -> SocketAddr {
        match self {
            Self::Plain(h) => h.local_addr(),
            Self::Supervised(h) => h.local_addr(),
        }
    }

    fn http_addr(&self) -> Option<SocketAddr> {
        match self {
            Self::Plain(h) => h.http_addr(),
            Self::Supervised(h) => h.http_addr(),
        }
    }

    fn endpoints(&self) -> ConnectEndpoints {
        ConnectEndpoints {
            socks5: self.socks5_addr().to_string(),
            http: self.http_addr().map(|a| a.to_string()),
        }
    }

    fn metrics(&self) -> Option<MetricsSnapshot> {
        match self {
            Self::Plain(h) => h.metrics().map(Into::into),
            Self::Supervised(_) => None,
        }
    }

    fn shutdown(self) {
        match self {
            Self::Plain(h) => h.shutdown(),
            Self::Supervised(h) => h.shutdown(),
        }
    }

    /// Spawns the state-forwarding task feeding `on_state`. The caller tracks
    /// the returned join handle and aborts it on teardown: an un-aborted
    /// forwarder could otherwise call into JS describing a session that no
    /// longer exists.
    fn spawn_state_forwarder(&self, on_state: StateFn) -> tokio::task::JoinHandle<()> {
        match self {
            Self::Plain(h) => {
                let mut rx = h.watch_state();
                tokio::spawn(async move {
                    loop {
                        let state = *rx.borrow_and_update();
                        on_state.call(
                            map_tunnel_state(state),
                            ThreadsafeFunctionCallMode::NonBlocking,
                        );
                        if rx.changed().await.is_err() {
                            break;
                        }
                    }
                })
            }
            Self::Supervised(h) => {
                let mut rx = h.watch_state();
                tokio::spawn(async move {
                    loop {
                        let state = *rx.borrow_and_update();
                        on_state.call(
                            map_connection_state(state).to_owned(),
                            ThreadsafeFunctionCallMode::NonBlocking,
                        );
                        if rx.changed().await.is_err() {
                            break;
                        }
                    }
                })
            }
        }
    }
}

fn map_tunnel_state(state: TunnelState) -> String {
    match state {
        TunnelState::Connected => "connected",
        TunnelState::Disconnected => "disconnected",
        // `TunnelState` is `#[non_exhaustive]`.
        _ => "unknown",
    }
    .to_owned()
}

fn map_connection_state(state: ConnectionState) -> &'static str {
    match state {
        ConnectionState::Connecting => "connecting",
        ConnectionState::Connected => "connected",
        ConnectionState::Reconnecting => "reconnecting",
        ConnectionState::Draining => "draining",
        ConnectionState::Failed => "failed",
        _ => "unknown",
    }
}

/// The state-callback shape: a plain string, fatal on a JS-side throw (mirrors
/// how the FFI observer callback is fire-and-forget).
type StateFn = ThreadsafeFunction<String, ErrorStrategy::Fatal>;

/// What lives in the session slot: the datapath plus its state-forwarding
/// task, torn down together.
struct ConnectedSession {
    proxy: ProxySession,
    state_forwarder: Option<tokio::task::JoinHandle<()>>,
}

impl ConnectedSession {
    fn shutdown(self) {
        if let Some(task) = self.state_forwarder {
            task.abort();
        }
        self.proxy.shutdown();
    }
}

/// A forwarded tunnel-side port (see [`WarrenProxy::forward_port`]).
#[napi]
pub struct WarrenForwardedPort {
    internal_port: u16,
    inner: tokio::sync::Mutex<Option<ForwardedPortKind>>,
}

enum ForwardedPortKind {
    /// One-shot datapath: the grant already happened (awaited inside
    /// `forward_port`), so `external_port` is fixed for this handle's life.
    Plain(ForwardedPort),
    /// Self-healing datapath: the mapping re-establishes across reconnects, so
    /// `external_port` can change and starts `None` until first granted.
    Supervised(SupervisedForwardedPort),
}

#[napi]
impl WarrenForwardedPort {
    /// The local internal port being forwarded.
    #[napi(getter)]
    pub fn internal_port(&self) -> u32 {
        u32::from(self.internal_port)
    }

    /// The external port remote peers reach the app on, or `null` if not yet
    /// granted (self-healing datapath) or after `release()`.
    #[napi]
    pub async fn external_port(&self) -> Option<u32> {
        let guard = self.inner.lock().await;
        match guard.as_ref() {
            Some(ForwardedPortKind::Plain(p)) => Some(u32::from(p.external_port())),
            Some(ForwardedPortKind::Supervised(p)) => p.external_port().map(u32::from),
            None => None,
        }
    }

    /// Releases the forward. Idempotent: a second call is a no-op.
    #[napi]
    pub async fn release(&self) {
        let taken = self.inner.lock().await.take();
        match taken {
            Some(ForwardedPortKind::Plain(p)) => p.shutdown().await,
            Some(ForwardedPortKind::Supervised(p)) => p.shutdown(),
            None => {}
        }
    }
}

// ---------------------------------------------------------------------------
// The client
// ---------------------------------------------------------------------------

/// napi-rs binding of the Warren engine's non-root proxy datapath.
#[napi]
pub struct WarrenProxy {
    client: Arc<Client>,
    address: String,
    slot: SessionSlot<ConnectedSession>,
    // Set via `onState` (a plain, non-async setter): building a
    // `ThreadsafeFunction` from a `JsFunction` must happen synchronously, on
    // the JS thread, before any `.await` (a raw `JsFunction` is not `Send` and
    // cannot be a parameter of an async napi method). The built callback itself
    // is `Send + Sync + Clone`, so it is cheap to read here and hand to
    // whichever connect attempt is next.
    on_state: std::sync::Mutex<Option<StateFn>>,
}

#[napi]
impl WarrenProxy {
    #[napi(constructor)]
    pub fn new(
        mnemonic: String,
        api_base: String,
        server_pubkey_pin: String,
        options: Option<WarrenProxyOptions>,
    ) -> napi::Result<Self> {
        let identity = WarrenIdentity::from_mnemonic(mnemonic.trim())
            .map_err(|_| err("identity", "invalid mnemonic"))?;
        let address = identity.address();
        let options = options.unwrap_or_default();

        let mut builder = WarrenClient::builder()
            .identity(identity)
            .api_base(api_base)
            .server_pubkey_pin(server_pubkey_pin);
        if let Some(hosts) = options.alternative_hosts {
            builder = builder.api_alternative_hosts(hosts);
        }
        if let Some(root) = options.multihop_root_pin_hex {
            builder = builder.multihop_root_pubkey_pin(root);
        }
        if let Some(machine) = options.daita_machine {
            builder = builder.daita_machine(machine);
        } else if options.daita.unwrap_or(false) {
            builder = builder.daita();
        }
        if options.request_ipv6.unwrap_or(false) {
            builder = builder.request_ipv6();
        }
        if let Some(state_dir) = options.state_dir.as_deref() {
            let dir = std::path::Path::new(state_dir);
            let io_err = |_| err("config", "persistence state directory is not usable");
            std::fs::create_dir_all(dir).map_err(io_err)?;
            let relay_gen =
                FileGenerationStore::new(dir.join("relay_generation")).map_err(io_err)?;
            let mh_gen =
                FileGenerationStore::new(dir.join("multihop_generation")).map_err(io_err)?;
            let key_store = FileServerKeyStore::new(dir.join("server_key")).map_err(io_err)?;
            builder = builder
                .generation_store(Arc::new(relay_gen))
                .multihop_generation_store(Arc::new(mh_gen))
                .server_key_store(Arc::new(key_store));
        }

        let client = builder.build().map_err(map_build_error)?;
        Ok(Self {
            client: Arc::new(client),
            address,
            slot: SessionSlot::new(),
            on_state: std::sync::Mutex::new(None),
        })
    }

    /// The signer's SS58 `wb...` address (sanity check).
    #[napi(getter)]
    pub fn address(&self) -> String {
        self.address.clone()
    }

    /// Registers (or replaces) the state-change callback for future
    /// `connect()` calls: called with a lifecycle state string on every
    /// transition: `"connecting"`, `"connected"`, `"reconnecting"`,
    /// `"draining"`, `"failed"` on the self-healing datapath (the default), or
    /// `"connected"` / `"disconnected"` on the one-shot datapath
    /// (`supervised: false`). Call before `connect()`; it has no effect on an
    /// already-running session. Pass `null`/`undefined` to stop reporting.
    #[napi]
    pub fn on_state(&self, callback: Option<JsFunction>) -> napi::Result<()> {
        let tsfn = callback
            .map(|f| f.create_threadsafe_function(0, |ctx| Ok(vec![ctx.value])))
            .transpose()?;
        *self
            .on_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = tsfn;
        Ok(())
    }

    /// Brings up a real multihop tunnel and local proxy listener(s); resolves
    /// with the bound address(es). Rejects if a connect is already in flight or
    /// a session is already live (never silently orphans the first one), and
    /// after `shutdown()` (no reconnecting a shut-down client). A `shutdown()`
    /// racing an in-flight connect is honoured fail-closed: the tunnel this
    /// call would have returned is torn down instead of ever being handed back
    /// (see `lifecycle::SessionSlot`). See [`Self::on_state`] for state
    /// reporting.
    #[napi]
    pub async fn connect(&self, options: Option<ConnectOptions>) -> napi::Result<ConnectEndpoints> {
        // Snapshot the registered callback (if any) synchronously: `StateFn` is
        // `Send + Sync + Clone`, unlike the raw `JsFunction` it was built from.
        let state_fn: Option<StateFn> = self
            .on_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();

        match self.slot.begin_connect().await {
            Ok(()) => {}
            Err(BeginConnectError::AlreadyConnecting) => {
                return Err(err("tunnel", "a connect is already in progress"))
            }
            Err(BeginConnectError::AlreadyConnected) => {
                return Err(err("tunnel", "already connected"))
            }
            Err(BeginConnectError::ShutDown) => return Err(err("tunnel", "client is shut down")),
        }

        let result = self.build_session(options, state_fn).await;

        match self
            .slot
            .finish_connect(result, |session| session.proxy.endpoints())
            .await
        {
            FinishConnect::Stored(endpoints) => Ok(endpoints),
            FinishConnect::TornDown(session) => {
                session.shutdown();
                Err(err("tunnel", "shut down while connecting"))
            }
            FinishConnect::Failed(e) => Err(e),
        }
    }

    /// Tears the tunnel down (fail-closed). Idempotent: a second call, or one
    /// racing an in-flight `connect()`, never leaves a live tunnel behind.
    #[napi]
    pub async fn shutdown(&self) {
        if let Some(session) = self.slot.shutdown().await {
            session.shutdown();
        }
    }

    /// A snapshot of the datapath's live counters, or `null` on the
    /// self-healing datapath (see [`MetricsSnapshot`]) or while not connected.
    #[napi]
    pub async fn metrics(&self) -> Option<MetricsSnapshot> {
        self.slot
            .with_connected(|s| s.proxy.metrics())
            .await
            .flatten()
    }

    /// The definitive cause the self-healing supervisor stopped on, or `null`
    /// when it is still healing, exhausted a merely-transient failure, or the
    /// session runs the one-shot datapath (no supervisor). Read it when the
    /// state callback reports `"failed"`: a present cause means no redial or
    /// other exit will help (an expired subscription, a device-limit rejection,
    /// an opaque policy refusal), so the caller must stop retrying and tell the
    /// user instead of looping "reconnecting" forever.
    #[napi]
    pub async fn fatal_cause(&self) -> Option<FatalCauseJs> {
        self.slot
            .with_connected(|s| match &s.proxy {
                ProxySession::Supervised(h) => h.last_fatal().map(FatalCauseJs::from),
                ProxySession::Plain(_) => None,
            })
            .await
            .flatten()
    }

    /// Proves live egress THROUGH the tunnel: runs the engine's SOCKS5
    /// egress-proof (a bounded no-auth CONNECT to `1.1.1.1:443` via the local
    /// proxy, the doc-62 contract in `warren_sdk::socks_egress`). Resolves when
    /// egress is proven; rejects (`egress: ...`) when it is not, so a caller can
    /// fail closed instead of handing traffic to a tunnel that silently drops
    /// it. Rejects with `egress: not connected` before `connect()`.
    #[napi]
    pub async fn verify_egress(&self) -> napi::Result<()> {
        // Read the listener address under the lock, then probe OUTSIDE it: the
        // proof does real network I/O and must not hold the session lock.
        let socks = self
            .slot
            .with_connected(|s| s.proxy.socks5_addr())
            .await
            .ok_or_else(|| err("egress", "not connected"))?;
        warren_sdk::socks_egress::verify_first_egress(
            socks,
            warren_sdk::socks_egress::FIRST_EGRESS_VERIFY,
        )
        .await
        // Surface only the safe attempt count: the underlying probe error can
        // carry addresses (no-log), so it never crosses the boundary.
        .map_err(|dead| {
            err(
                "egress",
                format_args!("egress not proven after {} probe attempts", dead.attempts),
            )
        })
    }

    /// Forwards a tunnel-side port: asks the exit to map `internalPort` via
    /// NAT-PMP and relays inbound connections to `localTarget` (`ip:port`).
    /// On the one-shot datapath this resolves once the exit grants the
    /// mapping; on the self-healing datapath it resolves immediately and the
    /// grant (and every re-grant across reconnects) is observed via
    /// [`WarrenForwardedPort::external_port`].
    ///
    /// Needs an exit that runs a NAT-PMP gateway; not every exit does.
    #[napi]
    pub async fn forward_port(
        &self,
        proto: MapProtoJs,
        internal_port: u32,
        local_target: String,
    ) -> napi::Result<WarrenForwardedPort> {
        let internal_port =
            u16::try_from(internal_port).map_err(|_| err("config", "invalid internal port"))?;
        let target: SocketAddr = local_target
            .parse()
            .map_err(|_| err("config", "invalid local target address"))?;
        let proto: MapProto = proto.into();

        // One-shot datapath: detach a cheap forwarder and await the grant
        // outside any lock (the engine's own doc'd pattern for this).
        let plain_forwarder = self
            .slot
            .with_connected(|s| match &s.proxy {
                ProxySession::Plain(h) => Some(h.forwarder()),
                ProxySession::Supervised(_) => None,
            })
            .await
            .flatten();
        if let Some(forwarder) = plain_forwarder {
            let forwarded = forwarder
                .forward_port(proto, internal_port, target)
                .await
                .map_err(map_sdk_error)?;
            return Ok(WarrenForwardedPort {
                internal_port: forwarded.internal_port(),
                inner: tokio::sync::Mutex::new(Some(ForwardedPortKind::Plain(forwarded))),
            });
        }

        // Self-healing datapath: `forward_port` is synchronous and returns
        // immediately; the grant (and every re-grant) happens in the
        // background and is observed via the returned handle.
        let supervised = self
            .slot
            .with_connected(|s| match &s.proxy {
                ProxySession::Supervised(h) => Some(h.forward_port(proto, internal_port, target)),
                ProxySession::Plain(_) => None,
            })
            .await
            .flatten();
        match supervised {
            Some(port) => Ok(WarrenForwardedPort {
                internal_port,
                inner: tokio::sync::Mutex::new(Some(ForwardedPortKind::Supervised(port))),
            }),
            None => Err(err("tunnel", "not connected")),
        }
    }

    /// Builds the requested datapath: resolves the exit(s), starts the
    /// one-shot or self-healing multihop proxy per `options`, and spawns the
    /// state forwarder if `state_fn` is set. Runs entirely before the slot
    /// records anything, so a `shutdown()` racing this call only takes effect
    /// once the caller passes the result to `finish_connect`.
    async fn build_session(
        &self,
        options: Option<ConnectOptions>,
        state_fn: Option<StateFn>,
    ) -> napi::Result<ConnectedSession> {
        let options = options.unwrap_or_default();
        let http_proxy = options.http_proxy.unwrap_or(false);
        let supervised = options.supervised.unwrap_or(true);
        let dns_server = match options.dns_server.as_deref() {
            Some(s) => Some(
                s.parse::<Ipv4Addr>()
                    .map_err(|_| err("config", "invalid dns server address"))?,
            ),
            None => None,
        };
        let cfg = ProxyConfig {
            socks5: "127.0.0.1:0".parse().expect("valid literal address"),
            http: http_proxy.then(|| "127.0.0.1:0".parse().expect("valid literal address")),
            dns_server,
        };

        let failover = options.failover_exit_pubkey_hexes.unwrap_or_default();
        let proxy = if failover.is_empty() {
            let mut exit = self.resolve_single_exit(options.selector).await?;
            if let Some(entry_query) = options.entry_selector {
                let (entries, policy) = self.fetch_cross_checked_entries().await?;
                // Best-effort advisory: absent or garbage keeps the
                // weight-plus-client-RTT ordering (never an error).
                let advisory = self.client.fetch_path_quality().await;
                exit = compose_circuit(
                    &self.client,
                    &exit,
                    &entries,
                    &policy,
                    &entry_query,
                    advisory.as_ref(),
                )
                .ok_or_else(|| {
                    err(
                        "discovery",
                        "no cross-checked entry satisfied the entry selector and the \
                             circuit diversity policy (distinct node, different country/AS)",
                    )
                })?;
            }
            if supervised {
                ProxySession::Supervised(
                    self.client
                        .start_proxy_supervised(&Circuit::SingleHop(exit), &cfg)
                        .await
                        .map_err(map_sdk_error)?,
                )
            } else {
                ProxySession::Plain(
                    self.client
                        .start_proxy(&Circuit::SingleHop(exit), &cfg)
                        .await
                        .map_err(map_sdk_error)?,
                )
            }
        } else {
            // Failover always needs the self-healing backend: the one-shot
            // datapath has no candidate rotation.
            let exits = self.resolve_failover_exits(&failover).await?;
            let circuits: Vec<Circuit> = exits.into_iter().map(Circuit::SingleHop).collect();
            ProxySession::Supervised(
                self.client
                    .start_proxy_supervised_failover(&circuits, &cfg)
                    .await
                    .map_err(map_sdk_error)?,
            )
        };

        let state_forwarder = state_fn.map(|f| proxy.spawn_state_forwarder(f));
        Ok(ConnectedSession {
            proxy,
            state_forwarder,
        })
    }

    /// Fetches the signed relay list and the multihop directory, and returns
    /// only the directory exits that are also cross-checked against the
    /// pinned relay list (the engine's documented anti-mint guard: a
    /// compromised online server key alone should not mint an accepted exit).
    async fn fetch_cross_checked_exits(&self) -> napi::Result<Vec<VerifiedExit>> {
        let selector = self.client.fetch_exits().await.map_err(map_sdk_error)?;
        let directory = self
            .client
            .fetch_multihop_directory()
            .await
            .map_err(map_sdk_error)?;
        Ok(directory
            .into_iter()
            .filter(|e| {
                selector
                    .relays()
                    .iter()
                    .any(|r| r.endpoint_id() == e.exit_ed25519_pubkey)
            })
            .collect())
    }

    /// Fetches the multihop directory's entry view, cross-checked against the
    /// pinned relay list exactly like the exits (same anti-mint guard: the
    /// dialed hop must be a node the offline roster vouches for), together with
    /// the fleet-wide [`CircuitPolicy`] that gates every entry-selected circuit.
    /// The policy is derived from the FULL verified directory, not the
    /// cross-checked subset, so its AS-diversity verdict reflects the real
    /// fleet spread.
    async fn fetch_cross_checked_entries(
        &self,
    ) -> napi::Result<(Vec<warren_sdk::discovery::VerifiedEntry>, CircuitPolicy)> {
        let selector = self.client.fetch_exits().await.map_err(map_sdk_error)?;
        let directory = self
            .client
            .fetch_multihop_directory_full()
            .await
            .map_err(map_sdk_error)?;
        let entries = directory
            .entries
            .iter()
            .filter(|e| {
                selector
                    .relays()
                    .iter()
                    .any(|r| r.endpoint_id() == e.relay_ed25519_pubkey)
            })
            .cloned()
            .collect();
        Ok((entries, directory.policy))
    }

    /// Resolves exactly one cross-checked exit matching `query` (an unset
    /// query matches the first cross-checked exit).
    async fn resolve_single_exit(&self, query: Option<ExitQuery>) -> napi::Result<VerifiedExit> {
        let exits = self.fetch_cross_checked_exits().await?;
        let query = query.unwrap_or_default();
        exits
            .into_iter()
            .find(|e| {
                query
                    .exit_pubkey_hex
                    .as_deref()
                    .is_none_or(|hex| hex.eq_ignore_ascii_case(&hex::encode(e.exit_ed25519_pubkey)))
                    && query
                        .country
                        .as_deref()
                        .is_none_or(|c| e.country.eq_ignore_ascii_case(c))
                    && query
                        .city
                        .as_deref()
                        .is_none_or(|c| e.city.eq_ignore_ascii_case(c))
            })
            .ok_or_else(|| err("discovery", "no cross-checked exit matched the selector"))
    }

    /// Resolves the cross-checked exits matching `hexes`, preserving the
    /// caller's priority order (missing/unmatched ids are silently dropped, as
    /// the FFI failover binding does).
    async fn resolve_failover_exits(&self, hexes: &[String]) -> napi::Result<Vec<VerifiedExit>> {
        let exits = self.fetch_cross_checked_exits().await?;
        let mut matched = Vec::with_capacity(hexes.len());
        for hex in hexes {
            let wanted = hex32(hex)?;
            if let Some(exit) = exits.iter().find(|e| e.exit_ed25519_pubkey == wanted) {
                matched.push(exit.clone());
            }
        }
        if matched.is_empty() {
            return Err(err(
                "discovery",
                "no cross-checked exit matched the failover candidates",
            ));
        }
        Ok(matched)
    }
}

/// Composes an entry-selected circuit: the cross-checked entries matching
/// `query` feed the SDK's ONE path-aware selection wiring
/// ([`WarrenClient::select_multihop_entry_among`]: the client's measured
/// entry-RTT history plus the path-quality advisory, gated by the shared
/// diversity policy), so this binding adds a geographic pre-filter and
/// nothing else. `None` when no matching entry forms a policy-legal
/// circuit, so a TS caller can never build a topology the app's security
/// rule forbids.
fn compose_circuit<T: warren_sdk::api::HttpTransport>(
    client: &WarrenClient<T>,
    exit: &VerifiedExit,
    entries: &[warren_sdk::discovery::VerifiedEntry],
    policy: &CircuitPolicy,
    query: &EntryQuery,
    advisory: Option<&warren_sdk::discovery::PathQualityAdvisory>,
) -> Option<VerifiedExit> {
    let matching: Vec<warren_sdk::discovery::VerifiedEntry> = entries
        .iter()
        .filter(|e| {
            query
                .country
                .as_deref()
                .is_none_or(|c| e.country.eq_ignore_ascii_case(c))
                && query
                    .city
                    .as_deref()
                    .is_none_or(|c| e.city.eq_ignore_ascii_case(c))
        })
        .cloned()
        .collect();
    client.select_multihop_entry_among(&matching, exit, policy, advisory, None)
}

#[cfg(test)]
mod tests {
    use warren_sdk::discovery::VerifiedEntry;

    use super::*;

    /// Offline transport: circuit composition is pure (directory data in,
    /// pick out), so the client under test must never touch HTTP.
    struct NoHttp;

    impl warren_sdk::api::HttpTransport for NoHttp {
        async fn execute(
            &self,
            _req: warren_sdk::api::HttpRequest,
        ) -> Result<warren_sdk::api::HttpResponse, warren_sdk::api::TransportError> {
            Err(warren_sdk::api::TransportError::Connect(
                "offline test transport".to_owned(),
            ))
        }
    }

    fn test_client() -> WarrenClient<NoHttp> {
        let (identity, _mnemonic) = WarrenIdentity::generate();
        WarrenClient::builder()
            .identity(identity)
            .api_base("https://api.invalid")
            .server_pubkey_pin("0".repeat(64))
            .multihop_root_pubkey_pin("0".repeat(64))
            .build_with_transport(NoHttp)
            .expect("offline client builds")
    }

    #[test]
    fn maps_each_engine_fatal_cause_to_its_own_boundary_kind() {
        // The A4 bug is collapsing every fatal to one kind so a subscription
        // rejection loops forever: each engine verdict must cross as a DISTINCT
        // machine-readable kind the JS side can stop on.
        assert!(matches!(
            FatalCauseJs::from(FatalCause::NotAuthorized),
            FatalCauseJs::NotAuthorized
        ));
        assert!(matches!(
            FatalCauseJs::from(FatalCause::DeviceLimit),
            FatalCauseJs::DeviceLimit
        ));
        assert!(matches!(
            FatalCauseJs::from(FatalCause::PolicyRefused),
            FatalCauseJs::PolicyRefused
        ));
    }

    fn exit(tag: u8, country: &str, city: &str) -> VerifiedExit {
        exit_asn(tag, country, city, 0)
    }

    fn exit_asn(tag: u8, country: &str, city: &str, asn: u32) -> VerifiedExit {
        VerifiedExit {
            exit_id: [tag; 16],
            exit_ed25519_pubkey: [tag; 32],
            exit_x25519_multihop_pubkey: [tag; 32],
            endpoint: format!("198.51.100.{tag}:443").parse().unwrap(),
            country: country.to_owned(),
            asn,
            city: city.to_owned(),
            weight: 100,
            dns_disabled: false,
            cover_domain: None,
            tcp_fallback: false,
            edge_cert_sha256: None,
            exit_mlkem768_pubkey: None,
        }
    }

    fn entry(tag: u8, country: &str, city: &str) -> VerifiedEntry {
        entry_asn(tag, country, city, 0)
    }

    fn entry_weight(tag: u8, country: &str, city: &str, weight: u64) -> VerifiedEntry {
        let mut e = entry_asn(tag, country, city, 0);
        e.weight = weight;
        e
    }

    fn entry_asn(tag: u8, country: &str, city: &str, asn: u32) -> VerifiedEntry {
        VerifiedEntry {
            relay_ed25519_pubkey: [tag; 32],
            endpoint: format!("198.51.100.{tag}:443").parse().unwrap(),
            country: country.to_owned(),
            asn,
            city: city.to_owned(),
            weight: 100,
            cover_domain: None,
            tcp_fallback: false,
            edge_cert_sha256: None,
            exit_id: [tag; 16],
        }
    }

    /// The fleet-wide policy for a set of entries (their AS spread), matching
    /// how production derives it from the verified directory.
    fn policy_of(entries: &[VerifiedEntry]) -> CircuitPolicy {
        CircuitPolicy::from_asns(entries.iter().map(|e| e.asn))
    }

    #[test]
    fn composes_a_circuit_through_the_requested_entry_country() {
        let exit = exit(1, "DE", "Kassel");
        let entries = vec![entry(1, "DE", "Kassel"), entry(2, "nl", "Amsterdam")];
        let q = EntryQuery {
            country: Some("NL".to_owned()),
            city: None,
        };
        let dialed = compose_circuit(
            &test_client(),
            &exit,
            &entries,
            &policy_of(&entries),
            &q,
            None,
        )
        .expect("nl entry exists");
        assert_eq!(dialed.endpoint, entries[1].endpoint, "dials the NL relay");
        assert_eq!(dialed.exit_id, exit.exit_id, "still routes to the DE exit");
    }

    #[test]
    fn never_composes_through_the_exits_own_node() {
        // The only entry matching the query is the exit's own node: the
        // unlinkability rule must refuse it rather than fall back silently.
        let exit = exit(1, "DE", "Kassel");
        let entries = vec![entry(1, "DE", "Kassel"), entry(2, "NL", "Amsterdam")];
        let q = EntryQuery {
            country: Some("DE".to_owned()),
            city: None,
        };
        assert!(compose_circuit(
            &test_client(),
            &exit,
            &entries,
            &policy_of(&entries),
            &q,
            None
        )
        .is_none());
    }

    #[test]
    fn an_empty_entry_query_picks_any_distinct_node() {
        let exit = exit(1, "DE", "Kassel");
        let entries = vec![entry(1, "DE", "Kassel"), entry(2, "SG", "Singapore")];
        let q = EntryQuery::default();
        let dialed = compose_circuit(
            &test_client(),
            &exit,
            &entries,
            &policy_of(&entries),
            &q,
            None,
        )
        .expect("distinct node exists");
        assert_eq!(dialed.endpoint, entries[1].endpoint);
    }

    #[test]
    fn city_filter_narrows_the_entry() {
        let exit = exit(1, "DE", "Kassel");
        let entries = vec![entry(2, "NL", "Amsterdam"), entry(3, "NL", "Rotterdam")];
        let q = EntryQuery {
            country: Some("nl".to_owned()),
            city: Some("rotterdam".to_owned()),
        };
        let dialed = compose_circuit(
            &test_client(),
            &exit,
            &entries,
            &policy_of(&entries),
            &q,
            None,
        )
        .expect("rotterdam entry");
        assert_eq!(dialed.endpoint, entries[1].endpoint);
    }

    #[test]
    fn two_legal_candidates_follow_the_shared_weight_order_not_list_order() {
        // The convergence guard: composition must ride the SDK's shared
        // path-aware selection (highest weight product, id tie-break),
        // never this binding's historical first-match-in-list pick.
        let exit = exit(1, "DE", "Kassel");
        let light_first = entry_weight(2, "NL", "Amsterdam", 100);
        let heavy_second = entry_weight(3, "NL", "Rotterdam", 500);
        let entries = vec![light_first, heavy_second.clone()];
        let q = EntryQuery {
            country: Some("NL".to_owned()),
            city: None,
        };
        let dialed = compose_circuit(
            &test_client(),
            &exit,
            &entries,
            &policy_of(&entries),
            &q,
            None,
        )
        .expect("legal candidates exist");
        assert_eq!(
            dialed.endpoint, heavy_second.endpoint,
            "the heavier entry must win regardless of list position"
        );
    }

    #[test]
    fn rejects_a_same_country_or_same_as_entry() {
        // A DE exit on AS100, on a fleet also spanning AS200. The country- and
        // AS-diversity rule must reject a same-country entry AND a same-AS
        // entry, and accept only the country- and AS-diverse one, so a TS
        // client cannot build the topology the app forbids.
        let exit = exit_asn(1, "DE", "Kassel", 100);
        let same_country = entry_asn(2, "DE", "Berlin", 200);
        let same_as = entry_asn(3, "NL", "Amsterdam", 100);
        let diverse = entry_asn(4, "NL", "Rotterdam", 200);
        let entries = vec![same_country.clone(), same_as.clone(), diverse.clone()];
        let policy = policy_of(&entries);
        assert!(policy.as_diversity_required());

        let q = EntryQuery {
            country: Some("DE".to_owned()),
            city: None,
        };
        assert!(
            compose_circuit(&test_client(), &exit, &entries, &policy, &q, None).is_none(),
            "a same-country entry must be refused"
        );

        let q = EntryQuery {
            country: Some("NL".to_owned()),
            city: Some("amsterdam".to_owned()),
        };
        assert!(
            compose_circuit(&test_client(), &exit, &entries, &policy, &q, None).is_none(),
            "a same-AS entry must be refused on a multi-AS fleet"
        );

        let q = EntryQuery {
            country: Some("NL".to_owned()),
            city: Some("rotterdam".to_owned()),
        };
        let dialed = compose_circuit(&test_client(), &exit, &entries, &policy, &q, None)
            .expect("the country- and AS-diverse entry composes");
        assert_eq!(dialed.endpoint, diverse.endpoint);
        assert_eq!(dialed.exit_id, exit.exit_id);
    }
}
