//! The session backend over the Warren engine (`warren-sdk`): the same calls
//! the napi binding makes (`packages/node/native/warren-napi/src/lib.rs`),
//! linked into this binary instead of a Node addon. Nothing here speaks the
//! protocol itself; every datapath and discovery primitive is the SDK's.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use warren_sdk::api::{ClientError, HttpTransport};
use warren_sdk::discovery::{CircuitPolicy, PathQualityAdvisory, VerifiedEntry, VerifiedExit};
use warren_sdk::identity::WarrenIdentity;
use warren_sdk::net::ProxyConfig;
use warren_sdk::product::{self, Channel};
use warren_sdk::{
    Circuit, ConnectionState, FileGenerationStore, FileServerKeyStore, SdkError,
    SupervisedProxyHandle, WarrenClient, WarrenClientBuilder,
};
use zeroize::Zeroizing;

use crate::protocol::{Endpoints, EntryQuery, ExitLocation, ExitQuery, HostState, TunnelExit};
use crate::session::{
    ConnectOptions, ErrorCode, HostBackend, HostError, HostTunnel, Listeners, StateSink, TunnelInit,
};

type Client = WarrenClient<warren_sdk::api::ReqwestTransport>;

/// The channel a request reaches: the one the extension named, else the
/// build's own.
#[must_use]
pub fn effective_channel(named: Option<Channel>) -> Channel {
    named.unwrap_or(product::CHANNEL)
}

/// Maps an API failure to the codes the TypeScript `WarrenApiError` uses. The
/// server body and the transport's own text never cross: the first may echo
/// identity material, the second names addresses.
#[must_use]
pub fn map_client_error(e: &ClientError) -> HostError {
    match e {
        ClientError::ServerStatus { status, .. } => HostError::new(
            ErrorCode::Server,
            format!("server returned status {status}"),
        ),
        ClientError::AllHostsBlocked => HostError::new(
            ErrorCode::AllHostsBlocked,
            "all API hosts are unreachable (no network, or the API is blocked)",
        ),
        ClientError::ResponseEncoding(_) | ClientError::ResponseJson(_) => HostError::new(
            ErrorCode::Response,
            "the API answered in an unexpected shape",
        ),
        ClientError::BadClock => {
            HostError::new(ErrorCode::BadClock, "system clock is before the Unix epoch")
        }
        _ => HostError::new(ErrorCode::Transport, "the API request failed"),
    }
}

/// Maps an engine failure to the kinds the napi binding reports, so the
/// extension sees the codes it already knows from the Node host. Every message
/// is the engine's own redaction-safe `Display`, or a fixed string.
#[must_use]
pub fn map_sdk_error(e: &SdkError) -> HostError {
    match e {
        SdkError::Api(ClientError::ServerStatus { status, .. }) => {
            HostError::new(ErrorCode::Api, format!("server returned status {status}"))
        }
        SdkError::Api(inner) => HostError::new(ErrorCode::Api, map_client_error(inner).message),
        SdkError::Discovery(_)
        | SdkError::MultihopDirectory(_)
        | SdkError::Selector(_)
        | SdkError::NoMultihopDirectory
        | SdkError::StaleMultihopDirectory
        | SdkError::RolledBackMultihopDirectory { .. }
        | SdkError::NoMultihopExit
        | SdkError::StaleRelayList
        | SdkError::RolledBackRelayList { .. } => {
            HostError::new(ErrorCode::Discovery, e.to_string())
        }
        SdkError::ExitDnsDisabled => HostError::new(ErrorCode::Unsupported, e.to_string()),
        SdkError::UnknownDaitaMachine { .. }
        | SdkError::EmptyDaitaPool
        | SdkError::DaitaConfig(_) => HostError::new(ErrorCode::Config, e.to_string()),
        SdkError::Build(_) => HostError::new(ErrorCode::Config, e.to_string()),
        _ => HostError::new(ErrorCode::Tunnel, e.to_string()),
    }
}

fn map_state(state: ConnectionState) -> Option<HostState> {
    match state {
        ConnectionState::Connecting => Some(HostState::Connecting),
        ConnectionState::Connected => Some(HostState::Connected),
        ConnectionState::Reconnecting => Some(HostState::Reconnecting),
        ConnectionState::Draining => Some(HostState::Draining),
        ConnectionState::Failed => Some(HostState::Failed),
        _ => None,
    }
}

/// Whether `exit` satisfies every field `query` sets.
#[must_use]
pub fn exit_matches(exit: &VerifiedExit, query: &ExitQuery) -> bool {
    query
        .exit_pubkey_hex
        .as_deref()
        .is_none_or(|h| h.eq_ignore_ascii_case(&hex::encode(exit.exit_ed25519_pubkey)))
        && query
            .country
            .as_deref()
            .is_none_or(|c| exit.country.eq_ignore_ascii_case(c))
        && query
            .city
            .as_deref()
            .is_none_or(|c| exit.city.eq_ignore_ascii_case(c))
}

/// Names `exit` as the extension shows it: the relay list's country code
/// upper-cased, and its city.
#[must_use]
pub fn tunnel_exit(exit: &VerifiedExit) -> TunnelExit {
    TunnelExit {
        country: exit.country.to_ascii_uppercase(),
        city: exit.city.clone(),
    }
}

/// Composes an entry-selected circuit exactly as the napi binding does: a
/// geographic pre-filter, then the SDK's one path-aware, policy-gated
/// selection. `None` when no matching entry forms a legal circuit.
pub fn compose_circuit<T: HttpTransport>(
    client: &WarrenClient<T>,
    exit: &VerifiedExit,
    entries: &[VerifiedEntry],
    policy: &CircuitPolicy,
    query: &EntryQuery,
    advisory: Option<&PathQualityAdvisory>,
) -> Option<VerifiedExit> {
    let matching: Vec<VerifiedEntry> = entries
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

/// The backend over the live engine. Anti-rollback floors persist under
/// `state_root/<channel>/`: the two channels are separate deployments whose
/// relay lists count generations independently.
pub struct EngineBackend {
    state_root: PathBuf,
}

impl EngineBackend {
    /// A backend persisting its floors under `state_root`.
    #[must_use]
    pub fn new(state_root: PathBuf) -> Self {
        Self { state_root }
    }

    fn client(
        &self,
        identity: WarrenIdentity,
        channel: Channel,
    ) -> Result<WarrenClientBuilder, HostError> {
        let dir = self.state_root.join(channel.name());
        let unusable = |_| {
            HostError::new(
                ErrorCode::Config,
                "the helper state directory is not usable",
            )
        };
        std::fs::create_dir_all(&dir).map_err(unusable)?;
        let relay = FileGenerationStore::new(dir.join("relay_generation")).map_err(unusable)?;
        let multihop =
            FileGenerationStore::new(dir.join("multihop_generation")).map_err(unusable)?;
        let server_key = FileServerKeyStore::new(dir.join("server_key")).map_err(unusable)?;
        Ok(WarrenClient::builder()
            .identity(identity)
            .api_base(channel.api_url())
            .server_pubkey_pin(product::SERVER_PUBKEY_HEX)
            .multihop_root_pubkey_pin(product::MULTIHOP_ROOT_PUBKEY_HEX)
            .generation_store(Arc::new(relay))
            .multihop_generation_store(Arc::new(multihop))
            .server_key_store(Arc::new(server_key)))
    }
}

fn identity_from(mnemonic: &Zeroizing<String>) -> Result<WarrenIdentity, HostError> {
    WarrenIdentity::from_mnemonic(mnemonic.trim())
        .map_err(|_| HostError::new(ErrorCode::Identity, "invalid mnemonic"))
}

fn build(builder: WarrenClientBuilder) -> Result<Client, HostError> {
    builder
        .build()
        .map_err(|e| map_sdk_error(&SdkError::Build(e)))
}

impl HostBackend for EngineBackend {
    type Tunnel = EngineTunnel;

    async fn create_tunnel(
        &self,
        mnemonic: Zeroizing<String>,
        on_state: StateSink,
        init: TunnelInit,
    ) -> Result<EngineTunnel, HostError> {
        let identity = identity_from(&mnemonic)?;
        drop(mnemonic);
        let mut builder = self.client(identity, effective_channel(init.channel))?;
        if init.daita.unwrap_or(false) {
            builder = builder.daita();
        }
        Ok(EngineTunnel {
            client: Arc::new(build(builder)?),
            on_state,
            live: None,
        })
    }

    async fn list_exits(&self, channel: Option<Channel>) -> Result<Vec<ExitLocation>, HostError> {
        // The relay list is public and unsigned by the caller: a throwaway
        // identity satisfies the builder and signs nothing.
        let (identity, _phrase) = WarrenIdentity::generate();
        let client = build(self.client(identity, effective_channel(channel))?)?;
        let selector = client.fetch_exits().await.map_err(|e| map_sdk_error(&e))?;
        Ok(selector
            .relays()
            .iter()
            .map(|relay| ExitLocation {
                country: relay.location().country_code().to_owned(),
                city: relay.location().city().to_owned(),
                active: relay.is_active(),
            })
            .collect())
    }

    async fn account_expiry(
        &self,
        mnemonic: Zeroizing<String>,
        channel: Option<Channel>,
    ) -> Result<u64, HostError> {
        let identity = identity_from(&mnemonic)?;
        drop(mnemonic);
        let client = build(self.client(identity, effective_channel(channel))?)?;
        client
            .api()
            .subscription()
            .await
            .map(|s| s.expires_at)
            .map_err(|e| map_client_error(&e))
    }
}

/// One engine tunnel: the client, and once connected the self-healing proxy
/// with the task relaying its state.
pub struct EngineTunnel {
    client: Arc<Client>,
    on_state: StateSink,
    live: Option<(SupervisedProxyHandle, tokio::task::JoinHandle<()>)>,
}

impl EngineTunnel {
    /// The directory exits the relay list also carries, as the napi binding
    /// resolves them. Both lists are signed by the same online key, so what
    /// stops that key alone from minting an exit is the directory's pinned
    /// offline root (`MULTIHOP_ROOT_PUBKEY_HEX`, set in [`EngineBackend`]).
    async fn cross_checked_exits(&self) -> Result<Vec<VerifiedExit>, HostError> {
        let selector = self
            .client
            .fetch_exits()
            .await
            .map_err(|e| map_sdk_error(&e))?;
        let directory = self
            .client
            .fetch_multihop_directory()
            .await
            .map_err(|e| map_sdk_error(&e))?;
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

    /// The directory entries cross-checked the same way, with the fleet-wide
    /// policy derived from the full directory.
    async fn cross_checked_entries(
        &self,
    ) -> Result<(Vec<VerifiedEntry>, CircuitPolicy), HostError> {
        let selector = self
            .client
            .fetch_exits()
            .await
            .map_err(|e| map_sdk_error(&e))?;
        let directory = self
            .client
            .fetch_multihop_directory_full()
            .await
            .map_err(|e| map_sdk_error(&e))?;
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
}

impl HostTunnel for EngineTunnel {
    async fn connect(&mut self, options: ConnectOptions) -> Result<Listeners, HostError> {
        let query = options.selector.unwrap_or_default();
        let mut exit = self
            .cross_checked_exits()
            .await?
            .into_iter()
            .find(|e| exit_matches(e, &query))
            .ok_or_else(|| {
                HostError::new(
                    ErrorCode::Discovery,
                    "no cross-checked exit matched the selector",
                )
            })?;
        // Named before an entry selector recomposes the circuit: what the
        // extension shows is where traffic leaves, never the hop it enters by.
        let landing = tunnel_exit(&exit);
        if let Some(entry_query) = options.entry_selector {
            let (entries, policy) = self.cross_checked_entries().await?;
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
                HostError::new(
                    ErrorCode::Discovery,
                    "no cross-checked entry satisfied the entry selector and the circuit \
                     diversity policy (distinct node, different country/AS)",
                )
            })?;
        }
        let loopback = SocketAddr::from(([127, 0, 0, 1], 0));
        let config = ProxyConfig {
            socks5: loopback,
            http: options.http_proxy.unwrap_or(false).then_some(loopback),
            dns_server: None,
            // Fresh per session, handed back through the connect answer.
            credentials: None,
        };
        let handle = self
            .client
            .start_proxy_supervised(&Circuit::SingleHop(exit), &config)
            .await
            .map_err(|e| map_sdk_error(&e))?;
        let listeners = Listeners {
            endpoints: Endpoints {
                socks5: handle.local_addr().to_string(),
                http: handle.http_addr().map(|a| a.to_string()),
            },
            username: handle.credentials().username().to_owned(),
            password: Zeroizing::new(handle.credentials().password().to_owned()),
            exit: Some(landing),
        };
        let mut states = handle.watch_state();
        let on_state = Arc::clone(&self.on_state);
        let forwarder = tokio::spawn(async move {
            loop {
                let state = *states.borrow_and_update();
                if let Some(state) = map_state(state) {
                    on_state(state);
                }
                if states.changed().await.is_err() {
                    break;
                }
            }
        });
        self.live = Some((handle, forwarder));
        Ok(listeners)
    }

    async fn shutdown(self) {
        if let Some((handle, forwarder)) = self.live {
            // Stop reporting first: nothing may describe a tunnel that is gone.
            forwarder.abort();
            handle.shutdown();
        }
    }
}

#[cfg(test)]
mod tests {
    use warren_sdk::api::{HttpRequest, HttpResponse, TransportError};

    use super::*;

    /// Circuit composition is pure: the client under test never touches HTTP.
    struct NoHttp;

    impl HttpTransport for NoHttp {
        async fn execute(&self, _req: HttpRequest) -> Result<HttpResponse, TransportError> {
            Err(TransportError::Connect("offline test transport".to_owned()))
        }
    }

    fn offline_client() -> WarrenClient<NoHttp> {
        let (identity, _phrase) = WarrenIdentity::generate();
        WarrenClient::builder()
            .identity(identity)
            .api_base("https://api.invalid")
            .server_pubkey_pin("0".repeat(64))
            .multihop_root_pubkey_pin("0".repeat(64))
            .build_with_transport(NoHttp)
            .expect("offline client builds")
    }

    fn exit(tag: u8, country: &str, city: &str, asn: u32) -> VerifiedExit {
        VerifiedExit {
            exit_id: [tag; 16],
            exit_ed25519_pubkey: [tag; 32],
            exit_x25519_multihop_pubkey: [tag; 32],
            endpoint: format!("198.51.100.{tag}:443").parse().unwrap(),
            endpoint_v6: None,
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

    fn entry(tag: u8, country: &str, city: &str, asn: u32) -> VerifiedEntry {
        VerifiedEntry {
            relay_ed25519_pubkey: [tag; 32],
            endpoint: format!("198.51.100.{tag}:443").parse().unwrap(),
            endpoint_v6: None,
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

    #[test]
    fn a_request_without_a_channel_reaches_the_builds_own() {
        assert_eq!(effective_channel(None), product::CHANNEL);
        assert_eq!(effective_channel(Some(Channel::Beta)), Channel::Beta);
        assert_eq!(effective_channel(Some(Channel::Prod)), Channel::Prod);
    }

    #[test]
    fn matches_an_exit_on_every_field_the_query_sets() {
        let de = exit(1, "DE", "Kassel", 0);
        let any = ExitQuery::default();
        assert!(exit_matches(&de, &any));
        let by_key = ExitQuery {
            exit_pubkey_hex: Some(hex::encode([1u8; 32]).to_uppercase()),
            ..ExitQuery::default()
        };
        assert!(exit_matches(&de, &by_key));
        let other_key = ExitQuery {
            exit_pubkey_hex: Some(hex::encode([2u8; 32])),
            ..ExitQuery::default()
        };
        assert!(!exit_matches(&de, &other_key));
        let wrong_city = ExitQuery {
            country: Some("de".into()),
            city: Some("Berlin".into()),
            ..ExitQuery::default()
        };
        assert!(!exit_matches(&de, &wrong_city));
    }

    #[test]
    fn names_the_exit_by_its_upper_case_country_and_its_city() {
        let ro = exit(1, "ro", "Bucharest", 0);
        assert_eq!(
            tunnel_exit(&ro),
            TunnelExit {
                country: "RO".into(),
                city: "Bucharest".into(),
            }
        );
    }

    #[test]
    fn composes_through_the_requested_entry_and_never_the_exits_own_node() {
        let de = exit(1, "DE", "Kassel", 100);
        let entries = vec![
            entry(1, "DE", "Kassel", 100),
            entry(2, "NL", "Amsterdam", 200),
        ];
        let policy = CircuitPolicy::from_asns(entries.iter().map(|e| e.asn));
        let nl = EntryQuery {
            country: Some("nl".into()),
            city: None,
        };
        let dialed = compose_circuit(&offline_client(), &de, &entries, &policy, &nl, None)
            .expect("the NL entry composes");
        assert_eq!(dialed.endpoint, entries[1].endpoint);
        assert_eq!(dialed.exit_id, de.exit_id);
        let own = EntryQuery {
            country: Some("DE".into()),
            city: None,
        };
        assert!(compose_circuit(&offline_client(), &de, &entries, &policy, &own, None).is_none());
    }

    #[test]
    fn an_api_failure_crosses_as_its_code_without_the_server_body() {
        let status = ClientError::ServerStatus {
            status: 402,
            body: "wb5Fsecretaddress 203.0.113.9".into(),
        };
        let mapped = map_client_error(&status);
        assert_eq!(
            mapped,
            HostError::new(ErrorCode::Server, "server returned status 402")
        );
        let transport = ClientError::Transport(TransportError::Connect(
            "error sending request to 203.0.113.9".into(),
        ));
        let mapped = map_client_error(&transport);
        assert_eq!(mapped.code, ErrorCode::Transport);
        assert!(!mapped.message.contains("203.0.113.9"));
        assert_eq!(
            map_client_error(&ClientError::AllHostsBlocked).code,
            ErrorCode::AllHostsBlocked
        );
    }

    #[test]
    fn an_engine_failure_crosses_as_the_napi_kind() {
        let api = map_sdk_error(&SdkError::Api(ClientError::ServerStatus {
            status: 403,
            body: "wb5Fsecret".into(),
        }));
        assert_eq!(
            api,
            HostError::new(ErrorCode::Api, "server returned status 403")
        );
        assert_eq!(
            map_sdk_error(&SdkError::StaleRelayList).code,
            ErrorCode::Discovery
        );
        assert_eq!(
            map_sdk_error(&SdkError::ExitDnsDisabled).code,
            ErrorCode::Unsupported
        );
        assert_eq!(
            map_sdk_error(&SdkError::EmptyDaitaPool).code,
            ErrorCode::Config
        );
    }

    #[test]
    fn maps_every_engine_state_the_extension_knows() {
        assert_eq!(
            map_state(ConnectionState::Connecting),
            Some(HostState::Connecting)
        );
        assert_eq!(
            map_state(ConnectionState::Connected),
            Some(HostState::Connected)
        );
        assert_eq!(
            map_state(ConnectionState::Reconnecting),
            Some(HostState::Reconnecting)
        );
        assert_eq!(
            map_state(ConnectionState::Draining),
            Some(HostState::Draining)
        );
        assert_eq!(map_state(ConnectionState::Failed), Some(HostState::Failed));
    }

    #[tokio::test]
    async fn refuses_an_invalid_mnemonic_as_an_identity_error() {
        let dir = tempfile::tempdir().unwrap();
        let backend = EngineBackend::new(dir.path().to_path_buf());
        let sink: StateSink = Arc::new(|_| {});
        let result = backend
            .create_tunnel(
                Zeroizing::new("not a mnemonic".into()),
                sink,
                TunnelInit::default(),
            )
            .await;
        assert_eq!(
            result.err(),
            Some(HostError::new(ErrorCode::Identity, "invalid mnemonic"))
        );
        let account = backend
            .account_expiry(Zeroizing::new("still not one".into()), None)
            .await;
        assert_eq!(account.err().map(|e| e.code), Some(ErrorCode::Identity));
    }

    #[tokio::test]
    async fn keeps_each_channels_floors_in_its_own_directory() {
        let dir = tempfile::tempdir().unwrap();
        let backend = EngineBackend::new(dir.path().to_path_buf());
        let (identity, phrase) = WarrenIdentity::generate();
        drop(identity);
        let sink: StateSink = Arc::new(|_| {});
        for channel in [Channel::Beta, Channel::Prod] {
            let init = TunnelInit {
                daita: None,
                channel: Some(channel),
            };
            backend
                .create_tunnel(Zeroizing::new(phrase.clone()), Arc::clone(&sink), init)
                .await
                .map(|_| ())
                .expect("a tunnel builds offline");
            assert!(
                dir.path().join(channel.name()).is_dir(),
                "{}",
                channel.name()
            );
        }
    }
}
