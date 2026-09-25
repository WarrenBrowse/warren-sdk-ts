//! The extension to helper protocol, version 3, wire-identical to
//! `packages/extension/src/protocol.ts`: requests carry a numeric `id`, answers
//! echo it with `ok`, and `{type: "state"}` events arrive unsolicited.

use serde::Deserialize;
use serde_json::{Value, json};
use warren_sdk::product::Channel;
use zeroize::Zeroizing;

/// The protocol version this helper speaks. A peer on any other is refused at
/// `hello`.
pub const PROTOCOL_VERSION: u64 = 3;

/// The name browsers resolve to this helper.
pub const HOST_NAME: &str = "com.warrenbrowse.host";

/// Reads a channel name as the extension spells it.
#[must_use]
pub fn parse_channel(name: &str) -> Option<Channel> {
    match name {
        "prod" => Some(Channel::Prod),
        "beta" => Some(Channel::Beta),
        _ => None,
    }
}

/// Tunnel lifecycle states reported to the extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostState {
    /// The first dial is in progress.
    Connecting,
    /// The tunnel carries traffic.
    Connected,
    /// The tunnel was lost and is being re-dialed on the same listeners.
    Reconnecting,
    /// The exit asked the session to move before it goes away.
    Draining,
    /// The datapath gave up.
    Failed,
    /// No tunnel.
    Disconnected,
}

impl HostState {
    /// The wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Connecting => "connecting",
            Self::Connected => "connected",
            Self::Reconnecting => "reconnecting",
            Self::Draining => "draining",
            Self::Failed => "failed",
            Self::Disconnected => "disconnected",
        }
    }
}

/// Exit selection carried by a connect request.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExitQuery {
    /// Exact exit Ed25519 pubkey, 64 hex characters.
    pub exit_pubkey_hex: Option<String>,
    /// ISO 3166-1 alpha-2 country code.
    pub country: Option<String>,
    /// City name.
    pub city: Option<String>,
}

/// Multihop entry-hop selection carried by a connect request.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryQuery {
    /// ISO 3166-1 alpha-2 country code.
    pub country: Option<String>,
    /// City name.
    pub city: Option<String>,
}

/// A connect request. The mnemonic is wiped when this is dropped; it has no
/// `Debug` so it can never be formatted into a log.
pub struct ConnectRequest {
    /// The account mnemonic, handed over for this connect only.
    pub mnemonic: Zeroizing<String>,
    /// Exit selection.
    pub selector: Option<ExitQuery>,
    /// Multihop entry selection.
    pub entry_selector: Option<EntryQuery>,
    /// Also open the HTTP listener.
    pub http_proxy: Option<bool>,
    /// Enable DAITA on the tunnel.
    pub daita: Option<bool>,
}

/// One decoded request.
pub enum Request {
    /// Version handshake, naming the extension's channel.
    Hello {
        /// The version the extension speaks, as sent.
        protocol: Option<Value>,
        /// The channel field as sent: `None` when absent, `Some(Null)` when
        /// explicitly null.
        channel: Option<Value>,
    },
    /// Current tunnel state.
    Status,
    /// Bring the tunnel up.
    Connect(ConnectRequest),
    /// Tear the tunnel down.
    Disconnect,
    /// Verified relay-list locations.
    Exits,
    /// Signed subscription lookup.
    Account {
        /// The account mnemonic, wiped on drop.
        mnemonic: Zeroizing<String>,
    },
    /// A request this helper cannot serve, answered with a `protocol` error.
    Refused(&'static str),
}

/// A request and the id its answer must echo.
pub struct Envelope {
    /// The request id, echoed verbatim.
    pub id: Value,
    /// The request.
    pub request: Request,
}

/// What one frame decoded to.
pub enum Decoded {
    /// A request to answer.
    Request(Envelope),
    /// Valid JSON that is not a request (no numeric id): ignored.
    Ignored,
    /// Not JSON at all: the stream is corrupt.
    Corrupt,
}

/// Every field any request carries. Unknown fields are ignored; a field of
/// the wrong shape fails the whole decode, which is answered as malformed.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawRequest {
    id: Option<Value>,
    #[serde(rename = "type")]
    kind: Option<String>,
    protocol: Option<Value>,
    #[serde(default, deserialize_with = "present")]
    channel: Option<Value>,
    mnemonic: Option<Zeroizing<String>>,
    selector: Option<ExitQuery>,
    entry_selector: Option<EntryQuery>,
    http_proxy: Option<bool>,
    daita: Option<bool>,
}

/// Keeps an explicit `null` apart from an absent field: the TS session
/// refuses `channel: null` just as it refuses an unknown channel.
fn present<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Value>, D::Error> {
    Value::deserialize(d).map(Some)
}

#[derive(Deserialize)]
struct IdOnly {
    id: Option<Value>,
}

/// Decodes one frame's payload.
#[must_use]
pub fn decode_request(payload: &[u8]) -> Decoded {
    // serde reads a struct from a JSON array too; only an object is a request.
    let is_object = payload
        .iter()
        .find(|b| !b.is_ascii_whitespace())
        .is_some_and(|b| *b == b'{');
    if !is_object {
        return match serde_json::from_slice::<serde::de::IgnoredAny>(payload) {
            Ok(_) => Decoded::Ignored,
            Err(_) => Decoded::Corrupt,
        };
    }
    let raw = match serde_json::from_slice::<RawRequest>(payload) {
        Ok(raw) => raw,
        Err(_) => {
            return match serde_json::from_slice::<IdOnly>(payload) {
                Ok(IdOnly { id: Some(id) }) if id.is_number() => Decoded::Request(Envelope {
                    id,
                    request: Request::Refused("malformed request"),
                }),
                Ok(_) => Decoded::Ignored,
                Err(_) => Decoded::Corrupt,
            };
        }
    };
    let Some(id) = raw.id.filter(Value::is_number) else {
        return Decoded::Ignored;
    };
    let request = match raw.kind.as_deref() {
        Some("hello") => Request::Hello {
            protocol: raw.protocol,
            channel: raw.channel,
        },
        Some("status") => Request::Status,
        Some("connect") => match raw.mnemonic {
            Some(mnemonic) => Request::Connect(ConnectRequest {
                mnemonic,
                selector: raw.selector,
                entry_selector: raw.entry_selector,
                http_proxy: raw.http_proxy,
                daita: raw.daita,
            }),
            None => Request::Refused("connect carries no mnemonic"),
        },
        Some("disconnect") => Request::Disconnect,
        Some("exits") => Request::Exits,
        Some("account") => match raw.mnemonic {
            Some(mnemonic) => Request::Account { mnemonic },
            None => Request::Refused("account carries no mnemonic"),
        },
        _ => Request::Refused("unknown request type"),
    };
    Decoded::Request(Envelope { id, request })
}

/// Local listener addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoints {
    /// SOCKS5 listener, `ip:port`.
    pub socks5: String,
    /// HTTP listener, when requested.
    pub http: Option<String>,
}

impl Endpoints {
    fn to_json(&self) -> Value {
        let mut value = json!({ "socks5": self.socks5 });
        if let Some(http) = &self.http {
            value["http"] = json!(http);
        }
        value
    }
}

/// The exit a tunnel lands on, as the relay list names it. With an entry
/// selector this is still the exit, never the entry the circuit enters by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelExit {
    /// ISO 3166-1 alpha-2 country code, upper-case.
    pub country: String,
    /// City name.
    pub city: String,
}

impl TunnelExit {
    fn to_json(&self) -> Value {
        json!({ "country": self.country, "city": self.city })
    }
}

/// One selectable exit location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitLocation {
    /// ISO 3166-1 alpha-2 country code.
    pub country: String,
    /// City name.
    pub city: String,
    /// Whether the relay list marks it active.
    pub active: bool,
}

/// The `hello` answer. This helper always carries its datapath.
#[must_use]
pub fn hello_answer(id: &Value) -> Value {
    json!({ "id": id, "ok": true, "type": "hello", "protocol": PROTOCOL_VERSION, "datapath": "ready" })
}

/// The `status` answer. `exit` is named while a tunnel is up and its exit is
/// known.
#[must_use]
pub fn status_answer(
    id: &Value,
    state: HostState,
    endpoints: Option<&Endpoints>,
    exit: Option<&TunnelExit>,
) -> Value {
    let mut value = json!({ "id": id, "ok": true, "type": "status", "state": state.as_str() });
    if let Some(endpoints) = endpoints {
        value["endpoints"] = endpoints.to_json();
    }
    if let Some(exit) = exit {
        value["exit"] = exit.to_json();
    }
    value
}

/// The `connect` answer: the one place the listener credentials cross. An
/// extension that predates `exit` ignores it; a newer one reads its absence as
/// an unknown exit.
#[must_use]
pub fn connect_answer(
    id: &Value,
    endpoints: &Endpoints,
    username: &str,
    password: &str,
    exit: Option<&TunnelExit>,
) -> Value {
    let mut value = json!({
        "id": id,
        "ok": true,
        "type": "connect",
        "endpoints": endpoints.to_json(),
        "auth": { "username": username, "password": password },
    });
    if let Some(exit) = exit {
        value["exit"] = exit.to_json();
    }
    value
}

/// The `disconnect` answer.
#[must_use]
pub fn disconnect_answer(id: &Value) -> Value {
    json!({ "id": id, "ok": true, "type": "disconnect" })
}

/// The `exits` answer.
#[must_use]
pub fn exits_answer(id: &Value, locations: &[ExitLocation]) -> Value {
    let locations: Vec<Value> = locations
        .iter()
        .map(|l| json!({ "country": l.country, "city": l.city, "active": l.active }))
        .collect();
    json!({ "id": id, "ok": true, "type": "exits", "locations": locations })
}

/// The `account` answer.
#[must_use]
pub fn account_answer(id: &Value, expires_at: u64) -> Value {
    json!({ "id": id, "ok": true, "type": "account", "expiresAt": expires_at })
}

/// An error answer. `message` must already be redacted.
#[must_use]
pub fn error_answer(id: &Value, code: &str, message: &str) -> Value {
    json!({ "id": id, "ok": false, "code": code, "message": message })
}

/// An unsolicited state event.
#[must_use]
pub fn state_event(state: HostState) -> Value {
    json!({ "type": "state", "state": state.as_str() })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(json: &str) -> Envelope {
        match decode_request(json.as_bytes()) {
            Decoded::Request(envelope) => envelope,
            _ => panic!("expected a request"),
        }
    }

    #[test]
    fn decodes_a_connect_with_every_option() {
        let envelope = request(
            r#"{"id":2,"type":"connect","mnemonic":"a b c","selector":{"country":"NL"},
                "entrySelector":{"country":"DE","city":"Kassel"},"httpProxy":true,"daita":false}"#,
        );
        assert_eq!(envelope.id, json!(2));
        let Request::Connect(connect) = envelope.request else {
            panic!("expected connect");
        };
        assert_eq!(connect.mnemonic.as_str(), "a b c");
        assert_eq!(connect.selector.unwrap().country.as_deref(), Some("NL"));
        let entry = connect.entry_selector.unwrap();
        assert_eq!(entry.country.as_deref(), Some("DE"));
        assert_eq!(entry.city.as_deref(), Some("Kassel"));
        assert_eq!(connect.http_proxy, Some(true));
        assert_eq!(connect.daita, Some(false));
    }

    #[test]
    fn keeps_an_explicit_null_channel_apart_from_an_absent_one() {
        let Request::Hello { channel, .. } =
            request(r#"{"id":1,"type":"hello","protocol":3}"#).request
        else {
            panic!("expected hello");
        };
        assert!(channel.is_none());
        let Request::Hello { channel, .. } =
            request(r#"{"id":1,"type":"hello","protocol":3,"channel":null}"#).request
        else {
            panic!("expected hello");
        };
        assert_eq!(channel, Some(Value::Null));
    }

    #[test]
    fn refuses_an_unknown_type_and_a_request_without_its_mnemonic() {
        for json in [
            r#"{"id":9,"type":"reboot"}"#,
            r#"{"id":9}"#,
            r#"{"id":9,"type":"connect"}"#,
            r#"{"id":9,"type":"account"}"#,
        ] {
            assert!(
                matches!(request(json).request, Request::Refused(_)),
                "{json}"
            );
        }
    }

    #[test]
    fn a_field_of_the_wrong_shape_is_a_malformed_request() {
        let envelope = request(r#"{"id":5,"type":"connect","mnemonic":42}"#);
        assert!(matches!(
            envelope.request,
            Request::Refused("malformed request")
        ));
        assert_eq!(envelope.id, json!(5));
    }

    #[test]
    fn ignores_json_without_a_numeric_id() {
        for json in [
            "null",
            r#"{"type":"status"}"#,
            r#"{"id":"1","type":"status"}"#,
            "[1]",
        ] {
            assert!(
                matches!(decode_request(json.as_bytes()), Decoded::Ignored),
                "{json}"
            );
        }
    }

    #[test]
    fn a_payload_that_is_not_json_is_corrupt() {
        assert!(matches!(decode_request(b"{nope"), Decoded::Corrupt));
        assert!(matches!(decode_request(&[0xff, 0xfe]), Decoded::Corrupt));
    }

    #[test]
    fn answers_match_the_typescript_shapes() {
        let endpoints = Endpoints {
            socks5: "127.0.0.1:1080".into(),
            http: Some("127.0.0.1:8118".into()),
        };
        assert_eq!(
            hello_answer(&json!(1)),
            json!({ "id": 1, "ok": true, "type": "hello", "protocol": 3, "datapath": "ready" })
        );
        assert_eq!(
            status_answer(&json!(2), HostState::Connected, Some(&endpoints), None),
            json!({ "id": 2, "ok": true, "type": "status", "state": "connected",
                    "endpoints": { "socks5": "127.0.0.1:1080", "http": "127.0.0.1:8118" } })
        );
        assert_eq!(
            status_answer(&json!(3), HostState::Disconnected, None, None),
            json!({ "id": 3, "ok": true, "type": "status", "state": "disconnected" })
        );
        assert_eq!(
            account_answer(&json!(4), 1_790_000_000),
            json!({ "id": 4, "ok": true, "type": "account", "expiresAt": 1_790_000_000u64 })
        );
        assert_eq!(
            state_event(HostState::Reconnecting),
            json!({ "type": "state", "state": "reconnecting" })
        );
    }

    #[test]
    fn connect_and_status_answers_name_the_exit_only_when_it_is_known() {
        let endpoints = Endpoints {
            socks5: "127.0.0.1:1080".into(),
            http: None,
        };
        let exit = TunnelExit {
            country: "RO".into(),
            city: "Bucharest".into(),
        };
        assert_eq!(
            connect_answer(&json!(5), &endpoints, "warren", "secret", Some(&exit)),
            json!({ "id": 5, "ok": true, "type": "connect",
                    "endpoints": { "socks5": "127.0.0.1:1080" },
                    "auth": { "username": "warren", "password": "secret" },
                    "exit": { "country": "RO", "city": "Bucharest" } })
        );
        assert_eq!(
            connect_answer(&json!(5), &endpoints, "warren", "secret", None),
            json!({ "id": 5, "ok": true, "type": "connect",
                    "endpoints": { "socks5": "127.0.0.1:1080" },
                    "auth": { "username": "warren", "password": "secret" } })
        );
        assert_eq!(
            status_answer(
                &json!(6),
                HostState::Connected,
                Some(&endpoints),
                Some(&exit)
            ),
            json!({ "id": 6, "ok": true, "type": "status", "state": "connected",
                    "endpoints": { "socks5": "127.0.0.1:1080" },
                    "exit": { "country": "RO", "city": "Bucharest" } })
        );
    }

    #[test]
    fn reads_only_the_two_channels() {
        assert_eq!(parse_channel("beta"), Some(Channel::Beta));
        assert_eq!(parse_channel("prod"), Some(Channel::Prod));
        assert_eq!(parse_channel("staging"), None);
    }
}
