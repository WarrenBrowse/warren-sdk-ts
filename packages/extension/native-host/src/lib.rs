//! The Warren browser extension's helper: a native messaging host that
//! carries the multi-hop datapath (linked from `warren-sdk`), plus the
//! per-user installer that registers it with every browser.
//!
//! It speaks the extension's native messaging protocol version 3, wire
//! identical to the Node host in `packages/extension/src/host`. The mnemonic
//! arrives inside a connect or account request, is used, and is wiped: it is
//! never stored and never logged.

#![forbid(unsafe_code)]

pub mod cli;
pub mod engine;
pub mod framing;
pub mod host;
pub mod ids;
pub mod install;
pub mod protocol;
pub mod session;
