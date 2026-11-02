//! TLS fingerprinting.
//!
//! `client` provides the profile resolver and the
//! `reqwest::Client` constructors used by the HTTP and DoH
//! transports. The BoringSSL browser-ClientHello path is a
//! downstream transport concern — see `client`'s module doc.

pub mod client;

pub use client::{
    hello_id_for_profile, new_doh_client, new_http_client,
    HelloProfile, TlsParams, TlsfpError,
};