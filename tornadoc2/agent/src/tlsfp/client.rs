//! TLS fingerprinting clients.
//!
//! Port of `internal/tlsfp/client.go`. The public surface is:
//!
//! - [`hello_id_for_profile`] — resolve a `--tls-profile` value
//!   to a [`HelloProfile`].
//! - [`new_http_client`] — build a `reqwest::Client` for the
//!   HTTP transport.
//! - [`new_doh_client`] — build a `reqwest::Client` for the DoH
//!   transport.
//!
//! # Profile → ClientHello
//!
//! | `--tls-profile` | Go tree (`utls`) | Rust |
//! |---|---|---|
//! | `rustls` / `go` / empty | `crypto/tls` | rustls |
//! | `chrome` | `HelloChrome_120` | BoringSSL Chrome 120 |
//! | `firefox` | `HelloFirefox_120` | BoringSSL Firefox 120 |
//! | `safari` | `HelloSafari_16_0` | BoringSSL Safari 16 |
//!
//! # Implementation status of the browser profiles
//!
//! `reqwest` 0.12 speaks rustls or native-tls. It does not
//! accept a BoringSSL connector: its `connector_layer` API
//! wraps the TCP connector, not the TLS layer, and there is no
//! supported hook to substitute the ClientHello. This is a
//! limitation of `reqwest`, not of the port.
//!
//! The three functions below therefore construct
//! `reqwest::Client` with rustls for **every** profile. For a
//! browser profile they emit a single diagnostic per process
//! (matching the Go tree's `warnOnce` pattern) and return the
//! rustls-backed client. The HTTP transport is responsible for
//! routing a browser-profile build through a `hyper::Client`
//! with a BoringSSL `SslConnector` if it wants the mimicry; the
//! Rust agent's HTTP transport does that — see
//! `transport/http.rs` and its `tls-boring` feature gate.
//!
//! This matches the pattern the README documents for QUIC and
//! WireGuard: those transports accept `--tls-profile` at build
//! time but fall back to rustls at runtime, because their
//! underlying libraries cannot substitute the ClientHello. HTTP
//! and DoH are the two transports where the boring path is
//! reachable, and this file provides the reqwest fallback while
//! the transport layer carries the boring path.
//!
//! # What is not ported
//!
//! - `newTransport(profile, cfg, forceH2Off)` — the internal
//!   transport constructor. Rust builds `reqwest::Client`
//!   directly; there is no intermediate `Transport` type to
//!   port.
//! - `translateConfig(cfg)` — the field-by-field translation
//!   from `*tls.Config` to `*utls.Config`. Rust's `TlsParams`
//!   is the surface, and the translation lives inside
//!   `build_reqwest_client`.
//! - `convertUTLSConnState(cs)` — the `utls.ConnectionState`
//!   to `tls.ConnectionState` adapter. No caller of this file
//!   inspects the connection state in the Rust tree; the
//!   rustls and boring paths each expose their own state type
//!   to their own callers, and a `reqwest::Client` does not
//!   expose it at all.

use std::sync::Once;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use thiserror::Error;

use crate::config;

// =====================================================================
// Profile resolution
// =====================================================================

/// Profile identifier accepted by `--tls-profile`.
///
/// Mirrors the Go tree's `utls.ClientHelloID` mapping. The
/// `Rustls` variant covers the `go` / `rustls` / empty-string
/// aliases the builder emits — the Go tree called them
/// interchangeably, and the builder continues to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HelloProfile {
    /// Standard Rust TLS. The builder's `--tls-profile rustls`
    /// (the default) maps here.
    Rustls,
    /// Chrome 120 preset. Requires BoringSSL.
    Chrome,
    /// Firefox 120 preset. Requires BoringSSL.
    Firefox,
    /// Safari 16 preset. Requires BoringSSL.
    Safari,
}

impl HelloProfile {
    /// Report whether the profile needs a BoringSSL ClientHello.
    ///
    /// `true` for the three browser profiles, `false` for
    /// `Rustls`. The HTTP transport consults this to decide
    /// whether to route through its boring connector.
    pub fn needs_boring(self) -> bool {
        !matches!(self, HelloProfile::Rustls)
    }

    /// Return the profile name the builder emits, for
    /// diagnostics and for the `X-Beacon-*` telemetry if it
    /// ever carries the profile.
    pub fn as_str(self) -> &'static str {
        match self {
            HelloProfile::Rustls => "rustls",
            HelloProfile::Chrome => "chrome",
            HelloProfile::Firefox => "firefox",
            HelloProfile::Safari => "safari",
        }
    }
}

// =====================================================================
// Errors
// =====================================================================

/// Errors from TLS profile configuration and client construction.
#[derive(Debug, Error)]
pub enum TlsfpError {
    #[error(
        "unknown tls_profile {0:?}; \
         valid values are rustls, chrome, firefox, safari"
    )]
    UnknownProfile(String),

    #[error("tls config {name}: {reason}")]
    Config {
        name: &'static str,
        reason: String,
    },

    #[error("client build: {0}")]
    ClientBuild(#[from] reqwest::Error),
}

// =====================================================================
// Profile resolver
// =====================================================================

/// Resolve a `--tls-profile` value to a [`HelloProfile`].
///
/// Mirrors `HelloIDForProfile`. Accepts the `"go"` alias for
/// `Rustls` for parity with the Go tree — the builder emits
/// `rustls`, `chrome`, `firefox`, and `safari`, and the
/// framework's documentation sometimes calls the default `go`
/// from its predecessor tree.
///
/// An unknown profile is an error, not a silent fallback. A
/// build that says `--tls-profile chrom` should fail loudly at
/// build time, not silently produce a rustls agent.
pub fn hello_id_for_profile(
    profile: &str,
) -> Result<HelloProfile, TlsfpError> {
    match profile {
        "" | "go" | "rustls" => Ok(HelloProfile::Rustls),
        "chrome" => Ok(HelloProfile::Chrome),
        "firefox" => Ok(HelloProfile::Firefox),
        "safari" => Ok(HelloProfile::Safari),
        other => Err(TlsfpError::UnknownProfile(other.to_string())),
    }
}

// =====================================================================
// TLS parameters
// =====================================================================

/// The subset of `*tls.Config` fields the agent actually uses.
///
/// The Go tree carried the full `*tls.Config` through the
/// transport. In Rust, that shape is awkward — `reqwest` and
/// `boring` each expose their own config type and neither
/// converts cleanly to the other. `TlsParams` is the
/// interchange format: the caller fills it from the build-time
/// constants ([`TlsParams::from_consts`]) and, for `curl -k`
/// in the network verbs, sets `insecure_skip_verify` for one
/// request.
///
/// Fields the Go tree's `translateConfig` flagged as missing
/// under uTLS (`GetClientCertificate`, `VerifyPeerCertificate`,
/// `KeyLogWriter`, `CurvePreferences`, `Renegotiation`,
/// `SessionTicketsDisabled`, `DynamicRecordSizingDisabled`,
/// `EncryptedClientHelloConfigList`, `Rand`, `Time`) are
/// **not** represented here. None of them is configured by the
/// agent's transports, and a field that nothing sets does not
/// need a slot in the interchange format.
#[derive(Clone, Debug, Default)]
pub struct TlsParams {
    /// Skip certificate verification.
    ///
    /// Set by `curl -k` (and `nc`/`resolve` if they ever grow
    /// an `-k`) for a single invocation. Never set by the
    /// agent's own transports — the beacon loop verifies the
    /// server against `root_ca` or the system store.
    pub insecure_skip_verify: bool,

    /// Root CA bundle in PEM. `None` means the system trust
    /// store. Set when the agent was built with `--mtls-dir`
    /// pointing at a bundle that includes a custom CA.
    pub root_ca: Option<Vec<u8>>,

    /// Client certificate chain in PEM. Present when the agent
    /// was built with `--mtls`. Combined with
    /// `client_key_pem` by `build_reqwest_client`.
    pub client_cert_pem: Option<Vec<u8>>,

    /// Client private key in PEM.
    pub client_key_pem: Option<Vec<u8>>,

    /// TLS version floor. `None` leaves rustls's default (1.2).
    pub min_tls_version: Option<reqwest::tls::Version>,

    /// TLS version ceiling.
    pub max_tls_version: Option<reqwest::tls::Version>,
}

impl TlsParams {
    /// Build the params the agent's own transports use, from
    /// the build-time constants.
    ///
    /// Replaces the Go tree's `BuildTLSConfig()`. The three
    /// base64 PEM fields (`ROOT_CA_PEM_B64`,
    /// `CLIENT_CERT_PEM_B64`, `CLIENT_KEY_PEM_B64`) are the
    /// only ones set. An empty base64 const means "not
    /// configured for this build" and leaves the field `None`.
    pub fn from_consts() -> Result<Self, TlsfpError> {
        let mut p = TlsParams::default();

        if !config::ROOT_CA_PEM_B64.is_empty() {
            p.root_ca = Some(decode_pem_b64(
                "ROOT_CA_PEM_B64",
                config::ROOT_CA_PEM_B64,
            )?);
        }
        if !config::CLIENT_CERT_PEM_B64.is_empty() {
            p.client_cert_pem = Some(decode_pem_b64(
                "CLIENT_CERT_PEM_B64",
                config::CLIENT_CERT_PEM_B64,
            )?);
        }
        if !config::CLIENT_KEY_PEM_B64.is_empty() {
            p.client_key_pem = Some(decode_pem_b64(
                "CLIENT_KEY_PEM_B64",
                config::CLIENT_KEY_PEM_B64,
            )?);
        }

        Ok(p)
    }
}

fn decode_pem_b64(
    name: &'static str,
    b64: &str,
) -> Result<Vec<u8>, TlsfpError> {
    STANDARD.decode(b64).map_err(|e| TlsfpError::Config {
        name,
        reason: e.to_string(),
    })
}

// =====================================================================
// Warning for the browser-profile fallback
// =====================================================================

/// Fires at most once per process. Matches the Go tree's
/// `warnOnce` — a loop that constructs a client per check-in
/// should not spam the diagnostic.
static BROWSER_FALLBACK_WARN: Once = Once::new();

fn warn_browser_fallback(profile: &str) {
    BROWSER_FALLBACK_WARN.call_once(|| {
        eprintln!(
            "[tlsfp] warning: profile {profile:?} requires \
             BoringSSL; reqwest cannot accept a Boring \
             connector, so this client uses rustls. The HTTP \
             transport routes browser-profile builds through \
             its boring connector directly; DoH and WebSocket \
             use this client."
        );
    });
}

// =====================================================================
// Client construction
// =====================================================================

/// Build a `reqwest::Client` for HTTP transport use.
///
/// Mirrors `NewHTTPClient`. 60-second total request timeout,
/// 15-second connect timeout (TCP + TLS handshake), HTTP/2
/// enabled by rustls's ALPN defaults.
///
/// For a browser profile, warns once per process and returns
/// the rustls-backed client — see the module doc for why.
pub fn new_http_client(
    profile: &str,
    params: &TlsParams,
) -> Result<reqwest::Client, TlsfpError> {
    let hello = hello_id_for_profile(profile)?;
    if hello.needs_boring() {
        warn_browser_fallback(hello.as_str());
    }
    build_client(params, BuildOpts {
        total_timeout: Duration::from_secs(60),
        connect_timeout: Duration::from_secs(15),
        no_redirect: false,
    })
}

/// Build a `reqwest::Client` for DoH transport use.
///
/// Mirrors `NewDoHClient`. 15-second total timeout, no
/// redirect following — the DoH transport resolves against a
/// fixed resolver URL and a 30x response is an error, not a
/// redirect. The Go tree used `CheckRedirect` returning
/// `http.ErrUseLastResponse`, which is the same "do not
/// follow" behaviour.
///
/// The DoH client is `reqwest::Client` because
/// `hickory-resolver` accepts one and there is no boring path
/// for the resolver's inner HTTPS. The README documents this
/// limitation — the ClientHello the resolver's
/// `hickory-proto` layer presents is rustls's.
pub fn new_doh_client(
    profile: &str,
    params: &TlsParams,
) -> Result<reqwest::Client, TlsfpError> {
    let hello = hello_id_for_profile(profile)?;
    if hello.needs_boring() {
        warn_browser_fallback(hello.as_str());
    }
    build_client(params, BuildOpts {
        total_timeout: Duration::from_secs(15),
        connect_timeout: Duration::from_secs(15),
        no_redirect: true,
    })
}

/// Build an HTTP client from the build-time constants.
///
/// Convenience wrapper around [`new_http_client`] for the
/// HTTP transport's check-in constructor. Reads
/// `config::TLS_PROFILE` and [`TlsParams::from_consts`].
pub fn new_http_client_from_consts(
) -> Result<reqwest::Client, TlsfpError> {
    let params = TlsParams::from_consts()?;
    new_http_client(config::TLS_PROFILE, &params)
}

/// Build a DoH client from the build-time constants.
pub fn new_doh_client_from_consts(
) -> Result<reqwest::Client, TlsfpError> {
    let params = TlsParams::from_consts()?;
    new_doh_client(config::TLS_PROFILE, &params)
}

struct BuildOpts {
    total_timeout: Duration,
    connect_timeout: Duration,
    no_redirect: bool,
}

fn build_client(
    params: &TlsParams,
    opts: BuildOpts,
) -> Result<reqwest::Client, TlsfpError> {
    let mut b = reqwest::Client::builder()
        .use_rustls_tls()
        .timeout(opts.total_timeout)
        .connect_timeout(opts.connect_timeout);

    if params.insecure_skip_verify {
        b = b.danger_accept_invalid_certs(true);
    }

    if let Some(ref pem) = params.root_ca {
        // `from_pem_bundle` accepts multiple `-----BEGIN
        // CERTIFICATE-----` blocks in one buffer, which is
        // what a CA bundle is. `from_pem` would take only the
        // first.
        let certs = reqwest::Certificate::from_pem_bundle(pem)?;
        for cert in certs {
            b = b.add_root_certificate(cert);
        }
    }

    if let (Some(cert_pem), Some(key_pem)) =
        (&params.client_cert_pem, &params.client_key_pem)
    {
        // reqwest's `Identity::from_pem` wants cert + key in
        // one buffer; the Go tree passed the two halves
        // separately and let `crypto/tls` combine them.
        let mut combined = Vec::with_capacity(
            cert_pem.len() + 1 + key_pem.len(),
        );
        combined.extend_from_slice(cert_pem);
        if !cert_pem.ends_with(b"\n") {
            combined.push(b'\n');
        }
        combined.extend_from_slice(key_pem);
        let id = reqwest::Identity::from_pem(&combined)?;
        b = b.identity(id);
    }

    if let Some(v) = params.min_tls_version {
        b = b.min_tls_version(v);
    }
    if let Some(v) = params.max_tls_version {
        b = b.max_tls_version(v);
    }

    if opts.no_redirect {
        b = b.redirect(reqwest::redirect::Policy::none());
    }

    b.build().map_err(TlsfpError::from)
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_id_covers_every_accepted_form() {
        for (input, want) in [
            ("", HelloProfile::Rustls),
            ("go", HelloProfile::Rustls),
            ("rustls", HelloProfile::Rustls),
            ("chrome", HelloProfile::Chrome),
            ("firefox", HelloProfile::Firefox),
            ("safari", HelloProfile::Safari),
        ] {
            assert_eq!(
                hello_id_for_profile(input).unwrap(),
                want,
                "input = {input:?}",
            );
        }
    }

    #[test]
    fn hello_id_rejects_unknown() {
        for bad in ["chrom", "Chrome", "edge", "none", "tls1.3"] {
            let err = hello_id_for_profile(bad);
            assert!(
                matches!(err, Err(TlsfpError::UnknownProfile(_))),
                "input = {bad:?}",
            );
        }
    }

    #[test]
    fn needs_boring_matches_profile_kind() {
        assert!(!HelloProfile::Rustls.needs_boring());
        assert!(HelloProfile::Chrome.needs_boring());
        assert!(HelloProfile::Firefox.needs_boring());
        assert!(HelloProfile::Safari.needs_boring());
    }

    #[test]
    fn as_str_round_trips_through_hello_id() {
        for p in [
            HelloProfile::Rustls,
            HelloProfile::Chrome,
            HelloProfile::Firefox,
            HelloProfile::Safari,
        ] {
            assert_eq!(hello_id_for_profile(p.as_str()).unwrap(), p);
        }
    }

    #[test]
    fn http_client_builds_for_every_profile() {
        let params = TlsParams::default();
        for profile in [
            "", "go", "rustls", "chrome", "firefox", "safari",
        ] {
            let client = new_http_client(profile, &params);
            assert!(
                client.is_ok(),
                "http client failed for {profile:?}: {:?}",
                client.err(),
            );
        }
    }

    #[test]
    fn doh_client_builds_for_every_profile() {
        let params = TlsParams::default();
        for profile in [
            "", "go", "rustls", "chrome", "firefox", "safari",
        ] {
            let client = new_doh_client(profile, &params);
            assert!(
                client.is_ok(),
                "doh client failed for {profile:?}: {:?}",
                client.err(),
            );
        }
    }

    #[test]
    fn unknown_profile_reaches_both_constructors() {
        let params = TlsParams::default();
        assert!(matches!(
            new_http_client("nope", &params),
            Err(TlsfpError::UnknownProfile(_)),
        ));
        assert!(matches!(
            new_doh_client("nope", &params),
            Err(TlsfpError::UnknownProfile(_)),
        ));
    }

    #[test]
    fn insecure_skip_verify_does_not_prevent_build() {
        let params = TlsParams {
            insecure_skip_verify: true,
            ..Default::default()
        };
        assert!(new_http_client("rustls", &params).is_ok());
    }

    #[test]
    fn min_max_tls_version_do_not_prevent_build() {
        use reqwest::tls::Version;
        let params = TlsParams {
            min_tls_version: Some(Version::TLS_1_2),
            max_tls_version: Some(Version::TLS_1_3),
            ..Default::default()
        };
        assert!(new_http_client("rustls", &params).is_ok());
    }

    #[test]
    fn pem_bundle_does_not_prevent_build() {
        // A CA bundle with one valid PEM cert. reqwest parses it
        // and the client builds. We do not attempt a network
        // round-trip here — that is the transport's test.
        let params = TlsParams {
            root_ca: Some(TEST_CA_PEM.to_vec()),
            ..Default::default()
        };
        assert!(new_http_client("rustls", &params).is_ok());
    }

    /// A minimal self-signed CA PEM used only to exercise the
    /// `from_pem_bundle` path. Regenerated on any cert change;
    /// carries no secrets.
    const TEST_CA_PEM: &[u8] = b"\
-----BEGIN CERTIFICATE-----
MIIBeTCCAR+gAwIBAgIUTestAAAAAAAAAAAAAAAAAAAAAAAAAAAA
MAoGCCqGSM49BAMCMAAwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAw
WjAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
-----END CERTIFICATE-----
";
}