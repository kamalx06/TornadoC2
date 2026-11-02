//! Small helpers shared by dispatch and the run loop.

use std::path::Path;

/// Base64-encode a task result's `output` field.
pub fn encode_output(raw: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(raw)
}

/// Return a copy of the current environment with shell-history
/// variables stripped and the safe defaults added. Matches the
/// Go `sanitizedEnv`.
pub fn sanitized_env() -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = std::env::vars()
        .filter(|(k, _)| {
            !matches!(
                k.as_str(),
                "HISTFILE"
                    | "HISTSIZE"
                    | "HISTFILESIZE"
                    | "HISTCONTROL"
                    | "HISTIGNORE"
                    | "HISTTIMEFORMAT"
            )
        })
        .collect();
    for (k, v) in [
        ("HISTFILE", "/dev/null"),
        ("HISTSIZE", "0"),
        ("HISTFILESIZE", "0"),
        ("HISTCONTROL", "ignorespace"),
        ("HISTIGNORE", "*"),
        ("HISTTIMEFORMAT", ""),
    ] {
        out.push((k.to_string(), v.to_string()));
    }
    out
}

/// Concatenate `stdout` and `stderr` with a `[stderr]` marker.
pub fn merge_streams(stdout: &[u8], stderr: &[u8]) -> Vec<u8> {
    if stderr.is_empty() {
        return stdout.to_vec();
    }
    if stdout.is_empty() {
        return stderr.to_vec();
    }
    let mut out = Vec::with_capacity(stdout.len() + stderr.len() + 16);
    out.extend_from_slice(stdout);
    if stdout.last() != Some(&b'\n') {
        out.push(b'\n');
    }
    out.extend_from_slice(b"[stderr]\n");
    out.extend_from_slice(stderr);
    out
}

/// Return the sub-arguments after a literal `--`, if present.
pub fn split_script_args(args: &[String]) -> Vec<String> {
    for i in 1..args.len() {
        if args[i] == "--" {
            return args[i + 1..].to_vec();
        }
    }
    Vec::new()
}

/// Truncate `s` to `n` characters, appending `...` on trim.
/// Byte-sliced, so callers should pass ASCII.
pub fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        return s.to_string();
    }
    format!("{}...", &s[..n])
}

/// The current working directory, or `"?"` on error.
pub fn must_getwd() -> String {
    std::env::current_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "?".to_string())
}

/// Best-effort path check used by the `which` verb.
#[allow(dead_code)]
pub fn looks_like_path(p: &Path) -> bool {
    p.is_absolute() || p.components().count() > 1
}