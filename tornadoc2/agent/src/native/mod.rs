//! Environment sanitization.
//!
//! Port of `native_env.go`. `sanitized_env` builds the environment
//! for a spawned child process: it strips the shell-history
//! variables (so a `sh -c "cmd"` does not append to the operator's
//! shell history) and adds the safe defaults.
//!
//! `core::helpers` re-exports this function, so the
//! `crate::core::helpers::sanitized_env` path continues to work.

/// Return the current environment with shell-history variables
/// stripped, plus the safe defaults.
///
/// The `HIST*` families are stripped before the defaults are
/// added, so a parent process that inherits a stale
/// `HISTFILE=/home/user/.bash_history` sees it replaced by
/// `HISTFILE=/dev/null` rather than duplicated.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_history_vars() {
        std::env::set_var("HISTFILE", "/home/user/.bash_history");
        let env = sanitized_env();
        let hist: Vec<&(String, String)> = env
            .iter()
            .filter(|(k, _)| k == "HISTFILE")
            .collect();
        assert_eq!(hist.len(), 1);
        assert_eq!(hist[0].1, "/dev/null");
    }

    #[test]
    fn adds_defaults() {
        let env = sanitized_env();
        for key in [
            "HISTFILE",
            "HISTSIZE",
            "HISTFILESIZE",
            "HISTCONTROL",
            "HISTIGNORE",
            "HISTTIMEFORMAT",
        ] {
            assert!(
                env.iter().any(|(k, _)| k == key),
                "missing {key}",
            );
        }
    }
}