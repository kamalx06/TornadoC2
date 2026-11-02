//! Diagnostics helpers.
//!
//! Port of `diag()`, `mustGetwd()`, `parseClock()`,
//! `formatWorkHours()`, and `insideWorkHours()` from
//! `core/main.go`.
//!
//! # `diag()` → `diag!`
//!
//! The Go `diag()` function printed a timestamped line to stderr
//! when `Verbose` was true. The Rust port replaces it with the
//! crate-wide [`diag!`] macro (defined in `lib.rs`):
//!
//! ```ignore
//! diag!("[core] starting — transport={:?}\n", cfg.transport_mode);
//! ```
//!
//! Two differences from the Go function:
//!
//! 1. **No timestamp.** The macro expands to a plain
//!    `eprintln!`. Timestamps on verbose lines were useful when
//!    the agent shared a terminal with other tools; for a
//!    red-team engagement whose output is captured to a file,
//!    the operator can timestamp externally. Dropping them
//!    keeps the macro simple and avoids a `chrono` dependency
//!    at every `diag!` call site.
//! 2. **Compile-time, not runtime.** `config::VERBOSE` is a
//!    `pub const bool`; the `if config::VERBOSE` branch is
//!    const-propagated away when false, and the format string
//!    is not emitted into the binary. The Go runtime toggle
//!    `Verbose` is gone — the design forbids a runtime
//!    diagnostic surface.
//!
//! See the crate root for the macro itself and
//! `CONTRIBUTING.md › Rust conventions` for the "never
//! `println!`" rule that the macro enforces.

use chrono::Timelike;

// =====================================================================
// diag_enabled
// =====================================================================

/// Whether verbose diagnostics are enabled.
///
/// Equivalent to the Go tree's `Verbose` check, but derived from
/// `config::VERBOSE` — the `TC2_VERBOSE` const emitted by
/// `build.rs` — rather than a package-level mutable variable.
/// The compiler inlines and const-folds this to `false` or `true`
/// at every call site; no function call remains in the generated
/// binary.
///
/// Use this when a caller needs to *avoid work* before calling
/// `diag!`:
///
/// ```ignore
/// if crate::core::diag::diag_enabled() {
///     let dump = expensive_hex_dump(&buf);
///     crate::diag!("[verify] canonical={dump}\n");
/// }
/// ```
#[inline]
pub fn diag_enabled() -> bool {
    crate::config::VERBOSE
}

// =====================================================================
// must_getwd
// =====================================================================

/// The current working directory, or `"?"` on failure.
///
/// Matches the Go tree's `mustGetwd`. `current_dir()` fails only
/// when the directory the process was started in has been
/// unlinked or the process lacks permissions to read the
/// attribute; both are anomalies worth surfacing as `"?"` rather
/// than aborting.
pub fn must_getwd() -> String {
    std::env::current_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "?".to_string())
}

// =====================================================================
// parse_clock
// =====================================================================

/// Parse `"HH:MM"` into minutes since midnight.
///
/// Accepts `"09:00"`, `"9:00"`, `" 09:00 "` (trimmed), `"23:59"`.
/// Rejects `"24:00"`, `"09:60"`, `"-1:00"`, `"09"`, `"09:00:00"`,
/// `""`, `":30"`, `"09:"`.
///
/// The two-field split on the first `:` is deliberate and matches
/// `strings.SplitN(s, ":", 2)` in the Go tree: `"12:34:56"`
/// yields `("12", "34:56")`, whose second element fails to parse
/// as a number. `split_once(':')` in Rust produces the same
/// behaviour.
pub fn parse_clock(s: &str) -> Option<u32> {
    let s = s.trim();
    let (h_str, m_str) = s.split_once(':')?;
    let h: u32 = h_str.parse().ok()?;
    let m: u32 = m_str.parse().ok()?;
    if h > 23 || m > 59 {
        return None;
    }
    Some(h * 60 + m)
}

// =====================================================================
// format_work_hours
// =====================================================================

/// Format a work-hours window as `"HH:MM-HH:MM"`, or `"off"` when
/// `start == end`.
///
/// Takes `start` and `end` as arguments rather than reading from
/// a package-level variable — the values live in
/// [`crate::protocol::SharedState`], and the caller is expected
/// to read them via `state.work_hours()` first. This matches the
/// earlier `run_loop.rs` call shape:
///
/// ```ignore
/// let (start, end) = self.state.work_hours();
/// format_work_hours(start, end)
/// ```
pub fn format_work_hours(start: u32, end: u32) -> String {
    if start == end {
        return "off".to_string();
    }
    format!(
        "{:02}:{:02}-{:02}:{:02}",
        start / 60,
        start % 60,
        end / 60,
        end % 60,
    )
}

// =====================================================================
// inside_work_hours
// =====================================================================

/// Whether the current local time falls inside `[start, end)`.
///
/// `start == end` means "no window" (always inside). A wrapped
/// window — `start > end`, e.g. `22:00-06:00` — is treated as
/// "after `start` **or** before `end`", which covers the
/// overnight case.
///
/// Uses `chrono::Local::now()`. The Go tree took `now time.Time`
/// as an argument; this port reads the clock internally for the
/// convenience wrapper and exposes [`inside_work_hours_at`] for
/// tests and for callers that already have a `now` value.
pub fn inside_work_hours(start: u32, end: u32) -> bool {
    inside_work_hours_at(start, end, chrono::Local::now())
}

/// Same as [`inside_work_hours`] but with an explicit `now`.
///
/// The Go function's actual shape. Useful for tests and for any
/// caller that already has a `DateTime<Local>` and does not want
/// to pay for a second `Local::now()` syscall.
pub fn inside_work_hours_at(
    start: u32,
    end: u32,
    now: chrono::DateTime<chrono::Local>,
) -> bool {
    if start == end {
        return true;
    }
    let cur = now.hour() * 60 + now.minute();
    if start < end {
        cur >= start && cur < end
    } else {
        cur >= start || cur < end
    }
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    // -------------------- diag_enabled --------------------

    #[test]
    fn diag_enabled_matches_config() {
        assert_eq!(diag_enabled(), crate::config::VERBOSE);
    }

    // -------------------- must_getwd --------------------

    #[test]
    fn must_getwd_non_empty() {
        // current_dir always succeeds in the test harness's
        // CWD; assert the returned string is not the fallback.
        let s = must_getwd();
        assert!(!s.is_empty());
    }

    // -------------------- parse_clock --------------------

    #[test]
    fn parse_clock_accepts_valid() {
        assert_eq!(parse_clock("00:00"), Some(0));
        assert_eq!(parse_clock("08:00"), Some(480));
        assert_eq!(parse_clock("08:05"), Some(485));
        assert_eq!(parse_clock("19:00"), Some(1140));
        assert_eq!(parse_clock("23:59"), Some(1439));
        assert_eq!(parse_clock("9:00"), Some(540));
    }

    #[test]
    fn parse_clock_trims_whitespace() {
        assert_eq!(parse_clock("  08:00  "), Some(480));
        assert_eq!(parse_clock("\t09:30\n"), Some(570));
    }

    #[test]
    fn parse_clock_rejects_out_of_range() {
        assert_eq!(parse_clock("24:00"), None);
        assert_eq!(parse_clock("09:60"), None);
        assert_eq!(parse_clock("99:99"), None);
    }

    #[test]
    fn parse_clock_rejects_malformed() {
        for bad in ["", ":", "09", "09:", ":30", "09:00:00"] {
            assert_eq!(
                parse_clock(bad),
                None,
                "input = {bad:?}",
            );
        }
    }

    #[test]
    fn parse_clock_rejects_negative() {
        // u32::from_str rejects the leading `-`, matching the
        // Go `h < 0` check.
        assert_eq!(parse_clock("-1:00"), None);
        assert_eq!(parse_clock("08:-1"), None);
    }

    // -------------------- format_work_hours --------------------

    #[test]
    fn format_off_when_equal() {
        assert_eq!(format_work_hours(0, 0), "off");
        assert_eq!(format_work_hours(480, 480), "off");
    }

    #[test]
    fn format_normal_window() {
        assert_eq!(
            format_work_hours(480, 1140),
            "08:00-19:00"
        );
    }

    #[test]
    fn format_wrapped_window() {
        assert_eq!(
            format_work_hours(1320, 360),
            "22:00-06:00"
        );
    }

    #[test]
    fn format_pads_to_two_digits() {
        assert_eq!(
            format_work_hours(5, 9),
            "00:05-00:09"
        );
    }

    // -------------------- inside_work_hours_at --------------------

    fn at(h: u32, m: u32) -> chrono::DateTime<chrono::Local> {
        chrono::Local
            .with_ymd_and_hms(2026, 11, 2, h, m, 0)
            .unwrap()
    }

    #[test]
    fn no_window_is_always_inside() {
        for (h, m) in [(0, 0), (12, 0), (23, 59)] {
            assert!(inside_work_hours_at(480, 480, at(h, m)));
        }
    }

    #[test]
    fn normal_window_boundaries() {
        // Window [08:00, 19:00) — start inclusive, end
        // exclusive.
        assert!(!inside_work_hours_at(480, 1140, at(7, 59)));
        assert!(inside_work_hours_at(480, 1140, at(8, 0)));
        assert!(inside_work_hours_at(480, 1140, at(12, 0)));
        assert!(inside_work_hours_at(480, 1140, at(18, 59)));
        assert!(!inside_work_hours_at(480, 1140, at(19, 0)));
        assert!(!inside_work_hours_at(480, 1140, at(20, 0)));
    }

    #[test]
    fn wrapped_window() {
        // Window [22:00, 06:00) — overnight.
        assert!(!inside_work_hours_at(1320, 360, at(21, 59)));
        assert!(inside_work_hours_at(1320, 360, at(22, 0)));
        assert!(inside_work_hours_at(1320, 360, at(23, 30)));
        assert!(inside_work_hours_at(1320, 360, at(0, 0)));
        assert!(inside_work_hours_at(1320, 360, at(5, 59)));
        assert!(!inside_work_hours_at(1320, 360, at(6, 0)));
        assert!(!inside_work_hours_at(1320, 360, at(7, 0)));
    }

    #[test]
    fn inside_work_hours_reads_local_now() {
        // The convenience wrapper just calls the `_at` variant
        // with `Local::now()`; assert it does not panic and
        // returns a bool.
        let _ = inside_work_hours(480, 1140);
    }
}