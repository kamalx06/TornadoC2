//! Transport diagnostics.
//!
//! Port of `transport/diag.go`. The file is thin because the
//! work has moved:
//!
//! | Go | Rust |
//! |---|---|
//! | `var Verbose bool` (package-level runtime toggle) | `config::VERBOSE` (build-time `pub const bool`) |
//! | `func diag(format, args...)` | `diag!` macro in `lib.rs` |
//!
//! The Go tree could flip `transport.Verbose` at runtime — a
//! beacon started with `--verbose` could stop emitting
//! diagnostics mid-engagement. The Rust port cannot: the design
//! invariant is "no runtime configuration," and a runtime
//! diagnostic toggle is a runtime configuration surface. A build
//! that wants verbose output sets `TC2_VERBOSE=true` at build
//! time; the macro reduces to nothing in the non-verbose build.
//!
//! # When to use [`diag_enabled`]
//!
//! The crate-wide `diag!` macro handles the common case — "print
//! this if verbose." The function below exists for the rarer
//! case where the caller needs to *avoid work* only when the
//! output would be discarded: computing an expensive diagnostic
//! value, allocating a large string, iterating a collection just
//! to format it.
//!
//! ```ignore
//! if crate::transport::diag::diag_enabled() {
//!     let dump = expensive_hex_dump(&buf);
//!     diag!("[transport] buf = {dump}\n");
//! }
//! ```
//!
//! Because `config::VERBOSE` is a `pub const bool`, the compiler
//! eliminates the call site entirely when the value is `false` —
//! the `expensive_hex_dump` call is not emitted, and the
//! `diag!` inside the branch is also dead code. No runtime
//! branch remains in the generated binary.

/// Return `true` when verbose diagnostics are enabled.
///
/// Equivalent to the Go tree's `transport.Verbose` check, but
/// derived from `config::VERBOSE` — the `TC2_VERBOSE` const
/// emitted by `build.rs` — rather than from a package-level
/// mutable variable. There is no runtime toggle.
///
/// The compiler inlines and const-folds this to `false` or
/// `true` at every call site; no function call remains in the
/// generated binary.
#[inline]
pub fn diag_enabled() -> bool {
    crate::config::VERBOSE
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diag_enabled_matches_config() {
        // The function is a one-line forwarding to
        // `config::VERBOSE`. The test asserts the forwarding
        // survives a future refactor that changes the source
        // of the value.
        assert_eq!(diag_enabled(), crate::config::VERBOSE);
    }
}