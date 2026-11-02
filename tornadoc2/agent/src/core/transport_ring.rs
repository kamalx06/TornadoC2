//! Transport failover ring.
//!
//! Port of `.advanceTransport()` and `isTransportFailure()`.
//!
//! The agent holds a `Vec<Box<dyn Transport>>`. On a transport-level
//! failure (classified by [`is_transport_failure`]), the run loop
//! increments a counter; when the counter reaches
//! `cfg.transport_failover_after`, `advance_transport` rotates to
//! the next transport and resets the counter. The ring is
//! symmetric: after the last transport fails N times, the agent
//! rotates back to the first.
//!
//! # Ring vs preference list
//!
//! This is a ring, not a preference list. Once rotated, the agent
//! stays on the new transport until *it* has failed N consecutive
//! times. Matches the README's documented behaviour under
//! "HTTP+DNS / HTTP+DoH / DNS+DoH failover."

use super::agent::Agent;

impl Agent {
    /// Rotate to the next transport in the ring and reset the
    /// failure counter.
    ///
    /// No-op when there is only one transport — a single-transport
    /// build cannot fail over, and the counter is left for the
    /// run loop to read if it wants to log the repeated failure
    /// count.
    pub fn advance_transport(&mut self) {
        if self.transports.len() <= 1 {
            return;
        }
        let failures = self.transport_failures;
        self.transport_index =
            (self.transport_index + 1) % self.transports.len();
        self.transport_failures = 0;
        crate::diag!(
            "[transport] failed {failures} consecutive times; \
             rotating to {:?} (index {}/{})\n",
            self.transport_names[self.transport_index],
            self.transport_index,
            self.transports.len(),
        );
    }
}

/// Classify an error message as a transport-level failure.
///
/// The Go tree used substring matching against a fixed list;
/// this port preserves that list exactly. A structured classifier
/// would need `TransportError` to carry the socket-level error
/// kind, which the individual transports do not currently surface
/// — the strings are the actual information available at the
/// call site.
///
/// The markers cover:
///
/// - **DNS / connection**: `no such host`, `connection refused`,
///   `network is unreachable`, `no route to host`.
/// - **Timeouts**: `i/o timeout`.
/// - **TLS**: `certificate`, `TLS handshake`.
/// - **Socket family**: `dial tcp`, `dial udp`.
/// - **EOF / closed socket**: `EOF`.
/// - **Permission**: `permission denied`, `operation not permitted`.
///
/// Anything not in the list — a 4xx/5xx status, a shaping parse
/// failure, a cookie rejection — is not classified as a transport
/// failure, so it does not advance the ring. Those cases are the
/// run loop's session-invalid path (see `should_recheck`).
pub fn is_transport_failure(msg: &str) -> bool {
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

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::is_transport_failure;

    #[test]
    fn each_marker_is_recognised() {
        for marker in [
            "connection refused",
            "no such host",
            "i/o timeout",
            "certificate has expired",
            "TLS handshake failed",
            "dial tcp 1.2.3.4:443",
            "dial udp 1.2.3.4:53",
            "unexpected EOF",
            "network is unreachable",
            "no route to host",
            "permission denied",
            "operation not permitted",
        ] {
            assert!(
                is_transport_failure(marker),
                "marker not matched: {marker:?}",
            );
        }
    }

    #[test]
    fn server_status_is_not_transport_failure() {
        // A server-side 4xx/5xx is a session issue, not a
        // transport issue.
        for msg in [
            "tasks status 401 (wanted 200)",
            "tasks status 404 (wanted 200)",
            "results status 500 (wanted 204)",
        ] {
            assert!(
                !is_transport_failure(msg),
                "status should not match: {msg:?}",
            );
        }
    }

    #[test]
    fn shaping_failure_is_not_transport_failure() {
        assert!(!is_transport_failure(
            "checkin shape: bad path segment: \"[0]\"",
        ));
    }

    #[test]
    fn empty_string_not_matched() {
        assert!(!is_transport_failure(""));
    }
}