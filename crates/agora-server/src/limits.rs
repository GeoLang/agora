use std::time::{Duration, Instant};

/// Longest accepted op key, bytes.
pub const MAX_KEY_BYTES: usize = 128;

/// Longest accepted op value, bytes of its json encoding.
pub const MAX_OP_VALUE_BYTES: usize = 64 * 1024;

/// Longest accepted presence frame, bytes of the raw text frame.
pub const MAX_PRESENCE_BYTES: usize = 4 * 1024;

/// Largest accepted document state. Measured as the sum over stored keys of
/// key length plus the json encoding length of the value.
pub const MAX_DOCUMENT_STATE_BYTES: usize = 4 * 1024 * 1024;

/// Longest accepted document name, bytes.
pub const MAX_DOCUMENT_NAME_BYTES: usize = 200;

/// Longest accepted member user id, bytes. A user id is an opaque platform jwt
/// subject and agora has no user directory, so a length bound is the only check
/// there is.
pub const MAX_USER_ID_BYTES: usize = 128;

/// Hard websocket message limit. Anything larger closes the connection before
/// it is buffered, so it never reaches the graceful per-field checks.
pub const MAX_INBOUND_FRAME_BYTES: usize = 128 * 1024;

/// Inbound client messages allowed per second per connection, ops and
/// presence together.
pub const MAX_CLIENT_MESSAGES_PER_SECOND: u32 = 60;

/// Connections allowed in one room.
pub const MAX_PEERS_PER_DOCUMENT: usize = 32;

/// Ops folded into the stored checkpoint at a time.
pub const CHECKPOINT_INTERVAL_OPS: u64 = 256;

/// Ops kept per document so a reconnect can replay instead of resnapshotting.
pub const RECONNECT_TAIL_OPS: i64 = 4096;

/// Lifetime of a share link session token, hours.
pub const SESSION_TOKEN_LIFETIME_HOURS: i64 = 12;

/// Entropy in a share link token, bytes.
pub const SHARE_TOKEN_BYTES: usize = 16;

/// Room fan out buffer. A connection that falls this far behind is resynced
/// with a fresh snapshot rather than dropped.
pub const ROOM_BROADCAST_CAPACITY: usize = 256;

/// Per connection buffer for messages addressed to one client.
pub const DIRECT_CHANNEL_CAPACITY: usize = 32;

/// Oldest op seq worth keeping once the document is checkpointed at
/// `checkpoint_seq`, leaving [`RECONNECT_TAIL_OPS`] behind it.
///
/// `None` when the document is younger than the tail, so there is nothing to
/// prune. Op seqs start at 1.
pub fn oldest_op_to_keep(checkpoint_seq: i64) -> Option<i64> {
    let oldest = checkpoint_seq.checked_sub(RECONNECT_TAIL_OPS - 1)?;
    (oldest > 1).then_some(oldest)
}

/// Fixed one second window counter, one per connection.
pub struct RateLimiter {
    window_started: Instant,
    seen: u32,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            window_started: Instant::now(),
            seen: 0,
        }
    }

    pub fn allow(&mut self) -> bool {
        let now = Instant::now();
        if now.duration_since(self.window_started) >= Duration::from_secs(1) {
            self.window_started = now;
            self.seen = 0;
        }
        self.seen += 1;
        self.seen <= MAX_CLIENT_MESSAGES_PER_SECOND
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn rate_limiter_allows_up_to_the_cap_then_refuses() {
        let mut limiter = RateLimiter::new();
        for index in 0..MAX_CLIENT_MESSAGES_PER_SECOND {
            assert!(limiter.allow(), "message {index} inside the cap");
        }
        assert!(!limiter.allow());
        assert!(!limiter.allow());
    }

    #[test]
    fn pruning_keeps_the_whole_tail_for_young_documents() {
        assert_eq!(oldest_op_to_keep(0), None);
        assert_eq!(oldest_op_to_keep(256), None);
        assert_eq!(oldest_op_to_keep(RECONNECT_TAIL_OPS), None);
        assert_eq!(oldest_op_to_keep(i64::MIN), None);
    }

    #[test]
    fn pruning_leaves_exactly_the_reconnect_tail() {
        let checkpoint_seq = RECONNECT_TAIL_OPS + 10;
        let oldest = oldest_op_to_keep(checkpoint_seq).unwrap();
        assert_eq!(oldest, 11);
        let kept = checkpoint_seq - oldest + 1;
        assert_eq!(kept, RECONNECT_TAIL_OPS);
    }
}
