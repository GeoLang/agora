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

/// Largest accepted attachment, bytes of the raw upload body.
pub const MAX_ATTACHMENT_BYTES: usize = 16 * 1024 * 1024;

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
/// presence together. A batch counts as one message per op it carries.
pub const MAX_CLIENT_MESSAGES_PER_SECOND: usize = 60;

/// Ops in one batch frame. A larger batch could never be accepted anyway, since
/// the rate limiter charges a batch per op.
pub const MAX_BATCH_OPS: usize = MAX_CLIENT_MESSAGES_PER_SECOND;

/// Connections allowed in one room.
pub const MAX_PEERS_PER_DOCUMENT: usize = 32;

/// Ops folded into the stored checkpoint at a time.
pub const CHECKPOINT_INTERVAL_OPS: u64 = 256;

/// Ops kept per document so a reconnect can replay instead of resnapshotting.
pub const RECONNECT_TAIL_OPS: i64 = 4096;

pub const MAX_REPLAY_BYTES: i64 = 4 * 1024 * 1024;

/// Lifetime of a share link session token, hours.
pub const SESSION_TOKEN_LIFETIME_HOURS: i64 = 12;

/// Entropy in a share link token, bytes.
pub const SHARE_TOKEN_BYTES: usize = 16;

/// Entropy in an attachment token, bytes. Wider than a share link token because
/// an attachment url is handed out to anything that renders the document and
/// there is nothing else to check on the read.
pub const ATTACHMENT_TOKEN_BYTES: usize = 32;

/// How long an attachment nothing points at survives. It has to outlive both a
/// live session's undo stack, which is per session and cleared when the session
/// leaves, and the reconnect tail, since either can put the reference back. A
/// week of orphaned blobs costs nothing.
pub const ATTACHMENT_GRACE_DAYS: i64 = 7;

/// How often the sweep looks for attachments nothing points at.
pub const ATTACHMENT_SWEEP_INTERVAL_HOURS: u64 = 6;

/// Longest accepted asset id or reading kind, bytes. Both are opaque ids a
/// sensor feed chooses, and agora has no asset directory, so a length bound is
/// the only check there is.
pub const MAX_ASSET_ID_BYTES: usize = 128;

/// Readings in one ingest frame. A larger frame could never be accepted anyway,
/// since the rate limiter charges a frame per reading.
pub const MAX_FEED_READINGS_PER_FRAME: usize = 256;

/// Readings allowed per second per ingest connection.
pub const MAX_FEED_READINGS_PER_SECOND: usize = 200;

/// Shortest and longest reporting interval a feed may declare, seconds.
pub const MIN_FEED_INTERVAL_SECONDS: i32 = 1;
pub const MAX_FEED_INTERVAL_SECONDS: i32 = 3600;

/// Lifetime of a feed token, days. A feed is a device that is set up once and
/// left alone, so the token outlives anyone who would notice it expiring.
/// Deleting the feed row is what revokes it.
pub const FEED_TOKEN_LIFETIME_DAYS: i64 = 3650;

/// Reporting intervals an asset may miss before it counts as offline.
pub const STALE_MISSED_INTERVALS: i64 = 3;

/// How often the loaded rooms are walked for assets that have gone quiet.
pub const STALE_CHECK_INTERVAL_SECONDS: u64 = 1;

/// Shortest reporting interval a region watch may declare, seconds. A watch
/// costs one geoplumb reduction per run, which is far more work than a sensor
/// reading, so it is floored well above a feed's.
pub const MIN_WATCH_INTERVAL_SECONDS: i32 = 60;

/// Ring positions across a watch region, summed over every ring. geoplumb
/// refuses a reduction past 20000, so a region accepted here always fits.
pub const MAX_REGION_POSITIONS: usize = 4_000;

/// Positions the smallest closed ring carries.
pub const MIN_RING_POSITIONS: usize = 4;

/// Bytes of a watch region's json encoding. The position cap does not bound a
/// position carrying a thousand numbers, nor the keys a geojson object may
/// carry beside the ones read here.
pub const MAX_REGION_BYTES: usize = 256 * 1024;

/// Longest accepted layer name, bytes. A layer name is whatever geoplumb's
/// config called it, and agora has no layer directory of its own.
pub const MAX_LAYER_NAME_BYTES: usize = 128;

/// Longest accepted webhook url and shared secret, bytes.
pub const MAX_WEBHOOK_URL_BYTES: usize = 2048;
pub const MAX_WEBHOOK_SECRET_BYTES: usize = 256;

/// Readings one watch keeps. The retention window drops old ones, and this
/// drops the ones a short interval piles up inside it.
pub const MAX_READINGS_PER_WATCH: i64 = 10_000;

/// Watch readings one list call returns.
pub const MAX_WATCH_READINGS_PAGE: i64 = 500;

/// How often the scheduler looks for watches whose interval has run out.
pub const WATCH_TICK_SECONDS: u64 = 30;

/// Watches one tick runs. They run one at a time, because geoplumb reduces four
/// regions at once and answers the rest a 503, so this bounds how long a tick
/// takes as well as how much work one asks for.
pub const MAX_WATCH_RUNS_PER_TICK: i64 = 16;

/// Characters of a failed run's reason kept on the watch.
pub const MAX_LAST_ERROR_CHARS: usize = 200;

/// Tries one webhook delivery gets, and the wait before the second, which
/// doubles for every attempt after it.
pub const WEBHOOK_ATTEMPTS: u32 = 3;
pub const WEBHOOK_BACKOFF_SECONDS: u64 = 2;

/// Ceiling on one webhook attempt.
pub const WEBHOOK_TIMEOUT_SECONDS: u64 = 10;

/// How long a reading is kept.
pub const READINGS_RETENTION_DAYS: i64 = 30;

/// How often the sweep deletes readings past the retention window.
pub const READINGS_SWEEP_INTERVAL_HOURS: u64 = 1;

/// Notifications one list call returns, newest first.
pub const NOTIFICATIONS_PAGE_SIZE: i64 = 50;

/// Characters of a comment's text and author name carried into its
/// notifications.
pub const NOTIFICATION_EXCERPT_CHARS: usize = 160;

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
    seen: usize,
    cap: usize,
}

impl RateLimiter {
    /// A document connection's limiter, charged per op and per presence frame.
    pub fn new() -> Self {
        Self::with_cap(MAX_CLIENT_MESSAGES_PER_SECOND)
    }

    pub fn with_cap(cap: usize) -> Self {
        Self {
            window_started: Instant::now(),
            seen: 0,
            cap,
        }
    }

    pub fn allow(&mut self) -> bool {
        self.allow_many(1)
    }

    /// Charge several messages at once, which is how a batch pays for every op
    /// it carries rather than for the one frame it arrived in. A refused charge
    /// still counts, so a client cannot probe the remaining budget for free.
    pub fn allow_many(&mut self, count: usize) -> bool {
        let now = Instant::now();
        if now.duration_since(self.window_started) >= Duration::from_secs(1) {
            self.window_started = now;
            self.seen = 0;
        }
        self.seen = self.seen.saturating_add(count);
        self.seen <= self.cap
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
    fn a_batch_charge_spends_the_window_and_sticks_after_a_refusal() {
        let mut limiter = RateLimiter::new();
        assert!(limiter.allow_many(MAX_CLIENT_MESSAGES_PER_SECOND));
        assert!(!limiter.allow());

        let mut limiter = RateLimiter::new();
        assert!(!limiter.allow_many(MAX_CLIENT_MESSAGES_PER_SECOND + 1));
        assert!(!limiter.allow(), "a refused batch left the budget unspent");
    }

    #[test]
    fn a_limiter_charges_against_the_cap_it_was_built_with() {
        let mut limiter = RateLimiter::with_cap(MAX_FEED_READINGS_PER_SECOND);
        assert!(limiter.allow_many(MAX_FEED_READINGS_PER_SECOND));
        assert!(!limiter.allow());

        let mut limiter = RateLimiter::with_cap(MAX_FEED_READINGS_PER_SECOND);
        assert!(!limiter.allow_many(MAX_FEED_READINGS_PER_SECOND + 1));
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
