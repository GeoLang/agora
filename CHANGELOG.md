# Changelog

## [Unreleased]

### Added

- 2026-08-09: **batch replay keeps its frame**. Every op row carries the seq
  of its frame's first op (migration 004), so a reconnect with `since` replays
  a batch as the one `batch` frame it was applied in rather than N separate
  `op` frames.

- 2026-08-08: **mention notifications**. A comment value's `mentions` array
  (`{"userId": ...}` entries) is read on write, the one exception to comment
  opacity besides `meta/name`: each newly named user who is a document member
  and not the writer gets a row in the new `notifications` table, inserted on
  the op's own transaction. Rewrites diff against the key's previous value, so
  resolving or editing a comment never pings twice. Deleting a comment deletes
  its unread notifications, removing a member deletes theirs for that document.
  New routes: `GET /notifications` (latest 50, with document name) and
  `POST /notifications/read` (ids, or everything unread when absent), platform
  tokens only. Migration 003.
