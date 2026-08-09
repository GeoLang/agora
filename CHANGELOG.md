# Changelog

## [Unreleased]

### Added

- 2026-08-09: **attachments expire once nothing points at them**. Attachments
  carry a `last_referenced_at` stamp (migration 006), set when they are uploaded
  and refreshed by a sweep that finds the attachment's url in the document's
  current state. Seven days unpointed at and the row goes. The sweep runs every
  six hours and only looks at documents holding an attachment already past its
  grace period, so a document with no attachments costs nothing. There is still
  no delete route: a client driven delete would fight undo and the reconnect
  tail. Reading an attachment does not refresh it, since reads are cached as
  immutable and agora never sees most of them.

- 2026-08-09: **document attachments**. `POST /documents/{id}/attachments`
  stores one image against a document, edit role only, raw body up to 16 MiB
  with the content type from the header. It answers `{"token", "url"}`, and
  `GET /attachments/{token}` serves those bytes to anyone holding the token,
  with no other credential and long lived immutable cache headers. The token is
  256 random bits stored as its SHA-256, the same way share links are kept.
  Attachments never change, so there is no update route, and deleting a document
  deletes them. Content types are limited to png, jpeg, webp, gif and avif,
  since a read carries no credential and runs on agora's own origin. Migration
  005.

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
