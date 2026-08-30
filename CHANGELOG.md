# Changelog

## [Unreleased]

### Added

- 2026-08-30: **watches run on a schedule**. A background task ticks every 30
  seconds and runs the watches whose interval has run out, oldest first, up to
  16 a tick and one at a time. A run is one `POST {GEOPLUMB_URL}/zonal/{layer}`
  over the watch's region at 30 metre resolution, and the reducer's field out of
  the row it answers is stored in `watch_readings` and relayed to the room.
  Anything else lands in `lastError` and stores nothing, with the run still
  marked so the watch retries on its own interval. Watch readings age out on the
  30 day readings sweep, and a watch keeps its newest 10000.

- 2026-08-30: **watches on the document socket**. A join now carries a
  `watches` frame after `assets`, holding every watch on the document with no
  webhook url and no webhook secret in it, so a share link guest sees what is
  watched and not where its alerts go. A run relays
  `watchReading {watch, at, value, count, tripped}` to everyone looking.

- 2026-08-30: **region watches, stored and routed**. A document can hold watches
  over a region (`POST /documents/{id}/watches`, migration 009): a GeoJSON
  Polygon or MultiPolygon, one geoplumb layer, a reducer, an interval of at
  least 60 seconds, and optionally a threshold and a webhook. Edit role creates
  and deletes, any member lists them and reads a watch's history through
  `GET /documents/{id}/watches/{watchId}/readings`. The webhook url and secret
  reach a caller who can edit and are absent from everyone else's copy. The
  layer is checked against `GET {GEOPLUMB_URL}/layers` at create time, so an
  unknown one is a 422 naming it. `GEOPLUMB_URL` unset turns the feature off.

- 2026-08-30: **an unknown key is refused instead of ignored**. Every request
  body, query string and document socket frame now carries
  `serde(deny_unknown_fields)`, so a key the type does not define is an error
  rather than a silent no-op. A body key is a 422, the answer a missing field
  already gets, and a query key is a 400. On the socket it is a `malformed
  message` error, which also stops a client claiming `actor` on a `presence`
  frame. This is what turns a misspelling like `project_id` for `projectId` into
  a refusal instead of a document created with no project. The ingest wire
  format is the exception and stays tolerant: `readings` frames come from
  devices nobody here controls, and a firmware that adds a field must not start
  losing readings.

- 2026-08-25: **sensor feeds and asset liveness**. A document can register feeds
  (`POST /documents/{id}/feeds`, migration 008), each getting a token that
  reaches one new socket, `GET /feeds/ws`, and nothing else: every existing route
  and `/ws` now refuse a token carrying `agora_use`, and the socket also checks
  the feed row still exists on the document the token names, which is what
  deleting the feed revokes. A `readings` frame is stored in one insert, answered
  with `{"type": "ack", "count": N}` and fanned out to everyone on the document.
  `GET /documents/{id}/assets` answers the latest value per asset and kind with
  whether it is still reporting, and `?t=` on `/assets/at` answers the same as of
  a past moment. An asset that misses three of its feed's intervals gets a
  `liveness` frame, checked once a second over the documents somebody has open,
  and the next reading brings it back. A join now carries an `assets` frame
  between the snapshot and `peers`. Readings are kept 30 days. New `assets` op
  namespace for how a client draws them.

- 2026-08-23: **`GET /documents` lists what a project role reaches**. A caller
  who has no members row on a document but holds a role on the project it is
  linked to now finds it in their listing, at the wider of the two roles and
  once. The project half is resolved with one call to
  `GET {PTOLEMY_URL}/api/v1/projects` for the whole listing, so it is bounded by
  how many projects the caller belongs to rather than by how many documents are
  listed. No answer from ptolemy leaves the members table as the only authority,
  as everywhere else.

- 2026-08-23: **project roles reach documents**. A document can name a ptolemy
  project (`project_id`, migration 007), and a caller's role on that project
  counts on the document: `viewer` reads, `editor` and `owner` edit. It is the
  wider of that and the members row that applies, so a link never narrows access
  someone already had. Set it on `POST /documents` or through
  `PUT /documents/{id}/project`, which takes edit on the document and, when
  linking, editor or owner on the project asked fresh. Roles come from
  `GET {PTOLEMY_URL}/api/v1/projects/{id}` with the caller's own bearer token,
  cached 30 seconds per document and caller. Every failure leaves the caller with
  their members row alone: an unset `PTOLEMY_URL`, a refusal, a timeout, a scoped
  tool token, and a share link session, which carries no platform identity for
  ptolemy to answer about.

- 2026-08-13: **postgres over TLS**. sqlx gains the `tls-rustls-ring` backend, so
  the server can reach a database with `rds.force_ssl` set, which it previously
  could not do at all: with no backend compiled in, sqlx's default `prefer`
  quietly falls back to plaintext and the server refuses it. ring was already
  here through jsonwebtoken, so this adds rustls and no second TLS stack. The
  mode lives in `DATABASE_URL`, and hosted wants
  `sslmode=verify-full&sslrootcert=/etc/ssl/rds-global-bundle.pem`, not
  `sslmode=require`, which in sqlx encrypts without checking the certificate. The
  image now carries the RDS root bundle, since those roots are in no public trust
  store.

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
