# Agora

Live multiplayer session service for GeoLang composition documents. A document
is one JSON object holding map layers, annotations, bookmarks and comments. Agora
owns it, orders every edit, and fans the edits out to everyone looking at it.

Single instance. The server assigns a sequence number to every op, and the last
writer on a key wins.

## Running

```
PLATFORM_JWT_SECRET=... DATABASE_URL=postgres://... cargo run -p agora-server
```

Migrations run at startup.

| Variable | Required | Meaning |
| --- | --- | --- |
| `PLATFORM_JWT_SECRET` | yes | Shared HS256 secret, 32 bytes or more. The same secret the other platform services validate. |
| `DATABASE_URL` | yes | Postgres connection string. Carries the TLS mode, see below. |
| `PORT` | no | Port to listen on, `3000` by default, which is the internal port the platform's nginx routes `/agora/` to. |
| `PTOLEMY_URL` | no | Ptolemy's base url, `http://` or `https://`. Turns on project roles, see below. Unset, only agora's own members reach a document, and startup says so. |
| `GEOPLUMB_URL` | no | Geoplumb's base url, `http://` or `https://`. Turns on region watches, see below. Unset, creating a watch is a 400 and nothing is scheduled. |

Copy `.env.example` and fill it in. Nothing reads a `.env` file at runtime, the
variables come from the environment.

## Project roles

A document can name a ptolemy project, and then a caller's role on that project
counts on the document: `viewer` reads, `editor` and `owner` edit. It is combined
with the members table rather than replacing it, so whichever of the two is wider
wins and taking a document into a project never narrows who already had it.

Set the link with `POST /documents` (`projectId`) or `PUT /documents/{id}/project`
(`{"projectId": ...}`, `null` to unlink). Linking takes edit on the document and
editor or owner on the project. Unlinking takes edit on the document alone.

Roles are read from ptolemy with the caller's own bearer token, cached for 30
seconds per document and caller. Every way that call can fail, an unset
`PTOLEMY_URL` included, leaves the caller with their members table role and
nothing else. Share link visitors never get a project role: the link is their
whole grant.

### Database TLS

The server is built with sqlx's `tls-rustls-ring` backend, so it can open a TLS
connection. Whether it opens one, and whether it checks who answered, is entirely
up to the `sslmode` in `DATABASE_URL`.

Against RDS, which refuses plaintext because `rds.force_ssl` is set, use:

```
postgres://agora:PASSWORD@ENDPOINT/agora?sslmode=verify-full&sslrootcert=/etc/ssl/rds-global-bundle.pem
```

Not `sslmode=require`. In sqlx, `require` encrypts and then accepts whatever
certificate it is handed, so anything able to answer in the database's place
reads and rewrites the session, credentials included. Only `verify-ca` and
`verify-full` check the certificate, and only `verify-full` also checks that the
hostname matches. The RDS certificate carries the instance endpoint, so point the
URL at that endpoint and not at a CNAME in front of it.

`sslrootcert` is needed because the Amazon RDS roots are private and appear in no
public trust store. The image carries the bundle at
`/etc/ssl/rds-global-bundle.pem`, downloaded from
`https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem` at build time.
Running outside the image, pass a path to your own copy.

Local and CI Postgres have no TLS, so their URLs leave `sslmode` unset and get
sqlx's `prefer`, which is a plaintext connection when the server offers no TLS.

## Document state

```json
{
  "meta": {"name": "city plan"},
  "layers": {"roads": {"order": "a0", "...": "..."}},
  "annotations": {},
  "bookmarks": {},
  "comments": {},
  "assets": {"rule": {"...": "..."}}
}
```

A layer's `order` is a client convention, a fractional index string, so a reorder
is a write to one key rather than a rewrite of the list. The server neither reads
nor validates it: op validation covers the key shape and the value size and
nothing else. Layer, annotation, bookmark, comment and asset
values are opaque JSON to the server. Only `meta/name` has server meaning: it has
to be a string within the name cap, and it also updates the document row.

`assets` holds how a client turns sensor readings into what is drawn on the map,
under whatever keys it likes. Readings themselves are not document state: they
arrive on the ingest socket and are served by the asset routes below.

A comment thread is flat: a reply is its own key carrying its parent's id, and
the client groups them. The server enforces no authorship, so any editor can
overwrite or delete any comment key.

One exception to comment opacity: a comment value's `mentions` array of
`{"userId": "..."}` entries is read on write. Each user id that is a current
member of the document, was not in the key's previous value and is not the
writer gets a notification row, on the op's own transaction. Deleting a comment
deletes its unread notifications, and removing a member deletes their
notifications for that document. Notifications are served by `GET
/notifications`, so a member with no open socket finds out by polling.

## HTTP API

Every route needs `Authorization: Bearer <platform jwt>` except `GET /health`,
`GET /links/{token}` and `GET /attachments/{token}`, which carry no credential
beyond the token in the url.

A scoped tool token is also accepted, on every route and on the websocket. It is
admitted when it carries `agora:read` for a `GET` or `HEAD` and `agora:write` for
anything else.

| Route | Does |
| --- | --- |
| `POST /documents` `{"name": "...", "projectId": "..."}` | Creates a document. The caller becomes its edit member. `projectId` is optional and takes editor or owner on that project. |
| `GET /documents` | The caller's documents. Members rows only, so a document reached through a project role alone is not listed. |
| `GET /documents/{id}` | Name, creation details, project and members. |
| `PUT /documents/{id}/project` `{"projectId": "..."\|null}` | Links the document to a project or unlinks it. Edit role, plus editor or owner on the project when linking. |
| `PUT /documents/{id}/members/{userId}` `{"role": "view"\|"edit"}` | Adds a member or changes their role, edit role only. Idempotent. |
| `DELETE /documents/{id}/members/{userId}` | Removes a member, edit role only. |
| `POST /documents/{id}/links` `{"role": "view"\|"edit"}` | Mints a share link, edit role only. Returns `{"token": "..."}`. |
| `POST /documents/{id}/attachments` | Stores one image against the document, edit role only. Raw body, `Content-Type` header. Returns `{"token": "...", "url": "/attachments/..."}`. |
| `POST /documents/{id}/feeds` `{"name": "...", "intervalSeconds": 5}` | Registers a sensor feed, edit role only. Returns `{"id", "name", "intervalSeconds", "token"}`, and the token appears here and nowhere else. |
| `GET /documents/{id}/feeds` | The document's feeds: `{"id", "name", "intervalSeconds", "createdBy", "createdAt"}`. Never the token. |
| `DELETE /documents/{id}/feeds/{feedId}` | Revokes a feed and deletes its readings, edit role only. |
| `POST /documents/{id}/watches` | Registers a region watch, edit role only. Returns the watch, webhook included. |
| `GET /documents/{id}/watches` | The document's watches. The webhook url and secret are there only for a caller who can edit, and absent rather than null for anyone else. |
| `DELETE /documents/{id}/watches/{watchId}` | Deletes a watch and its readings and notifications, edit role only. |
| `GET /documents/{id}/watches/{watchId}/readings?since=<rfc3339>&limit=` | The watch's readings, oldest first, after `since`. |
| `GET /documents/{id}/assets` | What every asset the document's feeds report is doing now. |
| `GET /documents/{id}/assets/at?t=<rfc3339>` | The same as of `t`. A missing or unparsable `t` is a 400. |
| `GET /attachments/{token}` | Reads an attachment. No credential beyond the token. |
| `DELETE /links/{token}` | Revokes a share link, edit role only. |
| `GET /links/{token}` | Resolves a link to `{"doc": "...", "role": "...", "sessionToken": "..."}`. |
| `GET /notifications` | The caller's latest 50 mention notifications, newest first. Hard capped, with no pagination and no total count, so a caller past 50 unread never sees the rest. |
| `POST /notifications/read` `{"ids": ["..."]}` | Marks the caller's notifications read, every unread one when `ids` is absent. |

Bodies and query strings are read strictly. A key the route does not define is
refused rather than ignored, so a client sending `project_id` where the route
reads `projectId` is told, instead of creating a document with no project. An
unknown body key is a 422, the same answer a missing or mistyped field already
gets, and an unknown query key is a 400.

`sessionToken` is a short lived HS256 JWT carrying the document, the role and a
random anonymous actor id. It is not a platform token and is refused everywhere a
platform token is required, so a share link cannot create documents or mint
further links.

A caller who cannot edit a document is told a link does not exist rather than
that it is forbidden, so link tokens cannot be probed.

There is no owner or admin role, so managing members needs the edit role and
nothing more, which an editor could already hand out as an edit link. A document
always keeps at least one edit member: removing or demoting the last editor is a
400, including when an editor is acting on themself.

A `userId` is a platform JWT subject. Agora has no user directory, so it is
taken as given and only checked for length, and adding a member who never signs
in costs nothing.

## Attachments

An op value is capped at 64 KiB, so a bitmap an overlay draws cannot travel as
one. It is uploaded on its own and the op carries its url.

```
POST /documents/{id}/attachments
Authorization: Bearer <platform jwt>
Content-Type: image/png

<the bytes>
```

The reply is `{"token": "...", "url": "/attachments/<token>"}`, and the url is
relative to the agora base url the client already uses. The token is 256 random
bits and the database stores only its SHA-256, so a database read hands over no
working url. Reading takes the token and nothing else, and it reaches that one
attachment.

An attachment never changes, so there is no update route and reads are served
`Cache-Control: public, max-age=31536000, immutable`. The schema cascades a
document's attachments away when the document row is deleted, but the API
registers no `DELETE /documents/{id}`, so that path is reachable only through
direct SQL.

The content type has to be `image/png`, `image/jpeg`, `image/webp`, `image/gif`
or `image/avif`, sent without a charset or with one. Anything a browser would
execute, `text/html` and `image/svg+xml` above all, is a 400: reads carry no
credential and come from agora's own origin, so a stored script would be an
editor's code running on the platform origin. Reads also carry
`X-Content-Type-Options: nosniff`.

Nothing caps how many attachments a document holds.

### Expiry

There is no delete route. A client driven delete would fight per user undo and
the reconnect tail, either of which can put back an entry that points at the
attachment. Instead a sweep decides liveness from the document itself: an
attachment is live while the document's current state, the same state a joining
client is sent, carries its url. Being pointed at refreshes it, and going seven
days unpointed at deletes it.

Keep the url the upload returned in the value. The sweep looks for
`/attachments/<token>` anywhere in the serialized state, so an absolute url
containing it counts too, but a value holding the bare token does not.

Seven days because the grace period has to outlive anything that can restore a
reference: a session's undo stack, which is per session and cleared when the
session leaves, and the reconnect tail. A week of orphaned blobs costs nothing.

Reading an attachment deliberately does not refresh it. Reads are cached as
immutable, so agora never sees most of them and read driven liveness would call
a live attachment dead.

The sweep runs every six hours, and only looks at documents holding an
attachment that is already past its grace period, so a document with no
attachments and a document whose attachments were confirmed recently both cost
nothing.

## Feeds

A feed is a sensor source reporting to one document. An editor registers it with
`POST /documents/{id}/feeds`, naming how often it reports, and gets a token back.
That reply is the only place the token exists: nothing stores it, and a lost one
is replaced by deleting the feed and registering another.

```
POST /documents/{id}/feeds
Authorization: Bearer <platform jwt>

{"name": "roof sensors", "intervalSeconds": 5}
```

The token is an HS256 JWT signed with the platform secret, carrying the feed id
as `sub`, the document as `doc` and `agora_use: "feed"`. It reaches the ingest
socket and nothing else: every other route and `/ws` refuse any token carrying
`agora_use` at all, so it is not a caller anywhere and grants no read of the
document. Deleting the feed row revokes it, since the ingest socket checks that
the feed still exists and is still on the document the token names.

### Ingesting readings

`GET /feeds/ws`, with the feed token offered the same way `/ws` takes one:

```js
new WebSocket(`${base}/feeds/ws`, ["bearer", feedToken])
```

```json
{"type": "readings", "readings": [{"asset": "TWIN-03", "kind": "temperature", "value": 21.5, "at": "2026-08-25T12:00:00Z"}]}
```

`at` is optional and defaults to when the server took the frame, which is what a
device with no clock relies on. `asset` and `kind` are opaque ids the feed
chooses, carrying no whitespace and no control characters. `value` is a finite
number.

A key not listed here is ignored rather than refused, which is the one place
agora tolerates one. Feeds are devices nobody here controls, and a firmware that
adds a field must not start losing readings.

An accepted frame answers `{"type": "ack", "count": 5}`, counting the readings
it carried, and goes out to everyone on the document as a `readings` frame. A
reading that repeats one already stored is dropped, so a feed replaying after a
reconnect costs nothing.

Anything refused answers `{"type": "error", "reason": "..."}` and closes the
connection, unlike the document socket, which stays open. A feed is a device
rather than a person: whatever it is sending it will keep sending, so the
refusal has to reach the code that reconnects. Deleting the feed while a socket
is open closes it on its next frame with `feed revoked`.

### Assets

An asset is whatever `asset` ids the readings carry. `GET /documents/{id}/assets`
answers with the latest reading of every kind per asset:

```json
{"assets": [{"asset": "TWIN-03", "feed": "...", "online": true, "values": [{"kind": "temperature", "value": 21.5, "at": "2026-08-25T12:00:00Z"}]}]}
```

`GET /documents/{id}/assets/at?t=<rfc3339>` answers the same shape as of `t`:
every value the latest at or before it, and `online` judged against it rather
than against now.

An asset is online while its newest reading of any kind is at or after now minus
three times its feed's interval. Three missed reports, so a single late one is
not an outage. When an asset crosses that line the room sends
`{"type": "liveness", "asset": "...", "online": false, "at": "..."}`, and the
next reading sends the same frame with `online: true`. The check runs once a
second over the documents somebody has open. A document nobody is looking at is
not checked, since there is nobody to tell, and its assets are judged again the
next time somebody joins.

Readings are kept for 30 days, and a sweep deletes what is older every hour.
Nothing caps how many feeds a document holds or how many assets a feed reports,
so the rate limit and the retention window are the only bounds on how many rows
a feed can write.

## Region watches

A watch is a region of the map, reduced over one geoplumb layer on a schedule.
An editor draws the region and names the layer, the reducer and how often to
run:

```
POST /documents/{id}/watches
Authorization: Bearer <platform jwt>

{
  "name": "reservoir",
  "layer": "ndvi",
  "region": {"type": "Polygon", "coordinates": [[[...]]]},
  "reducer": "mean",
  "intervalSeconds": 3600,
  "thresholdOp": "lt",
  "thresholdValue": 0.4,
  "webhookUrl": "https://hooks.example.test/basin",
  "webhookSecret": "..."
}
```

`region` is a GeoJSON `Polygon` or `MultiPolygon` in lon/lat degrees. `reducer`
is one of `mean`, `min`, `max`, `sum` or `count`. `thresholdOp` is `gt` or `lt`
and comes with a `thresholdValue` or not at all: a watch with no threshold
records its readings and alerts nobody. The webhook is optional, and both halves
of it come back only to a caller who can edit.

The layer is checked against `GET {GEOPLUMB_URL}/layers` while the create is
still in flight, so a name geoplumb does not serve is a 422 naming it rather
than a watch that fails every interval. A geoplumb that does not answer is a
503, since a watch stored against an unchecked layer is a watch nobody knows is
broken.

Watches belong to the document rather than to whoever made one, so any editor
can delete one, and deleting the document takes them with it.

### Running a watch

A scheduler ticks every 30 seconds, takes the watches whose interval has run
out, oldest first, and runs up to 16 of them one at a time. Each one is a
`POST {GEOPLUMB_URL}/zonal/{layer}` carrying the region as a one feature
collection at 30 metre resolution and no `t`, which leaves geoplumb on the
layer's own window. They run one at a time because geoplumb reduces four regions
at once and answers the rest a 503.

The reducer picks its own field out of the row that comes back, and that value
and the pixel count are stored against the watch. Anything else, a refusal, a
timeout, a body that is not a reduction, or a region that caught no pixels,
lands in `lastError` instead and stores nothing. Either way the run is marked,
so a watch geoplumb cannot answer retries on its own interval rather than on
every tick, and the next reading clears the error.

Readings are kept for 30 days, the same window a sensor reading gets, and a
watch keeps its newest 10000 whatever the window says.

## Websocket

`GET /ws?doc=<id>` and optionally `&since=<seq>`.

Offer the token as a subprotocol, which is the platform handshake and the way
this should be used:

```js
new WebSocket(`${base}/ws?doc=${documentId}`, ["bearer", token])
```

That sends `Sec-WebSocket-Protocol: bearer, <token>`, with the marker first and
the token second. The response echoes `bearer` and never the token. Prefer it
over the url because proxies log urls and not headers.

Non browser clients may send `Authorization: Bearer <token>` and offer no
subprotocol. A `?token=` query param also works as a last resort. Agora never
logs a request url.

The token is either a platform JWT of a member of the document or a
`sessionToken` from a share link on that document.

On connect the server sends either a `snapshot` or the ops after `since`, then
`assets`, then `peers`. `peers` always ends the join sequence, so a client knows
it is caught up when `peers` arrives. Ops after `since` are replayed only while
the retained tail still reaches back that far, otherwise the client gets a
snapshot. `assets` goes out on every join, a resume that missed nothing
included, because asset state is not carried by ops and cannot be replayed from
the tail.

### Client to server

```json
{"type": "op", "clientSeq": 4, "key": "layers/roads", "value": {"order": "a0"}}
{"type": "op", "clientSeq": 5, "key": "layers/roads", "value": null}
{"type": "batch", "clientSeq": 6, "ops": [{"key": "layers/roads", "value": {"order": "a1"}}, {"key": "layers/rail", "value": null}]}
{"type": "presence", "cursor": [12.5, -3.25], "selection": ["layers/roads"], "viewport": {}}
```

`value: null` deletes the key. The field is required, so a message that omits it
is refused rather than deleting anything.

A frame on this socket carrying a key its type does not define is a `malformed
message` error. That covers `actor` on a `presence` frame and `seq` on an op,
both of which the server decides and a client may not claim. The ingest socket
is the exception and ignores an unknown key, described under Feeds above.

A `batch` is several ops the server applies all or nothing, which is what keeps a
multi feature paste or a multi layer reorder from rendering half done on a peer.
Every op is validated before any of them is ordered, so one bad op refuses the
whole frame with an `error` naming its position, and the document is left as it
was. Duplicate keys inside a batch are allowed and settle last writer wins, the
same as two separate ops. One `clientSeq` covers the batch and one `ack` answers
it.

Keys are `<namespace>/<id>` where the namespace is one of `meta`, `layers`,
`annotations`, `bookmarks`, `comments` or `assets`, and the id is letters,
digits, `-`, `_` or `.`. Anything else is refused.

### Server to client

```json
{"type": "snapshot", "seq": 12, "state": {}, "actor": "user-1", "role": "edit"}
{"type": "op", "seq": 13, "actor": "user-1", "key": "layers/roads", "value": null}
{"type": "batch", "actor": "user-1", "ops": [{"seq": 14, "key": "layers/roads", "value": {"order": "a1"}}, {"seq": 15, "key": "layers/rail", "value": null}]}
{"type": "ack", "clientSeq": 4, "seq": 13}
{"type": "peers", "peers": [{"actor": "user-1", "name": "Ada", "role": "edit"}]}
{"type": "presence", "actor": "user-1", "cursor": [12.5, -3.25], "selection": [], "viewport": null}
{"type": "readings", "feed": "...", "readings": [{"asset": "TWIN-03", "kind": "temperature", "value": 21.5, "at": "2026-08-25T12:00:00Z"}]}
{"type": "assets", "assets": [{"asset": "TWIN-03", "feed": "...", "online": true, "values": [{"kind": "temperature", "value": 21.5, "at": "2026-08-25T12:00:00Z"}]}]}
{"type": "liveness", "asset": "TWIN-03", "online": false, "at": "2026-08-25T12:00:16Z"}
{"type": "watches", "watches": [{"id": "...", "name": "reservoir", "layer": "ndvi", "region": {}, "reducer": "mean", "intervalSeconds": 3600, "thresholdOp": "lt", "thresholdValue": 0.4, "createdBy": "user-1", "createdAt": "2026-08-30T09:00:00Z", "lastRunAt": null, "lastError": null}]}
{"type": "watchReading", "watch": "...", "at": "2026-08-30T12:00:00Z", "value": 0.31, "count": 4096, "tripped": true}
{"type": "error", "reason": "edit role required"}
```

`readings`, `assets` and `liveness` carry no `seq` and are not ops. They come
from the feeds on the document, described under Feeds above, and `assets` holds
the same JSON as `GET /documents/{id}/assets`.

`watches` goes out on every join, after `assets`, and holds every watch on the
document. It never carries `webhookUrl` or `webhookSecret`, so a share link
guest on this socket sees what a watch measures and not where its alerts go.
`watchReading` goes out on every watch run that produced a number, with
`tripped` set on the run that crossed the watch's threshold. Neither is an op
and neither carries a `seq`.

`peers` goes out on every join and leave. A refused message is an `error` and the
connection stays open, unless the credential itself is the problem, which is a
4xx before the handshake completes. A document already at its peer cap is a third
case: the handshake completes, then the server sends an `error` and closes.

Apply ops in `seq` order. A client receives its own ops back alongside the `ack`,
which is what keeps two tabs of one account in step.

A batch takes one seq per op, so `batch` carries the same ops an `op` frame would
and only groups them. Apply them in the order given and treat the last seq as the
one reached. A batch of a single op relays as an `op`, since there is nothing to
hold together. A reconnect with `since` replays a batch as a `batch` frame, but
only the part of it after `since`: the replay selects on `seq > since`, so a
`since` landing inside a batch yields the remainder as a shorter `batch`, or as a
plain `op` when one op is left. What is guaranteed is that the ops arrive in
`seq` order and none is skipped, not that a batch is always whole.

A connection that falls far enough behind to lose messages is sent a fresh
`snapshot` instead of the ops it missed, so presence traffic can be dropped under
load without costing anyone a consistent document.

A `snapshot` also tells a client its own `actor` and `role`, so it can filter
itself out of the peer list and know it is read only before an op is refused.

Presence is relayed and never stored. The `actor` is set by the server, so a
client cannot present itself as somebody else, and presence is never sent back to
the peer that produced it. The exclusion is per connection, so two tabs of one
account still see each other.

A refusal is best effort. A client that floods past the rate limit faster than it
reads loses some of its `error` and `ack` messages rather than the connection, and
reconnecting with `since` is what puts it back in step.

## Limits

All of these are named constants in `crates/agora-server/src/limits.rs`. Passing
one is an `error` message or a 4xx, never a panic.

| Limit | Value |
| --- | --- |
| Op key | 128 bytes |
| Op value | 64 KiB of JSON |
| Presence frame | 4 KiB |
| Websocket frame | 128 KiB, larger closes the connection |
| Client messages per connection | 60 per second, ops and presence together, a batch counting one per op |
| Ops in one batch | 60, which is the whole per second budget |
| Peers per document | 32 |
| Document name | 200 bytes |
| Member user id | 128 bytes |
| Document state | 4 MiB, measured as the sum over stored keys of the key length plus the JSON length of its value |
| Attachment | 16 MiB, refused while the body is still arriving |
| Feed name | 200 bytes, the same as a document name |
| Feed interval | 1 to 3600 seconds |
| Asset id and reading kind | 128 bytes each |
| Readings in one ingest frame | 256 |
| Readings per ingest connection | 200 per second, so a frame at the 256 cap is refused by the rate limit first |
| Watch name | 200 bytes, the same as a document name |
| Watch interval | 60 seconds or more |
| Watch region | 4000 ring positions and 256 KiB of JSON, both under what geoplumb reduces |
| Layer name | 128 bytes of letters, digits, `-` and `_`, so it stays one url path segment |
| Webhook url and secret | 2048 and 256 bytes |
| Watch readings per list call | 500 |
| Watch readings kept per watch | 10000, on top of the 30 day window |
| Watches run per tick | 16, one at a time, every 30 seconds |

Share link tokens are 128 random bits and attachment tokens 256, url safe.
Session tokens expire after 12 hours and feed tokens after ten years, since a
feed is set up once and revoked by deleting its row rather than by expiry.

The database stores only the SHA-256 of a share link or attachment token, so a
database read hands over no working link and no working attachment url. The raw
token is returned once when it is minted and never again.

## Revoking a share link

Revoking stops link resolution and stops any new websocket connection using a
session token from that link. A connection already open on a revoked link keeps
working until it drops. Close the tab or restart agora to cut one off
immediately.

## Storage

Attachment bytes sit in Postgres beside everything else, in `attachments`,
sensor readings in `readings`, keyed by feed, asset, kind and time, and watch
readings in `watch_readings`, keyed by watch and time.

Ops are appended to `ops` and folded into `documents.checkpoint` every 256 ops
after the last fold (`seq - checkpoint_seq`). The fold and the prune run in one
transaction, and the last 4096 ops per document are kept so a reconnect can
replay rather than resnapshot. A room is loaded from the checkpoint plus that
tail on the first join and dropped when the last connection leaves. The interval
is the stored gap, not ops in the current room lifetime, so a document edited
only in short sessions still folds once that gap reaches 256.

## Tests

The suite needs a reachable Postgres. It creates its own tables and never drops
any, so it is safe to point at a scratch database and to run in parallel.

```
DATABASE_URL=postgres://postgres:postgres@localhost/agora_test cargo test --all
```

Without `DATABASE_URL` the tests try
`postgres://postgres:postgres@localhost/agora_test`.

## License

AGPL-3.0-or-later.
