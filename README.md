# Agora

Live multiplayer session service for GeoLang composition documents. A document
is one JSON object holding map layers, annotations and bookmarks. Agora owns it,
orders every edit, and fans the edits out to everyone looking at it.

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
| `DATABASE_URL` | yes | Postgres connection string. |
| `PORT` | no | Port to listen on, `3000` by default, which is the internal port the platform's nginx routes `/agora/` to. |

Copy `.env.example` and fill it in. Nothing reads a `.env` file at runtime, the
variables come from the environment.

## Document state

```json
{
  "meta": {"name": "city plan"},
  "layers": {"roads": {"order": "a0", "...": "..."}},
  "annotations": {},
  "bookmarks": {}
}
```

A layer's `order` is a fractional index string, so a reorder is a write to one
key rather than a rewrite of the list. Layer, annotation and bookmark values are
opaque JSON to the server. Only `meta/name` has server meaning: it has to be a
string within the name cap, and it also updates the document row.

## HTTP API

Every route needs `Authorization: Bearer <platform jwt>` except `GET /health` and
`GET /links/{token}`.

| Route | Does |
| --- | --- |
| `POST /documents` `{"name": "..."}` | Creates a document. The caller becomes its edit member. |
| `GET /documents` | The caller's documents. |
| `GET /documents/{id}` | Name, creation details and members. |
| `POST /documents/{id}/links` `{"role": "view"\|"edit"}` | Mints a share link, edit role only. Returns `{"token": "..."}`. |
| `DELETE /links/{token}` | Revokes a share link, edit role only. |
| `GET /links/{token}` | Resolves a link to `{"doc": "...", "role": "...", "sessionToken": "..."}`. |

`sessionToken` is a short lived HS256 JWT carrying the document, the role and a
random anonymous actor id. It is not a platform token and is refused everywhere a
platform token is required, so a share link cannot create documents or mint
further links.

A caller who cannot edit a document is told a link does not exist rather than
that it is forbidden, so link tokens cannot be probed.

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

On connect the server sends either a `snapshot` or the ops after `since`, and
then `peers`. `peers` always ends the join sequence, so a client knows it is
caught up when `peers` arrives. Ops after `since` are replayed only while the
retained tail still reaches back that far, otherwise the client gets a snapshot.

### Client to server

```json
{"type": "op", "clientSeq": 4, "key": "layers/roads", "value": {"order": "a0"}}
{"type": "op", "clientSeq": 5, "key": "layers/roads", "value": null}
{"type": "presence", "cursor": [12.5, -3.25], "selection": ["layers/roads"], "viewport": {}}
```

`value: null` deletes the key. The field is required, so a message that omits it
is refused rather than deleting anything.

Keys are `<namespace>/<id>` where the namespace is one of `meta`, `layers`,
`annotations` or `bookmarks`, and the id is letters, digits, `-`, `_` or `.`.
Anything else is refused.

### Server to client

```json
{"type": "snapshot", "seq": 12, "state": {}, "actor": "user-1", "role": "edit"}
{"type": "op", "seq": 13, "actor": "user-1", "key": "layers/roads", "value": null}
{"type": "ack", "clientSeq": 4, "seq": 13}
{"type": "peers", "peers": [{"actor": "user-1", "name": "Ada", "role": "edit"}]}
{"type": "presence", "actor": "user-1", "cursor": [12.5, -3.25], "selection": [], "viewport": null}
{"type": "error", "reason": "edit role required"}
```

`peers` goes out on every join and leave. A refused message is an `error` and the
connection stays open, unless the credential itself is the problem, which is a
4xx before the handshake completes.

Apply ops in `seq` order. A client receives its own ops back alongside the `ack`,
which is what keeps two tabs of one account in step.

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
| Client messages per connection | 60 per second, ops and presence together |
| Peers per document | 32 |
| Document name | 200 bytes |
| Document state | 4 MiB, measured as the sum over stored keys of the key length plus the JSON length of its value |

Share link tokens are 128 random bits, url safe. Session tokens expire after 12
hours.

The database stores only the SHA-256 of a share link token, so a database read
hands over no working link. The raw token is returned once when the link is
minted and never again.

## Revoking a share link

Revoking stops link resolution and stops any new websocket connection using a
session token from that link. A connection already open on a revoked link keeps
working until it drops. Close the tab or restart agora to cut one off
immediately.

## Storage

Ops are appended to `ops` and folded into `documents.checkpoint` every 256 ops.
The fold and the prune run in one transaction, and the last 4096 ops per document
are kept so a reconnect can replay rather than resnapshot. A room is loaded from
the checkpoint plus that tail on the first join and dropped when the last
connection leaves.

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
