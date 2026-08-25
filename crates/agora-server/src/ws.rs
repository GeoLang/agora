use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use sqlx::PgPool;
use time::OffsetDateTime;
use tokio::sync::{broadcast, mpsc};
use uuid::Uuid;

use crate::AppState;
use crate::assets::asset_states;
use crate::auth::{AGORA_WRITE_SCOPE, BEARER_SUBPROTOCOL, VerificationError, websocket_token};
use crate::documents::{effective_role, project_grant};
use crate::error::ApiError;
use crate::limits::{
    DIRECT_CHANNEL_CAPACITY, MAX_BATCH_OPS, MAX_INBOUND_FRAME_BYTES, MAX_PRESENCE_BYTES,
    RateLimiter,
};
use crate::links::live_link;
use crate::protocol::{ClientMessage, Peer, ServerMessage};
use crate::role::DocumentRole;
use crate::room::{JoinError, Room, RoomEvent, oldest_retained_op, ops_between};

/// Display name for anyone who arrived through a share link. They have no
/// platform identity, so there is no name to show beyond this.
pub const GUEST_NAME: &str = "guest";

/// No `Debug`: `token` is a bearer credential and must never reach a log line.
#[derive(Deserialize)]
pub struct WebsocketQuery {
    doc: Uuid,
    since: Option<u64>,
    token: Option<String>,
}

#[derive(Clone)]
struct Identity {
    actor: String,
    name: String,
    role: DocumentRole,
}

/// Either a platform caller with a role on this document or a live share link
/// visitor. Everything else is refused before the handshake completes.
///
/// The role is fixed here for the life of the connection, project half included,
/// which is what it already was for the members half.
async fn authenticate(
    state: &AppState,
    document_id: Uuid,
    token: &str,
) -> Result<Identity, ApiError> {
    match state.auth.verify_for_scope(token, AGORA_WRITE_SCOPE) {
        Ok(caller) => {
            let grant = project_grant(state, document_id, &caller).await?;
            let role = effective_role(&state.pool, document_id, &caller.user_id, grant)
                .await?
                .ok_or_else(|| ApiError::forbidden("not a member of this document"))?;
            return Ok(Identity {
                actor: caller.user_id,
                name: caller.name,
                role,
            });
        }
        Err(VerificationError::MissingScope) => {
            return Err(ApiError::forbidden("required tool scope missing"));
        }
        Err(VerificationError::Invalid) => {}
    }

    if let Some(claims) = state.auth.verify_session(token) {
        if claims.doc != document_id {
            return Err(ApiError::forbidden("session token is for another document"));
        }
        // the row, not the claim, decides the role, so revoking a link stops
        // the next connection even while its token is still unexpired
        //
        // no project resolution here on purpose: a link visitor has no platform
        // identity for ptolemy to have a role for, so the link is the whole grant
        let link = live_link(&state.pool, &claims.link)
            .await?
            .ok_or_else(|| ApiError::forbidden("share link is revoked"))?;
        return Ok(Identity {
            actor: claims.sub,
            name: GUEST_NAME.to_string(),
            role: link.role,
        });
    }

    Err(ApiError::unauthorized("invalid or expired token"))
}

pub async fn websocket(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebsocketQuery>,
    upgrade: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    let document_id = query.doc;
    let token = websocket_token(&headers, query.token.as_deref())
        .ok_or_else(|| ApiError::unauthorized("missing bearer token"))?;
    let identity = authenticate(&state, document_id, token).await?;
    let since = match query.since {
        Some(since) => {
            Some(i64::try_from(since).map_err(|_| ApiError::bad_request("since out of range"))?)
        }
        None => None,
    };

    Ok(upgrade
        // echoing the marker is what lets a browser accept the 101, and only the
        // marker is echoed, never the token beside it
        .protocols([BEARER_SUBPROTOCOL])
        .max_message_size(MAX_INBOUND_FRAME_BYTES)
        .on_upgrade(move |socket| async move {
            run(state, socket, document_id, since, identity).await;
        }))
}

async fn run(
    state: AppState,
    socket: WebSocket,
    document_id: Uuid,
    since: Option<i64>,
    identity: Identity,
) {
    let peer = Peer {
        actor: identity.actor.clone(),
        name: identity.name.clone(),
        role: identity.role,
    };
    let joined = match state.rooms.join(&state.pool, document_id, peer).await {
        Ok(joined) => joined,
        Err(error) => {
            close_with(socket, join_refusal(&error)).await;
            return;
        }
    };

    let (mut sink, stream) = socket.split();
    let opening = opening_messages(
        &state.pool,
        document_id,
        since,
        joined.seq,
        joined.state,
        &identity,
    )
    .await;
    for message in opening {
        if sink
            .send(Message::text(message.encode().as_ref()))
            .await
            .is_err()
        {
            state.rooms.leave(document_id, joined.connection_id).await;
            return;
        }
    }

    let (direct_sender, direct_receiver) = mpsc::channel(DIRECT_CHANNEL_CAPACITY);
    let room = Arc::clone(&joined.room);
    let mut sending = tokio::spawn(send_loop(
        sink,
        Arc::clone(&room),
        joined.receiver,
        direct_receiver,
        joined.connection_id,
        identity.clone(),
    ));

    tokio::select! {
        _ = &mut sending => {}
        _ = receive_loop(
            &state,
            &room,
            &identity,
            joined.connection_id,
            stream,
            direct_sender,
        ) => {}
    }
    sending.abort();
    state.rooms.leave(document_id, joined.connection_id).await;
}

fn join_refusal(error: &JoinError) -> &'static str {
    match error {
        JoinError::DocumentNotFound => "no such document",
        JoinError::RoomFull => "document has too many peers",
        JoinError::Database(_) => "database error",
    }
}

/// A room that is full is refused after the handshake, because a peer slot can
/// only be claimed once the upgrade is certain to have happened.
async fn close_with(mut socket: WebSocket, reason: &str) {
    let message = ServerMessage::error(reason).encode();
    let _ = socket.send(Message::text(message.as_ref())).await;
    let _ = socket.close().await;
}

/// What a client is sent before the live stream starts: either the whole state
/// or the ops it missed, when the retained tail still reaches back that far,
/// and then what every asset on the document is reporting.
///
/// The asset frame goes out on every join, a resume that missed nothing
/// included, because asset state is not carried by ops and so cannot be
/// replayed from the tail.
async fn opening_messages(
    pool: &PgPool,
    document_id: Uuid,
    since: Option<i64>,
    seq: i64,
    state: serde_json::Value,
    identity: &Identity,
) -> Vec<ServerMessage> {
    let mut opening = document_messages(pool, document_id, since, seq, state, identity).await;
    opening.push(assets_message(pool, document_id).await);
    opening
}

async fn document_messages(
    pool: &PgPool,
    document_id: Uuid,
    since: Option<i64>,
    seq: i64,
    state: serde_json::Value,
    identity: &Identity,
) -> Vec<ServerMessage> {
    let snapshot = || vec![snapshot_message(seq, state.clone(), identity)];
    let Some(since) = since else {
        return snapshot();
    };
    if since > seq {
        return snapshot();
    }
    if since == seq {
        return Vec::new();
    }
    match oldest_retained_op(pool, document_id).await {
        Ok(Some(oldest)) if oldest <= since + 1 => {
            match ops_between(pool, document_id, since, seq).await {
                Ok(replay) => replay,
                Err(_) => snapshot(),
            }
        }
        _ => snapshot(),
    }
}

/// A database failure here sends an empty asset list rather than dropping the
/// frame, so the join sequence a client waits on is always the same length.
/// The next reading or liveness frame corrects it.
async fn assets_message(pool: &PgPool, document_id: Uuid) -> ServerMessage {
    let assets = asset_states(pool, document_id, None, OffsetDateTime::now_utc())
        .await
        .unwrap_or_default();
    ServerMessage::Assets { assets }
}

fn snapshot_message(seq: i64, state: serde_json::Value, identity: &Identity) -> ServerMessage {
    ServerMessage::Snapshot {
        seq,
        state,
        actor: identity.actor.clone(),
        role: identity.role,
    }
}

async fn send_loop(
    mut sink: SplitSink<WebSocket, Message>,
    room: Arc<Room>,
    mut fanned: broadcast::Receiver<RoomEvent>,
    mut direct: mpsc::Receiver<Arc<str>>,
    connection_id: u64,
    identity: Identity,
) {
    loop {
        let text = tokio::select! {
            addressed = direct.recv() => match addressed {
                Some(text) => text,
                None => break,
            },
            relayed = fanned.recv() => match relayed {
                Ok(event) if event.skip_connection == Some(connection_id) => continue,
                Ok(event) => event.text,
                // this connection fell too far behind to be caught up op by
                // op, so it gets the current state instead
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    let (seq, state) = room.snapshot().await;
                    snapshot_message(seq, state, &identity).encode()
                }
                Err(broadcast::error::RecvError::Closed) => break,
            },
        };
        if sink.send(Message::text(text.as_ref())).await.is_err() {
            break;
        }
    }
}

/// Best effort delivery to one client. A burst of refusals larger than the
/// buffer loses messages rather than the connection, which is what keeps a rate
/// limited client connected.
fn deliver(direct: &mpsc::Sender<Arc<str>>, message: ServerMessage) {
    let _ = direct.try_send(message.encode());
}

fn refuse(direct: &mpsc::Sender<Arc<str>>, reason: &str) {
    deliver(direct, ServerMessage::error(reason));
}

async fn receive_loop(
    state: &AppState,
    room: &Arc<Room>,
    identity: &Identity,
    connection_id: u64,
    mut stream: SplitStream<WebSocket>,
    direct: mpsc::Sender<Arc<str>>,
) {
    let mut limiter = RateLimiter::new();
    while let Some(Ok(message)) = stream.next().await {
        match message {
            Message::Text(text) => {
                handle_text(
                    state,
                    room,
                    identity,
                    connection_id,
                    &direct,
                    &mut limiter,
                    text.as_str(),
                )
                .await;
            }
            Message::Binary(_) => refuse(&direct, "binary frames are not accepted"),
            Message::Close(_) => break,
            Message::Ping(_) | Message::Pong(_) => {}
        }
    }
}

async fn handle_text(
    state: &AppState,
    room: &Arc<Room>,
    identity: &Identity,
    connection_id: u64,
    direct: &mpsc::Sender<Arc<str>>,
    limiter: &mut RateLimiter,
    text: &str,
) {
    if !limiter.allow() {
        return refuse(direct, "rate limit exceeded");
    }
    let Ok(message) = serde_json::from_str::<ClientMessage>(text) else {
        return refuse(direct, "malformed message");
    };

    match message {
        ClientMessage::Op {
            client_seq,
            key,
            value,
        } => {
            if !identity.role.can_edit() {
                return refuse(direct, "edit role required");
            }
            match room
                .apply_op(&state.pool, &identity.actor, client_seq, &key, value.0)
                .await
            {
                Ok(seq) => deliver(direct, ServerMessage::Ack { client_seq, seq }),
                Err(error) => refuse(direct, error.reason()),
            }
        }
        ClientMessage::Batch { client_seq, ops } => {
            if !identity.role.can_edit() {
                return refuse(direct, "edit role required");
            }
            if ops.is_empty() {
                return refuse(direct, "batch carries no ops");
            }
            if ops.len() > MAX_BATCH_OPS {
                return refuse(direct, "batch too large");
            }
            // the frame itself was charged above, so the rest of its ops are
            // charged here and grouping ops buys none of them
            if !limiter.allow_many(ops.len() - 1) {
                return refuse(direct, "rate limit exceeded");
            }
            match room
                .apply_batch(&state.pool, &identity.actor, client_seq, &ops)
                .await
            {
                Ok(seq) => deliver(direct, ServerMessage::Ack { client_seq, seq }),
                Err(error) => refuse(direct, &error.reason()),
            }
        }
        ClientMessage::Presence {
            cursor,
            selection,
            viewport,
        } => {
            if text.len() > MAX_PRESENCE_BYTES {
                return refuse(direct, "presence too large");
            }
            room.relay_excluding(
                connection_id,
                &ServerMessage::Presence {
                    actor: identity.actor.clone(),
                    cursor,
                    selection,
                    viewport,
                },
            );
        }
    }
}
