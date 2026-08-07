use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use sqlx::PgPool;
use tokio::sync::{broadcast, mpsc};
use uuid::Uuid;

use crate::AppState;
use crate::auth::{BEARER_SUBPROTOCOL, websocket_token};
use crate::documents::member_role;
use crate::error::ApiError;
use crate::limits::{
    DIRECT_CHANNEL_CAPACITY, MAX_INBOUND_FRAME_BYTES, MAX_PRESENCE_BYTES, RateLimiter,
};
use crate::links::live_link;
use crate::protocol::{ClientMessage, Peer, ServerMessage};
use crate::role::DocumentRole;
use crate::room::{JoinError, Room, oldest_retained_op, ops_between};

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

struct Identity {
    actor: String,
    name: String,
    role: DocumentRole,
}

/// Either a platform member of this document or a live share link visitor.
/// Everything else is refused before the handshake completes.
async fn authenticate(
    state: &AppState,
    document_id: Uuid,
    token: &str,
) -> Result<Identity, ApiError> {
    if let Some(caller) = state.auth.verify_platform(token) {
        let role = member_role(&state.pool, document_id, &caller.user_id)
            .await?
            .ok_or_else(|| ApiError::forbidden("not a member of this document"))?;
        return Ok(Identity {
            actor: caller.user_id,
            name: caller.name,
            role,
        });
    }

    if let Some(claims) = state.auth.verify_session(token) {
        if claims.doc != document_id {
            return Err(ApiError::forbidden("session token is for another document"));
        }
        // the row, not the claim, decides the role, so revoking a link stops
        // the next connection even while its token is still unexpired
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
    let opening = opening_messages(&state.pool, document_id, since, joined.seq, joined.state).await;
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
    ));

    tokio::select! {
        _ = &mut sending => {}
        _ = receive_loop(&state, &room, &identity, stream, direct_sender) => {}
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
/// or the ops it missed, when the retained tail still reaches back that far.
async fn opening_messages(
    pool: &PgPool,
    document_id: Uuid,
    since: Option<i64>,
    seq: i64,
    state: serde_json::Value,
) -> Vec<ServerMessage> {
    let snapshot = || {
        vec![ServerMessage::Snapshot {
            seq,
            state: state.clone(),
        }]
    };
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

async fn send_loop(
    mut sink: SplitSink<WebSocket, Message>,
    room: Arc<Room>,
    mut fanned: broadcast::Receiver<Arc<str>>,
    mut direct: mpsc::Receiver<Arc<str>>,
) {
    loop {
        let text = tokio::select! {
            addressed = direct.recv() => match addressed {
                Some(text) => text,
                None => break,
            },
            relayed = fanned.recv() => match relayed {
                Ok(text) => text,
                // this connection fell too far behind to be caught up op by
                // op, so it gets the current state instead
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    let (seq, state) = room.snapshot().await;
                    ServerMessage::Snapshot { seq, state }.encode()
                }
                Err(broadcast::error::RecvError::Closed) => break,
            },
        };
        if sink.send(Message::text(text.as_ref())).await.is_err() {
            break;
        }
    }
}

enum Flow {
    Continue,
    Close,
}

/// Tell the client why a message was refused and keep the connection. A client
/// that is not draining its own errors is closed instead of buffered.
fn refuse(direct: &mpsc::Sender<Arc<str>>, reason: &str) -> Flow {
    match direct.try_send(ServerMessage::error(reason).encode()) {
        Ok(()) => Flow::Continue,
        Err(_) => Flow::Close,
    }
}

async fn receive_loop(
    state: &AppState,
    room: &Arc<Room>,
    identity: &Identity,
    mut stream: SplitStream<WebSocket>,
    direct: mpsc::Sender<Arc<str>>,
) {
    let mut limiter = RateLimiter::new();
    while let Some(Ok(message)) = stream.next().await {
        let flow = match message {
            Message::Text(text) => {
                handle_text(state, room, identity, &direct, &mut limiter, text.as_str()).await
            }
            Message::Binary(_) => refuse(&direct, "binary frames are not accepted"),
            Message::Close(_) => Flow::Close,
            Message::Ping(_) | Message::Pong(_) => Flow::Continue,
        };
        if matches!(flow, Flow::Close) {
            break;
        }
    }
}

async fn handle_text(
    state: &AppState,
    room: &Arc<Room>,
    identity: &Identity,
    direct: &mpsc::Sender<Arc<str>>,
    limiter: &mut RateLimiter,
    text: &str,
) -> Flow {
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
                Ok(seq) => {
                    let ack = ServerMessage::Ack { client_seq, seq }.encode();
                    match direct.try_send(ack) {
                        Ok(()) => Flow::Continue,
                        Err(_) => Flow::Close,
                    }
                }
                Err(error) => refuse(direct, error.reason()),
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
            room.relay(&ServerMessage::Presence {
                actor: identity.actor.clone(),
                cursor,
                selection,
                viewport,
            });
            Flow::Continue
        }
    }
}
