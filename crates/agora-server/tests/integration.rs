use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agora_server::auth::{AuthConfig, capability_token_hash};
use agora_server::limits::{
    ATTACHMENT_GRACE_DAYS, MAX_ATTACHMENT_BYTES, MAX_BATCH_OPS, MAX_CLIENT_MESSAGES_PER_SECOND,
    MAX_DOCUMENT_NAME_BYTES, MAX_DOCUMENT_STATE_BYTES, MAX_FEED_READINGS_PER_FRAME,
    MAX_INBOUND_FRAME_BYTES, MAX_KEY_BYTES, MAX_OP_VALUE_BYTES, MAX_PEERS_PER_DOCUMENT,
    MAX_PRESENCE_BYTES, MAX_READINGS_PER_WATCH, MAX_REGION_POSITIONS, MAX_USER_ID_BYTES,
    MAX_WATCH_READINGS_PAGE, MIN_WATCH_INTERVAL_SECONDS, READINGS_RETENTION_DAYS, WEBHOOK_ATTEMPTS,
};
use agora_server::projects::ProjectAccess;
use agora_server::protocol::{BatchOp, OpValue, Peer};
use agora_server::role::DocumentRole;
use agora_server::state::META_NAME_KEY;
use agora_server::watches::{Geoplumb, run_due};
use agora_server::webhooks::{PrivateHosts, Webhooks};
use agora_server::{AppState, migrate, router};
use futures_util::{SinkExt, StreamExt};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};
use sqlx::{PgPool, Row};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::handshake::client::Response;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::{Error as WebsocketError, Message};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};
use uuid::Uuid;

const TEST_SECRET: &str = "agora-integration-secret-0123456789abcdef";
const DEFAULT_DATABASE_URL: &str = "postgres://postgres:postgres@localhost/agora_test";
const MESSAGE_TIMEOUT: Duration = Duration::from_secs(15);
const QUIET_TIMEOUT: Duration = Duration::from_millis(300);

/// Small on purpose. Every test owns its own runtime, so a pool cannot be
/// shared, and the whole suite has to fit inside one server's connection limit.
const TEST_POOL_CONNECTIONS: u32 = 3;

/// Tests share one database and never drop tables, so they stay correct under
/// the default parallel test runner: every document, member and link is keyed by
/// a fresh uuid or a per test user id.
///
/// Migrating on every test is safe because sqlx takes an advisory lock, and it
/// keeps the pool on the runtime that created it.
async fn test_pool() -> PgPool {
    let url = std::env::var("DATABASE_URL").unwrap_or_else(|_| DEFAULT_DATABASE_URL.to_string());
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(TEST_POOL_CONNECTIONS)
        .connect(&url)
        .await
        .expect("these tests need a reachable postgres, see the README");
    migrate(&pool).await.expect("migrations apply");
    pool
}

struct TestApp {
    http_base: String,
    websocket_base: String,
    state: AppState,
    client: reqwest::Client,
}

async fn spawn_app() -> TestApp {
    spawn_app_on(test_pool().await).await
}

/// A second app over the same database, which is what a restart looks like to
/// the room registry: no memory, only the checkpoint and the op tail.
async fn restart(app: &TestApp) -> TestApp {
    spawn_app_on(app.state.pool.clone()).await
}

async fn spawn_app_on(pool: PgPool) -> TestApp {
    let auth = AuthConfig::new(TEST_SECRET).expect("test secret is long enough");
    serve(AppState::new(pool, auth)).await
}

async fn serve(state: AppState) -> TestApp {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("local address");
    let app = router(state.clone());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    TestApp {
        http_base: format!("http://{address}"),
        websocket_base: format!("ws://{address}"),
        state,
        client: reqwest::Client::new(),
    }
}

fn platform_token(subject: &str) -> String {
    let expires_at = time::OffsetDateTime::now_utc().unix_timestamp() + 3600;
    let claims = json!({"sub": subject, "exp": expires_at, "role": "editor"});
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(TEST_SECRET.as_bytes()),
    )
    .expect("sign a test token")
}

/// A user id nothing else in the suite shares, so listing is isolated.
fn fresh_user() -> String {
    format!("user-{}", Uuid::new_v4())
}

async fn create_document(app: &TestApp, token: &str, name: &str) -> Uuid {
    let response = app
        .client
        .post(format!("{}/documents", app.http_base))
        .bearer_auth(token)
        .json(&json!({"name": name}))
        .send()
        .await
        .expect("create document");
    assert_eq!(response.status(), 201);
    let body: Value = response.json().await.expect("json body");
    body["id"]
        .as_str()
        .and_then(|id| Uuid::parse_str(id).ok())
        .expect("a document id")
}

async fn set_member(
    app: &TestApp,
    token: &str,
    document_id: Uuid,
    user_id: &str,
    role: &str,
) -> reqwest::Response {
    app.client
        .put(format!(
            "{}/documents/{document_id}/members/{user_id}",
            app.http_base
        ))
        .bearer_auth(token)
        .json(&json!({"role": role}))
        .send()
        .await
        .expect("set member")
}

async fn remove_member(
    app: &TestApp,
    token: &str,
    document_id: Uuid,
    user_id: &str,
) -> reqwest::Response {
    app.client
        .delete(format!(
            "{}/documents/{document_id}/members/{user_id}",
            app.http_base
        ))
        .bearer_auth(token)
        .send()
        .await
        .expect("remove member")
}

async fn member_roles(app: &TestApp, token: &str, document_id: Uuid) -> Vec<(String, String)> {
    let detail: Value = app
        .client
        .get(format!("{}/documents/{document_id}", app.http_base))
        .bearer_auth(token)
        .send()
        .await
        .expect("detail")
        .json()
        .await
        .expect("json");
    detail["members"]
        .as_array()
        .expect("members")
        .iter()
        .map(|member| {
            (
                member["userId"].as_str().expect("a user id").to_string(),
                member["role"].as_str().expect("a role").to_string(),
            )
        })
        .collect()
}

async fn mint_link(app: &TestApp, token: &str, document_id: Uuid, role: &str) -> String {
    let response = app
        .client
        .post(format!("{}/documents/{document_id}/links", app.http_base))
        .bearer_auth(token)
        .json(&json!({"role": role}))
        .send()
        .await
        .expect("mint link");
    assert_eq!(response.status(), 201);
    let body: Value = response.json().await.expect("json body");
    body["token"].as_str().expect("a link token").to_string()
}

async fn resolve_link(app: &TestApp, link_token: &str) -> Value {
    let response = app
        .client
        .get(format!("{}/links/{link_token}", app.http_base))
        .send()
        .await
        .expect("resolve link");
    assert_eq!(response.status(), 200);
    response.json().await.expect("json body")
}

/// Mint a link and resolve it, which is the whole path an anonymous visitor
/// takes to get a credential.
async fn guest_session(app: &TestApp, token: &str, document_id: Uuid, role: &str) -> String {
    let link = mint_link(app, token, document_id, role).await;
    resolve_link(app, &link).await["sessionToken"]
        .as_str()
        .expect("a session token")
        .to_string()
}

fn websocket_url(app: &TestApp, document_id: Uuid, since: Option<i64>) -> String {
    let mut url = format!("{}/ws?doc={document_id}", app.websocket_base);
    if let Some(since) = since {
        url.push_str(&format!("&since={since}"));
    }
    url
}

struct WebsocketClient {
    stream: WebSocketStream<MaybeTlsStream<TcpStream>>,
}

/// The handshake a browser makes: the token rides in the subprotocol offer, not
/// the url and not a header.
async fn connect_with_subprotocol(
    app: &TestApp,
    document_id: Uuid,
    token: &str,
    since: Option<i64>,
) -> Result<(WebsocketClient, Response), WebsocketError> {
    let mut request = websocket_url(app, document_id, since).into_client_request()?;
    let offer = HeaderValue::from_str(&format!("bearer, {token}")).expect("header value");
    request
        .headers_mut()
        .insert("sec-websocket-protocol", offer);
    let (stream, response) = connect_async(request).await?;
    Ok((WebsocketClient { stream }, response))
}

async fn connect_with_header(
    app: &TestApp,
    document_id: Uuid,
    token: &str,
) -> Result<(WebsocketClient, Response), WebsocketError> {
    let mut request = websocket_url(app, document_id, None).into_client_request()?;
    let value = HeaderValue::from_str(&format!("Bearer {token}")).expect("header value");
    request.headers_mut().insert("authorization", value);
    let (stream, response) = connect_async(request).await?;
    Ok((WebsocketClient { stream }, response))
}

async fn connect_with_query_param(
    app: &TestApp,
    document_id: Uuid,
    token: &str,
) -> Result<(WebsocketClient, Response), WebsocketError> {
    let url = format!("{}&token={token}", websocket_url(app, document_id, None));
    let (stream, response) = connect_async(url).await?;
    Ok((WebsocketClient { stream }, response))
}

async fn open(
    app: &TestApp,
    document_id: Uuid,
    token: &str,
    since: Option<i64>,
) -> WebsocketClient {
    connect_with_subprotocol(app, document_id, token, since)
        .await
        .expect("handshake")
        .0
}

fn handshake_status(outcome: Result<(WebsocketClient, Response), WebsocketError>) -> Option<u16> {
    match outcome {
        Ok(_) => None,
        Err(WebsocketError::Http(response)) => Some(response.status().as_u16()),
        Err(other) => panic!("expected an http refusal, got {other:?}"),
    }
}

impl WebsocketClient {
    async fn next_message(&mut self) -> Value {
        let frame = tokio::time::timeout(MESSAGE_TIMEOUT, self.stream.next())
            .await
            .expect("timed out waiting for a server message")
            .expect("the stream ended early")
            .expect("websocket error");
        match frame {
            Message::Text(text) => serde_json::from_str(&text).expect("server sends json"),
            other => panic!("expected a text frame, got {other:?}"),
        }
    }

    /// `None` once the server has gone quiet, which is how a test asserts a
    /// message was not sent.
    async fn try_next_message(&mut self) -> Option<Value> {
        match tokio::time::timeout(QUIET_TIMEOUT, self.stream.next()).await {
            Ok(Some(Ok(Message::Text(text)))) => {
                Some(serde_json::from_str(&text).expect("server sends json"))
            }
            Ok(other) => panic!("expected a text frame or quiet, got {other:?}"),
            Err(_) => None,
        }
    }

    /// Whether the server hung up, which is how a connection level refusal ends.
    async fn is_closed(&mut self) -> bool {
        match tokio::time::timeout(QUIET_TIMEOUT, self.stream.next()).await {
            Ok(None) | Ok(Some(Err(_))) | Ok(Some(Ok(Message::Close(_)))) => true,
            Ok(other) => panic!("expected a close, got {other:?}"),
            Err(_) => false,
        }
    }

    async fn expect_message(&mut self, kind: &str) -> Value {
        let message = self.next_message().await;
        assert_eq!(message["type"], kind, "unexpected message {message}");
        message
    }

    async fn send_op(&mut self, client_seq: i64, key: &str, value: Value) {
        self.send(json!({"type": "op", "clientSeq": client_seq, "key": key, "value": value}))
            .await;
    }

    async fn send_batch(&mut self, client_seq: i64, ops: Vec<Value>) {
        self.send(json!({"type": "batch", "clientSeq": client_seq, "ops": ops}))
            .await;
    }

    async fn send(&mut self, message: Value) {
        self.send_text(&message.to_string()).await;
    }

    /// Raw text, for a frame `serde_json::Value` cannot hold, such as one
    /// carrying a number outside f64.
    async fn send_text(&mut self, text: &str) {
        self.stream
            .send(Message::text(text.to_string()))
            .await
            .expect("send");
    }

    async fn close(mut self) {
        let _ = self.stream.close(None).await;
    }
}

/// Send an op and settle it: read until both the ack and the sender's own echo
/// have arrived, so whatever a test reads next is not one of them. The two race
/// each other, which is why neither can be assumed to come first.
async fn send_and_settle(
    client: &mut WebsocketClient,
    client_seq: i64,
    key: &str,
    value: Value,
) -> i64 {
    client.send_op(client_seq, key, value).await;
    let mut acked = None;
    let mut echoed = false;
    for _ in 0..8 {
        let message = client.next_message().await;
        match message["type"].as_str() {
            Some("ack") => {
                assert_eq!(message["clientSeq"], client_seq);
                acked = message["seq"].as_i64();
            }
            Some("op") => echoed = true,
            _ => panic!("unexpected message {message}"),
        }
        if let (Some(seq), true) = (acked, echoed) {
            return seq;
        }
    }
    panic!("op {client_seq} was never settled")
}

fn batch_op(key: &str, value: Value) -> Value {
    json!({"key": key, "value": value})
}

/// Send a batch and settle it: read until both the ack and the sender's own
/// echo have arrived, since the two race each other. A batch of one op echoes
/// as an `op` frame, a bigger one as a `batch` frame. Returns the seq of the
/// last op.
async fn send_batch_and_settle(
    client: &mut WebsocketClient,
    client_seq: i64,
    ops: Vec<Value>,
) -> i64 {
    client.send_batch(client_seq, ops).await;
    let mut acked = None;
    let mut echoed = false;
    for _ in 0..8 {
        let message = client.next_message().await;
        match message["type"].as_str() {
            Some("ack") => {
                assert_eq!(message["clientSeq"], client_seq);
                acked = message["seq"].as_i64();
            }
            Some("op") | Some("batch") => echoed = true,
            Some("peers") => {}
            _ => panic!("unexpected message {message}"),
        }
        if let (Some(seq), true) = (acked, echoed) {
            return seq;
        }
    }
    panic!("batch {client_seq} was never settled")
}

/// Send a batch that should be refused and return the reason given.
async fn send_batch_and_refuse(
    client: &mut WebsocketClient,
    client_seq: i64,
    ops: Vec<Value>,
) -> String {
    client.send_batch(client_seq, ops).await;
    for _ in 0..8 {
        let message = client.next_message().await;
        match message["type"].as_str() {
            Some("error") => return message["reason"].as_str().expect("a reason").to_string(),
            Some("peers") => continue,
            _ => panic!("unexpected message {message}"),
        }
    }
    panic!("batch {client_seq} was never refused")
}

/// The seq and state a client that joins now would be given.
async fn stored_document(app: &TestApp, document_id: Uuid, token: &str) -> Value {
    let mut fresh = open(app, document_id, token, None).await;
    fresh.expect_message("snapshot").await
}

/// Send an op that should be refused and return the reason given.
async fn send_and_refuse(
    client: &mut WebsocketClient,
    client_seq: i64,
    key: &str,
    value: Value,
) -> String {
    client.send_op(client_seq, key, value).await;
    let refusal = client.expect_message("error").await;
    refusal["reason"].as_str().expect("a reason").to_string()
}

/// Read until the op with this seq arrives, skipping a client's own ack.
async fn expect_op_with_seq(client: &mut WebsocketClient, seq: i64) -> Value {
    for _ in 0..8 {
        let message = client.next_message().await;
        match message["type"].as_str() {
            Some("op") if message["seq"] == seq => return message,
            Some("op") | Some("ack") => continue,
            _ => panic!("unexpected message {message}"),
        }
    }
    panic!("op {seq} never arrived")
}

/// The whole join sequence: a snapshot, the assets, the watches, then the peer
/// list.
async fn expect_join(client: &mut WebsocketClient) -> (Value, Value) {
    let snapshot = client.expect_message("snapshot").await;
    client.expect_message("assets").await;
    client.expect_message("watches").await;
    let peers = client.expect_message("peers").await;
    (snapshot, peers)
}

/// Ops applied straight through the room, which is the same path the websocket
/// takes but without a connection rate limit in the way.
async fn apply_ops_directly(app: &TestApp, document_id: Uuid, actor: &str, count: usize) -> i64 {
    apply_ops_directly_from(app, document_id, actor, 0, count).await
}

async fn apply_ops_directly_from(
    app: &TestApp,
    document_id: Uuid,
    actor: &str,
    start: usize,
    count: usize,
) -> i64 {
    let peer = Peer {
        actor: actor.to_string(),
        name: actor.to_string(),
        role: DocumentRole::Edit,
    };
    let joined = app
        .state
        .rooms
        .join(&app.state.pool, document_id, peer)
        .await
        .expect("join the room");
    let mut last_seq = 0;
    for index in start..start + count {
        last_seq = joined
            .room
            .apply_op(
                &app.state.pool,
                actor,
                index as i64,
                &format!("layers/l{index}"),
                Some(json!({"order": format!("a{index:04}")})),
            )
            .await
            .expect("apply an op");
    }
    app.state
        .rooms
        .leave(document_id, joined.connection_id)
        .await;
    last_seq
}

#[tokio::test]
async fn a_join_receives_a_snapshot_the_assets_the_watches_then_the_peer_list() {
    let app = spawn_app().await;
    let owner = fresh_user();
    let token = platform_token(&owner);
    let document_id = create_document(&app, &token, "city plan").await;

    let mut client = open(&app, document_id, &token, None).await;
    let snapshot = client.expect_message("snapshot").await;
    assert_eq!(snapshot["seq"], 0);
    assert_eq!(snapshot["state"]["meta"]["name"], "city plan");
    for namespace in ["layers", "annotations", "bookmarks", "comments", "assets"] {
        assert!(snapshot["state"][namespace].is_object(), "{namespace}");
    }
    // a client learns who it is and what it may do from the snapshot itself
    assert_eq!(snapshot["actor"], owner.as_str());
    assert_eq!(snapshot["role"], "edit");

    let assets = client.expect_message("assets").await;
    assert_eq!(
        assets["assets"].as_array().expect("an asset array").len(),
        0,
        "a document with no feeds reported assets"
    );
    let watches = client.expect_message("watches").await;
    assert_eq!(
        watches["watches"].as_array().expect("a watch array").len(),
        0,
        "a document with no watches reported one"
    );

    let peers = client.expect_message("peers").await;
    let peers = peers["peers"].as_array().expect("a peer array");
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0]["actor"], owner.as_str());
    assert_eq!(peers[0]["role"], "edit");
}

#[tokio::test]
async fn a_join_and_a_leave_both_republish_the_peer_list() {
    let app = spawn_app().await;
    let owner = fresh_user();
    let token = platform_token(&owner);
    let document_id = create_document(&app, &token, "peer list").await;
    let guest_token = guest_session(&app, &token, document_id, "view").await;

    let mut owner_client = open(&app, document_id, &token, None).await;
    expect_join(&mut owner_client).await;

    let guest_client = open(&app, document_id, &guest_token, None).await;
    let joined = owner_client.expect_message("peers").await;
    assert_eq!(joined["peers"].as_array().expect("peers").len(), 2);

    guest_client.close().await;
    let left = owner_client.expect_message("peers").await;
    let left = left["peers"].as_array().expect("peers");
    assert_eq!(left.len(), 1);
    assert_eq!(left[0]["actor"], owner.as_str());
}

#[tokio::test]
async fn an_op_broadcasts_to_the_other_client_and_acks_the_sender() {
    let app = spawn_app().await;
    let owner = fresh_user();
    let token = platform_token(&owner);
    let document_id = create_document(&app, &token, "broadcast").await;
    let guest_token = guest_session(&app, &token, document_id, "edit").await;

    let mut owner_client = open(&app, document_id, &token, None).await;
    expect_join(&mut owner_client).await;
    let mut guest_client = open(&app, document_id, &guest_token, None).await;
    expect_join(&mut guest_client).await;
    owner_client.expect_message("peers").await;

    owner_client
        .send_op(
            7,
            "layers/roads",
            json!({"order": "a0", "url": "roads.pmtiles"}),
        )
        .await;

    let relayed = guest_client.expect_message("op").await;
    assert_eq!(relayed["seq"], 1);
    assert_eq!(relayed["actor"], owner.as_str());
    assert_eq!(relayed["key"], "layers/roads");
    assert_eq!(relayed["value"]["url"], "roads.pmtiles");

    let mut acked = false;
    for _ in 0..2 {
        let message = owner_client.next_message().await;
        if message["type"] == "ack" {
            assert_eq!(message["clientSeq"], 7);
            assert_eq!(message["seq"], 1);
            acked = true;
        }
    }
    assert!(acked, "the sender was never acked");
}

#[tokio::test]
async fn a_delete_removes_the_key_for_everyone() {
    let app = spawn_app().await;
    let token = platform_token(&fresh_user());
    let document_id = create_document(&app, &token, "deletes").await;

    let mut client = open(&app, document_id, &token, None).await;
    expect_join(&mut client).await;
    assert_eq!(
        send_and_settle(&mut client, 1, "layers/gone", json!({"order": "a0"})).await,
        1
    );
    assert_eq!(
        send_and_settle(&mut client, 2, "layers/gone", Value::Null).await,
        2
    );

    let mut fresh = open(&app, document_id, &token, None).await;
    let snapshot = fresh.expect_message("snapshot").await;
    assert_eq!(snapshot["seq"], 2);
    assert!(
        snapshot["state"]["layers"].get("gone").is_none(),
        "a null value did not delete the key"
    );
}

#[tokio::test]
async fn two_ops_on_one_key_settle_on_the_server_order_for_both_clients() {
    let app = spawn_app().await;
    let owner = fresh_user();
    let token = platform_token(&owner);
    let document_id = create_document(&app, &token, "one key").await;
    let guest_token = guest_session(&app, &token, document_id, "edit").await;

    let mut owner_client = open(&app, document_id, &token, None).await;
    expect_join(&mut owner_client).await;
    let mut guest_client = open(&app, document_id, &guest_token, None).await;
    expect_join(&mut guest_client).await;
    owner_client.expect_message("peers").await;

    // the first op is settled before the second is sent, so the test asserts an
    // order the server chose rather than racing it
    let first = send_and_settle(
        &mut owner_client,
        1,
        "layers/contested",
        json!({"order": "owner"}),
    )
    .await;
    assert_eq!(first, 1);
    guest_client.expect_message("op").await;

    let second = send_and_settle(
        &mut guest_client,
        1,
        "layers/contested",
        json!({"order": "guest"}),
    )
    .await;
    assert_eq!(second, 2);

    let seen_by_owner = expect_op_with_seq(&mut owner_client, 2).await;
    assert_eq!(seen_by_owner["value"]["order"], "guest");

    // both sides reconnect onto the later write, so server order is what the
    // stored document settled on
    for connect_token in [token.as_str(), guest_token.as_str()] {
        let mut fresh = open(&app, document_id, connect_token, None).await;
        let snapshot = fresh.expect_message("snapshot").await;
        assert_eq!(snapshot["seq"], 2);
        assert_eq!(
            snapshot["state"]["layers"]["contested"]["order"], "guest",
            "the later write did not win"
        );
    }
}

#[tokio::test]
async fn a_batch_applies_every_op_and_reaches_a_peer_as_one_frame() {
    let app = spawn_app().await;
    let owner = fresh_user();
    let token = platform_token(&owner);
    let document_id = create_document(&app, &token, "batching").await;
    let guest_token = guest_session(&app, &token, document_id, "edit").await;

    let mut owner_client = open(&app, document_id, &token, None).await;
    expect_join(&mut owner_client).await;
    let mut guest_client = open(&app, document_id, &guest_token, None).await;
    expect_join(&mut guest_client).await;
    owner_client.expect_message("peers").await;

    assert_eq!(
        send_batch_and_settle(
            &mut owner_client,
            4,
            vec![
                batch_op("layers/a", json!({"order": "a0"})),
                batch_op("layers/b", json!({"order": "a1"})),
                batch_op("layers/c", json!({"order": "a2"})),
            ],
        )
        .await,
        3
    );

    let relayed = guest_client.expect_message("batch").await;
    assert_eq!(relayed["actor"], owner.as_str());
    assert_eq!(
        relayed["ops"],
        json!([
            {"seq": 1, "key": "layers/a", "value": {"order": "a0"}},
            {"seq": 2, "key": "layers/b", "value": {"order": "a1"}},
            {"seq": 3, "key": "layers/c", "value": {"order": "a2"}},
        ]),
        "the ops did not arrive together in one frame"
    );

    let snapshot = stored_document(&app, document_id, &token).await;
    assert_eq!(snapshot["seq"], 3);
    for (id, order) in [("a", "a0"), ("b", "a1"), ("c", "a2")] {
        assert_eq!(snapshot["state"]["layers"][id]["order"], order);
    }
}

#[tokio::test]
async fn a_batch_with_one_bad_op_applies_none_of_them() {
    let app = spawn_app().await;
    let token = platform_token(&fresh_user());
    let document_id = create_document(&app, &token, "atomic batch").await;

    let mut client = open(&app, document_id, &token, None).await;
    expect_join(&mut client).await;

    let good = batch_op("layers/kept", json!({"order": "a0"}));
    for (ops, reason) in [
        (
            vec![good.clone(), batch_op("secrets/root", json!(true))],
            "op 1: unknown key namespace",
        ),
        (
            vec![
                batch_op("layers/big", json!("x".repeat(MAX_OP_VALUE_BYTES))),
                good.clone(),
            ],
            "op 0: op value too large",
        ),
        (
            vec![good.clone(), batch_op("meta/name", json!(7))],
            "op 1: invalid document name",
        ),
    ] {
        assert_eq!(send_batch_and_refuse(&mut client, 1, ops).await, reason);
    }

    let snapshot = stored_document(&app, document_id, &token).await;
    assert_eq!(snapshot["seq"], 0, "a refused batch still spent a seq");
    assert!(
        snapshot["state"]["layers"].get("kept").is_none(),
        "a refused batch wrote one of its ops"
    );

    // the same ops without the bad one are fine, so nothing but the bad entry
    // was the problem
    assert_eq!(send_batch_and_settle(&mut client, 2, vec![good]).await, 1);
}

#[tokio::test]
async fn one_key_written_twice_in_a_batch_settles_on_the_last_write() {
    let app = spawn_app().await;
    let token = platform_token(&fresh_user());
    let document_id = create_document(&app, &token, "batch duplicates").await;

    let mut client = open(&app, document_id, &token, None).await;
    expect_join(&mut client).await;

    assert_eq!(
        send_batch_and_settle(
            &mut client,
            1,
            vec![
                batch_op("layers/a", json!({"order": "first"})),
                batch_op("layers/b", json!({"order": "kept"})),
                batch_op("layers/a", json!({"order": "last"})),
                batch_op("layers/b", Value::Null),
            ],
        )
        .await,
        4
    );

    let snapshot = stored_document(&app, document_id, &token).await;
    assert_eq!(snapshot["seq"], 4);
    assert_eq!(snapshot["state"]["layers"]["a"]["order"], "last");
    assert!(
        snapshot["state"]["layers"].get("b").is_none(),
        "a delete later in the batch did not win"
    );
}

#[tokio::test]
async fn a_view_role_op_is_refused_and_the_connection_stays_open() {
    let app = spawn_app().await;
    let owner = fresh_user();
    let token = platform_token(&owner);
    let document_id = create_document(&app, &token, "read only").await;

    let reader = fresh_user();
    sqlx::query("insert into members (doc_id, user_id, role) values ($1, $2, 'view')")
        .bind(document_id)
        .bind(&reader)
        .execute(&app.state.pool)
        .await
        .expect("add a view member");
    let reader_token = platform_token(&reader);

    let mut reader_client = open(&app, document_id, &reader_token, None).await;
    let snapshot = reader_client.expect_message("snapshot").await;
    assert_eq!(snapshot["role"], "view", "a reader was not told its role");
    reader_client.expect_message("assets").await;
    reader_client.expect_message("watches").await;
    reader_client.expect_message("peers").await;

    let reason = send_and_refuse(
        &mut reader_client,
        1,
        "layers/sneaky",
        json!({"order": "a0"}),
    )
    .await;
    assert_eq!(reason, "edit role required");

    // still connected, and still receiving what an editor does
    let mut owner_client = open(&app, document_id, &token, None).await;
    expect_join(&mut owner_client).await;
    reader_client.expect_message("peers").await;
    owner_client
        .send_op(1, "layers/allowed", json!({"order": "a0"}))
        .await;
    let relayed = reader_client.expect_message("op").await;
    assert_eq!(relayed["key"], "layers/allowed");

    let mut fresh = open(&app, document_id, &token, None).await;
    let snapshot = fresh.expect_message("snapshot").await;
    assert!(
        snapshot["state"]["layers"].get("sneaky").is_none(),
        "a view role op reached the document"
    );
}

#[tokio::test]
async fn a_share_link_admits_an_anonymous_reader_until_it_is_revoked() {
    let app = spawn_app().await;
    let owner = fresh_user();
    let token = platform_token(&owner);
    let document_id = create_document(&app, &token, "shared").await;

    let link = mint_link(&app, &token, document_id, "view").await;
    assert_eq!(link.len(), 22, "a share token carries 128 bits");
    let resolved = resolve_link(&app, &link).await;
    assert_eq!(resolved["doc"], document_id.to_string());
    assert_eq!(resolved["role"], "view");
    let guest_token = resolved["sessionToken"]
        .as_str()
        .expect("a session token")
        .to_string();

    let mut guest_client = open(&app, document_id, &guest_token, None).await;
    let (snapshot, peers) = expect_join(&mut guest_client).await;
    assert_eq!(snapshot["state"]["meta"]["name"], "shared");
    assert_eq!(snapshot["role"], "view");
    let own_actor = snapshot["actor"].as_str().expect("an actor").to_string();
    assert!(
        own_actor.starts_with("guest-"),
        "an anonymous actor id was not issued"
    );
    let peers = peers["peers"].as_array().expect("peers");
    assert_eq!(peers[0]["role"], "view");
    assert_eq!(peers[0]["name"], "guest");
    assert_eq!(peers[0]["actor"], own_actor.as_str());

    let reason = send_and_refuse(&mut guest_client, 1, "layers/nope", json!({"order": "a0"})).await;
    assert_eq!(reason, "edit role required");

    let revoked = app
        .client
        .delete(format!("{}/links/{link}", app.http_base))
        .bearer_auth(&token)
        .send()
        .await
        .expect("revoke");
    assert_eq!(revoked.status(), 204);

    let gone = app
        .client
        .get(format!("{}/links/{link}", app.http_base))
        .send()
        .await
        .expect("resolve a revoked link");
    assert_eq!(gone.status(), 404);

    let refused = connect_with_subprotocol(&app, document_id, &guest_token, None).await;
    assert_eq!(
        handshake_status(refused),
        Some(403),
        "a revoked link still opened a connection"
    );
}

#[tokio::test]
async fn a_reconnect_with_since_replays_only_the_missed_ops() {
    let app = spawn_app().await;
    let token = platform_token(&fresh_user());
    let document_id = create_document(&app, &token, "replay").await;

    let mut client = open(&app, document_id, &token, None).await;
    expect_join(&mut client).await;
    for index in 1..=3 {
        let seq = send_and_settle(
            &mut client,
            index,
            &format!("layers/l{index}"),
            json!({"order": "a0"}),
        )
        .await;
        assert_eq!(seq, index);
    }
    client.close().await;

    let mut reconnected = open(&app, document_id, &token, Some(1)).await;
    let first = reconnected.expect_message("op").await;
    assert_eq!(first["seq"], 2);
    assert_eq!(first["key"], "layers/l2");
    let second = reconnected.expect_message("op").await;
    assert_eq!(second["seq"], 3);
    reconnected.expect_message("assets").await;
    reconnected.expect_message("watches").await;
    reconnected.expect_message("peers").await;
    assert!(
        reconnected.try_next_message().await.is_none(),
        "a replay sent more than the gap"
    );

    let mut caught_up = open(&app, document_id, &token, Some(3)).await;
    caught_up.expect_message("assets").await;
    caught_up.expect_message("watches").await;
    let peers = caught_up.expect_message("peers").await;
    assert!(peers["peers"].is_array(), "a caught up client got a replay");
}

#[tokio::test]
async fn a_reconnect_replays_a_batch_as_the_one_frame_it_was_applied_in() {
    let app = spawn_app().await;
    let owner = fresh_user();
    let token = platform_token(&owner);
    let document_id = create_document(&app, &token, "batch replay").await;

    let mut client = open(&app, document_id, &token, None).await;
    expect_join(&mut client).await;
    assert_eq!(
        send_and_settle(&mut client, 1, "layers/first", json!({"order": "a0"})).await,
        1
    );
    assert_eq!(
        send_batch_and_settle(
            &mut client,
            2,
            vec![
                batch_op("layers/a", json!({"order": "a1"})),
                batch_op("layers/b", json!({"order": "a2"})),
            ],
        )
        .await,
        3
    );
    assert_eq!(
        send_and_settle(&mut client, 3, "layers/last", json!({"order": "a3"})).await,
        4
    );
    client.close().await;

    let mut reconnected = open(&app, document_id, &token, Some(0)).await;
    let first = reconnected.expect_message("op").await;
    assert_eq!(first["seq"], 1);
    assert_eq!(first["key"], "layers/first");

    let replayed = reconnected.expect_message("batch").await;
    assert_eq!(replayed["actor"], owner.as_str());
    assert_eq!(
        replayed["ops"],
        json!([
            {"seq": 2, "key": "layers/a", "value": {"order": "a1"}},
            {"seq": 3, "key": "layers/b", "value": {"order": "a2"}},
        ]),
        "the batch was replayed torn"
    );

    let last = reconnected.expect_message("op").await;
    assert_eq!(last["seq"], 4);
    assert_eq!(last["key"], "layers/last");
    reconnected.expect_message("assets").await;
    reconnected.expect_message("watches").await;
    reconnected.expect_message("peers").await;
    assert!(
        reconnected.try_next_message().await.is_none(),
        "a replay sent more than the gap"
    );
}

#[tokio::test]
async fn a_since_older_than_the_retained_tail_falls_back_to_a_snapshot() {
    let app = spawn_app().await;
    let token = platform_token(&fresh_user());
    let document_id = create_document(&app, &token, "pruned").await;

    // one connection stays on the document so the room keeps the state that the
    // pruned ops carried
    let mut holder = open(&app, document_id, &token, None).await;
    expect_join(&mut holder).await;
    for index in 1..=3 {
        let seq = send_and_settle(
            &mut holder,
            index,
            &format!("layers/l{index}"),
            json!({"order": "a0"}),
        )
        .await;
        assert_eq!(seq, index);
    }

    // what a checkpoint prune leaves behind: the oldest ops are gone
    sqlx::query("delete from ops where doc_id = $1 and seq <= 2")
        .bind(document_id)
        .execute(&app.state.pool)
        .await
        .expect("prune the tail");

    let mut reconnected = open(&app, document_id, &token, Some(1)).await;
    let snapshot = reconnected.expect_message("snapshot").await;
    assert_eq!(snapshot["seq"], 3);
    assert_eq!(snapshot["state"]["layers"]["l1"]["order"], "a0");
    reconnected.expect_message("assets").await;
    reconnected.expect_message("watches").await;
    reconnected.expect_message("peers").await;
}

#[tokio::test]
async fn document_state_survives_a_restart_from_its_checkpoint_and_tail() {
    let app = spawn_app().await;
    let owner = fresh_user();
    let token = platform_token(&owner);
    let document_id = create_document(&app, &token, "checkpointed").await;

    let ops = 300;
    let last_seq = apply_ops_directly(&app, document_id, &owner, ops).await;
    assert_eq!(last_seq, ops as i64);

    let checkpoint_seq: i64 =
        sqlx::query_scalar("select checkpoint_seq from documents where id = $1")
            .bind(document_id)
            .fetch_one(&app.state.pool)
            .await
            .expect("read the checkpoint seq");
    assert_eq!(checkpoint_seq, 256, "no checkpoint was folded");
    assert!(
        !app.state.rooms.is_loaded(document_id).await,
        "the room outlived its last connection"
    );

    let restarted = restart(&app).await;
    let mut client = open(&restarted, document_id, &token, None).await;
    let snapshot = client.expect_message("snapshot").await;
    assert_eq!(snapshot["seq"], ops as i64);
    let layers = snapshot["state"]["layers"]
        .as_object()
        .expect("a layer map");
    assert_eq!(layers.len(), ops);
    // one key from before the checkpoint and one from the tail after it
    assert_eq!(layers["l0"]["order"], "a0000");
    assert_eq!(layers["l299"]["order"], "a0299");
    assert_eq!(snapshot["state"]["meta"]["name"], "checkpointed");
}

#[tokio::test]
async fn a_checkpoint_folds_once_ops_across_short_sessions_reach_the_interval() {
    let app = spawn_app().await;
    let owner = fresh_user();
    let token = platform_token(&owner);
    let document_id = create_document(&app, &token, "short sessions").await;

    let last_seq = apply_ops_directly(&app, document_id, &owner, 200).await;
    assert_eq!(last_seq, 200);
    assert!(
        !app.state.rooms.is_loaded(document_id).await,
        "the room outlived its last connection"
    );

    let checkpoint_seq: i64 =
        sqlx::query_scalar("select checkpoint_seq from documents where id = $1")
            .bind(document_id)
            .fetch_one(&app.state.pool)
            .await
            .expect("read the checkpoint seq");
    assert_eq!(checkpoint_seq, 0);

    let last_seq = apply_ops_directly_from(&app, document_id, &owner, 200, 56).await;
    assert_eq!(last_seq, 256);

    let checkpoint_seq: i64 =
        sqlx::query_scalar("select checkpoint_seq from documents where id = $1")
            .bind(document_id)
            .fetch_one(&app.state.pool)
            .await
            .expect("read the checkpoint seq");
    assert_eq!(checkpoint_seq, 256, "no checkpoint was folded");
}

#[tokio::test]
async fn comments_reach_the_snapshot_the_checkpoint_and_a_restart() {
    let app = spawn_app().await;
    let owner = fresh_user();
    let token = platform_token(&owner);
    let document_id = create_document(&app, &token, "commented").await;

    let thread = "018f2c1a-6d3b-7e42-9c10-5a8b7d2e4f16";
    let reply = "018f2c1a-6d3b-7e42-9c10-5a8b7d2e4f17";
    let mut client = open(&app, document_id, &token, None).await;
    expect_join(&mut client).await;
    send_and_settle(
        &mut client,
        1,
        &format!("comments/{thread}"),
        json!({
            "id": thread,
            "actor": owner,
            "authorName": "Ada",
            "text": "is this the right coastline",
            "createdAt": 10,
            "resolved": false,
            "anchor": {"lng": 12.5, "lat": -3.25, "zoom": 8}
        }),
    )
    .await;
    send_and_settle(
        &mut client,
        2,
        &format!("comments/{reply}"),
        json!({
            "id": reply,
            "actor": owner,
            "authorName": "Ada",
            "text": "checked, it is",
            "createdAt": 20,
            "parentId": thread
        }),
    )
    .await;
    client.close().await;

    let snapshot = stored_document(&app, document_id, &token).await;
    let comments = snapshot["state"]["comments"]
        .as_object()
        .expect("a comment map");
    assert_eq!(comments.len(), 2);
    assert_eq!(comments[thread]["text"], "is this the right coastline");
    assert_eq!(comments[thread]["anchor"]["lng"], 12.5);
    assert_eq!(comments[reply]["parentId"], thread);

    // fold a checkpoint over the comment ops, then prove it carried them
    apply_ops_directly(&app, document_id, &owner, 300).await;
    let checkpoint: Value = sqlx::query_scalar("select checkpoint from documents where id = $1")
        .bind(document_id)
        .fetch_one(&app.state.pool)
        .await
        .expect("read the checkpoint");
    assert_eq!(checkpoint["comments"][thread]["createdAt"], 10);
    assert_eq!(checkpoint["comments"][reply]["parentId"], thread);

    let restarted = restart(&app).await;
    let recovered = stored_document(&restarted, document_id, &token).await;
    assert_eq!(
        recovered["state"]["comments"][thread]["text"],
        "is this the right coastline"
    );

    // resolve is last writer wins on the same key, and a null deletes it
    let mut client = open(&restarted, document_id, &token, None).await;
    expect_join(&mut client).await;
    send_and_settle(
        &mut client,
        1,
        &format!("comments/{thread}"),
        json!({
            "id": thread,
            "actor": owner,
            "authorName": "Ada",
            "text": "is this the right coastline",
            "createdAt": 10,
            "resolved": true
        }),
    )
    .await;
    send_and_settle(&mut client, 2, &format!("comments/{reply}"), Value::Null).await;
    client.close().await;

    let settled = stored_document(&restarted, document_id, &token).await;
    assert_eq!(settled["state"]["comments"][thread]["resolved"], true);
    assert!(settled["state"]["comments"].get(reply).is_none());
}

#[tokio::test]
async fn a_room_is_dropped_once_its_last_connection_leaves() {
    let app = spawn_app().await;
    let owner = fresh_user();
    let token = platform_token(&owner);
    let document_id = create_document(&app, &token, "transient").await;

    let peer = Peer {
        actor: owner.clone(),
        name: owner.clone(),
        role: DocumentRole::Edit,
    };
    let joined = app
        .state
        .rooms
        .join(&app.state.pool, document_id, peer)
        .await
        .expect("join");
    assert!(app.state.rooms.is_loaded(document_id).await);
    app.state
        .rooms
        .leave(document_id, joined.connection_id)
        .await;
    assert!(!app.state.rooms.is_loaded(document_id).await);
}

#[tokio::test]
async fn presence_reaches_the_others_with_a_server_actor_and_never_the_sender() {
    let app = spawn_app().await;
    let owner = fresh_user();
    let token = platform_token(&owner);
    let document_id = create_document(&app, &token, "presence").await;
    let guest_token = guest_session(&app, &token, document_id, "view").await;

    let mut owner_client = open(&app, document_id, &token, None).await;
    expect_join(&mut owner_client).await;
    let mut guest_client = open(&app, document_id, &guest_token, None).await;
    let (snapshot, _) = expect_join(&mut guest_client).await;
    let guest_actor = snapshot["actor"].as_str().expect("an actor").to_string();
    owner_client.expect_message("peers").await;

    // claiming an actor is refused outright rather than ignored
    guest_client
        .send(json!({
            "type": "presence",
            "cursor": [12.5, -3.25],
            "selection": ["layers/roads"],
            "viewport": {"zoom": 6},
            "actor": "someone-else"
        }))
        .await;
    assert_eq!(
        guest_client.expect_message("error").await["reason"],
        json!("malformed message")
    );

    guest_client
        .send(json!({
            "type": "presence",
            "cursor": [12.5, -3.25],
            "selection": ["layers/roads"],
            "viewport": {"zoom": 6}
        }))
        .await;

    // the sender is never drawn its own cursor
    assert!(
        guest_client.try_next_message().await.is_none(),
        "presence was echoed back to its sender"
    );

    let relayed = owner_client.expect_message("presence").await;
    assert_eq!(relayed["cursor"], json!([12.5, -3.25]));
    assert_eq!(relayed["selection"], json!(["layers/roads"]));
    assert_eq!(relayed["viewport"]["zoom"], 6);
    assert_eq!(
        relayed["actor"], guest_actor,
        "the server did not stamp the sender's actor"
    );

    let stored: i64 = sqlx::query_scalar("select count(*) from ops where doc_id = $1")
        .bind(document_id)
        .fetch_one(&app.state.pool)
        .await
        .expect("count ops");
    assert_eq!(stored, 0, "presence was persisted");
}

#[tokio::test]
async fn the_key_namespace_whitelist_refuses_anything_outside_it() {
    let app = spawn_app().await;
    let token = platform_token(&fresh_user());
    let document_id = create_document(&app, &token, "namespaces").await;

    let mut client = open(&app, document_id, &token, None).await;
    expect_join(&mut client).await;

    for (key, reason) in [
        ("secrets/root", "unknown key namespace"),
        ("layers", "unknown key namespace"),
        ("/root", "unknown key namespace"),
        ("layers/", "invalid key id"),
        ("layers/a/b", "invalid key id"),
        ("layers/../escape", "invalid key id"),
    ] {
        let given = send_and_refuse(&mut client, 1, key, json!({"order": "a0"})).await;
        assert_eq!(given, reason, "key {key:?}");
    }
}

#[tokio::test]
async fn the_key_length_cap_refuses_a_long_key() {
    let app = spawn_app().await;
    let token = platform_token(&fresh_user());
    let document_id = create_document(&app, &token, "key cap").await;

    let mut client = open(&app, document_id, &token, None).await;
    expect_join(&mut client).await;

    let at_cap = format!("layers/{}", "a".repeat(MAX_KEY_BYTES - "layers/".len()));
    assert_eq!(
        send_and_settle(&mut client, 1, &at_cap, json!({"order": "a0"})).await,
        1
    );

    let over_cap = format!("{at_cap}a");
    let reason = send_and_refuse(&mut client, 2, &over_cap, json!({"order": "a0"})).await;
    assert_eq!(reason, "key too long");
}

#[tokio::test]
async fn the_op_value_cap_refuses_an_oversized_value() {
    let app = spawn_app().await;
    let token = platform_token(&fresh_user());
    let document_id = create_document(&app, &token, "value cap").await;

    let mut client = open(&app, document_id, &token, None).await;
    expect_join(&mut client).await;

    let reason = send_and_refuse(
        &mut client,
        1,
        "layers/big",
        json!("x".repeat(MAX_OP_VALUE_BYTES)),
    )
    .await;
    assert_eq!(reason, "op value too large");

    assert_eq!(
        send_and_settle(
            &mut client,
            2,
            "layers/fits",
            json!("x".repeat(MAX_OP_VALUE_BYTES - 2))
        )
        .await,
        1
    );
}

#[tokio::test]
async fn the_presence_cap_refuses_an_oversized_presence() {
    let app = spawn_app().await;
    let token = platform_token(&fresh_user());
    let document_id = create_document(&app, &token, "presence cap").await;

    let mut client = open(&app, document_id, &token, None).await;
    expect_join(&mut client).await;

    client
        .send(json!({
            "type": "presence",
            "cursor": [0.0, 0.0],
            "selection": ["x".repeat(MAX_PRESENCE_BYTES)],
        }))
        .await;
    assert_eq!(
        client.expect_message("error").await["reason"],
        "presence too large"
    );
}

#[tokio::test]
async fn the_document_state_cap_refuses_an_op_that_would_exceed_it() {
    let app = spawn_app().await;
    let owner = fresh_user();
    let token = platform_token(&owner);
    let document_id = create_document(&app, &token, "state cap").await;

    let peer = Peer {
        actor: owner.clone(),
        name: owner.clone(),
        role: DocumentRole::Edit,
    };
    let joined = app
        .state
        .rooms
        .join(&app.state.pool, document_id, peer)
        .await
        .expect("join");

    let chunk = "x".repeat(MAX_OP_VALUE_BYTES - 2);
    let mut accepted = 0;
    let mut refusal = None;
    for index in 0..128 {
        let outcome = joined
            .room
            .apply_op(
                &app.state.pool,
                &owner,
                index,
                &format!("layers/l{index}"),
                Some(json!(chunk)),
            )
            .await;
        match outcome {
            Ok(_) => accepted += 1,
            Err(error) => {
                refusal = Some(error.reason());
                break;
            }
        }
    }
    assert_eq!(refusal, Some("document state limit reached"));
    assert!(accepted >= 60, "the state cap refused far too early");

    let mut client = open(&app, document_id, &token, None).await;
    expect_join(&mut client).await;
    let reason = send_and_refuse(&mut client, 1, "layers/one-more", json!(chunk)).await;
    assert_eq!(reason, "document state limit reached");

    app.state
        .rooms
        .leave(document_id, joined.connection_id)
        .await;
}

#[tokio::test]
async fn the_document_state_cap_refuses_a_batch_that_no_single_op_would_trip() {
    let app = spawn_app().await;
    let owner = fresh_user();
    let token = platform_token(&owner);
    let name = "cumulative cap";
    let document_id = create_document(&app, &token, name).await;

    let peer = Peer {
        actor: owner.clone(),
        name: owner.clone(),
        role: DocumentRole::Edit,
    };
    let joined = app
        .state
        .rooms
        .join(&app.state.pool, document_id, peer)
        .await
        .expect("join");

    // fill to just under the cap, counting the way the server does: the key
    // length plus the json length of the value, for the name it was created with
    // and then for every chunk
    let chunk = json!("x".repeat(MAX_OP_VALUE_BYTES - 2));
    let mut used = META_NAME_KEY.len() + name.len() + 2;
    let mut client_seq = 0;
    loop {
        let key = format!("layers/l{client_seq:02}");
        if used + key.len() + MAX_OP_VALUE_BYTES > MAX_DOCUMENT_STATE_BYTES {
            break;
        }
        joined
            .room
            .apply_op(
                &app.state.pool,
                &owner,
                client_seq,
                &key,
                Some(chunk.clone()),
            )
            .await
            .expect("a chunk that fits");
        used += key.len() + MAX_OP_VALUE_BYTES;
        client_seq += 1;
    }

    let headroom = MAX_DOCUMENT_STATE_BYTES - used;
    let key_bytes = "layers/m0".len();
    let value_bytes = headroom * 3 / 5;
    assert!(
        key_bytes + value_bytes <= headroom,
        "each op has to fit in the headroom on its own"
    );
    assert!(
        2 * (key_bytes + value_bytes) > headroom,
        "the two ops together have to pass the cap"
    );
    let value = json!("x".repeat(value_bytes - 2));

    let refusal = joined
        .room
        .apply_batch(
            &app.state.pool,
            &owner,
            client_seq,
            &[
                BatchOp {
                    key: "layers/m0".to_string(),
                    value: OpValue(Some(value.clone())),
                },
                BatchOp {
                    key: "layers/m1".to_string(),
                    value: OpValue(Some(value.clone())),
                },
            ],
        )
        .await
        .expect_err("the pair passes the cap together");
    assert_eq!(refusal.reason(), "document state limit reached");

    let (_, state) = joined.room.snapshot().await;
    assert!(
        state["layers"].get("m0").is_none() && state["layers"].get("m1").is_none(),
        "a refused batch wrote one of its ops"
    );

    // the same op on its own is accepted, so it was only the pair that was over
    joined
        .room
        .apply_op(
            &app.state.pool,
            &owner,
            client_seq + 1,
            "layers/m0",
            Some(value),
        )
        .await
        .expect("one of the pair fits on its own");

    app.state
        .rooms
        .leave(document_id, joined.connection_id)
        .await;
}

#[tokio::test]
async fn a_batch_past_the_op_cap_or_with_no_ops_is_refused() {
    let app = spawn_app().await;
    let token = platform_token(&fresh_user());
    let document_id = create_document(&app, &token, "batch cap").await;

    let mut client = open(&app, document_id, &token, None).await;
    expect_join(&mut client).await;

    let over_cap = (0..=MAX_BATCH_OPS)
        .map(|index| batch_op(&format!("layers/l{index}"), json!({"order": "a0"})))
        .collect();
    assert_eq!(
        send_batch_and_refuse(&mut client, 1, over_cap).await,
        "batch too large"
    );
    assert_eq!(
        send_batch_and_refuse(&mut client, 2, Vec::new()).await,
        "batch carries no ops"
    );

    let snapshot = stored_document(&app, document_id, &token).await;
    assert_eq!(snapshot["seq"], 0);
}

#[tokio::test]
async fn the_rate_limit_refuses_a_flood_and_keeps_the_connection() {
    let app = spawn_app().await;
    let token = platform_token(&fresh_user());
    let document_id = create_document(&app, &token, "rate cap").await;
    let guest_token = guest_session(&app, &token, document_id, "view").await;

    let mut flooder = open(&app, document_id, &token, None).await;
    expect_join(&mut flooder).await;
    let mut watcher = open(&app, document_id, &guest_token, None).await;
    expect_join(&mut watcher).await;
    flooder.expect_message("peers").await;

    let cap = MAX_CLIENT_MESSAGES_PER_SECOND;
    let flood = cap * 2;
    for _ in 0..flood {
        flooder
            .send(json!({"type": "presence", "cursor": [0.0, 0.0], "selection": []}))
            .await;
    }

    let mut refusals = 0;
    while let Some(message) = flooder.try_next_message().await {
        assert_eq!(message["type"], "error", "unexpected message {message}");
        assert_eq!(message["reason"], "rate limit exceeded");
        refusals += 1;
    }
    assert!(refusals > 0, "the flood was never refused");

    let mut relayed = 0;
    while let Some(message) = watcher.try_next_message().await {
        match message["type"].as_str() {
            Some("presence") => relayed += 1,
            Some("peers") => {}
            other => panic!("unexpected message kind {other:?}"),
        }
    }
    assert!(relayed > 0, "nothing at all got through");
    assert!(
        relayed <= cap,
        "{relayed} of {flood} got past a cap of {cap}"
    );

    // the connection survived the flood, which is the point of refusing a
    // message rather than hanging up on it
    assert!(!flooder.is_closed().await, "a flood closed the connection");
    flooder
        .send_op(1, "layers/after", json!({"order": "a0"}))
        .await;
    // once the flood's rate limit window has run out the op is applied, and
    // then its own echo races the ack, so either can arrive first
    for _ in 0..8 {
        let reply = flooder.next_message().await;
        match reply["type"].as_str() {
            Some("ack") | Some("error") => return,
            Some("op") => continue,
            _ => panic!("the connection stopped answering: {reply}"),
        }
    }
    panic!("the op after the flood was never answered");
}

#[tokio::test]
async fn a_batch_charges_the_rate_limit_for_every_op_it_carries() {
    let app = spawn_app().await;
    let token = platform_token(&fresh_user());
    let document_id = create_document(&app, &token, "batch rate").await;

    let full_batch = || -> Vec<Value> {
        (0..MAX_BATCH_OPS)
            .map(|index| batch_op(&format!("layers/l{index}"), json!({"order": "a0"})))
            .collect()
    };

    // one op leaves room for one short of a full batch, so the batch that
    // follows it is a single op over the budget and is refused whole
    let mut spent = open(&app, document_id, &token, None).await;
    expect_join(&mut spent).await;
    assert_eq!(
        send_and_settle(&mut spent, 1, "layers/first", json!({"order": "a0"})).await,
        1
    );
    assert_eq!(
        send_batch_and_refuse(&mut spent, 2, full_batch()).await,
        "rate limit exceeded"
    );

    let snapshot = stored_document(&app, document_id, &token).await;
    assert_eq!(
        snapshot["seq"], 1,
        "a batch past the rate limit was still applied"
    );

    // a connection with its whole budget takes the same batch, so the cap and
    // the batch size agree
    let mut fresh = open(&app, document_id, &token, None).await;
    expect_join(&mut fresh).await;
    assert_eq!(
        send_batch_and_settle(&mut fresh, 1, full_batch()).await,
        1 + MAX_BATCH_OPS as i64
    );
}

#[tokio::test]
async fn the_peer_cap_refuses_the_connection_past_the_limit() {
    let app = spawn_app().await;
    let token = platform_token(&fresh_user());
    let document_id = create_document(&app, &token, "peer cap").await;

    let mut clients = Vec::new();
    for _ in 0..MAX_PEERS_PER_DOCUMENT {
        let mut client = open(&app, document_id, &token, None).await;
        client.expect_message("snapshot").await;
        clients.push(client);
    }

    let mut over = open(&app, document_id, &token, None).await;
    let refusal = over.expect_message("error").await;
    assert_eq!(refusal["reason"], "document has too many peers");
    assert!(
        over.is_closed().await,
        "a refused peer was left on the document"
    );
}

#[tokio::test]
async fn the_document_name_cap_refuses_a_long_name() {
    let app = spawn_app().await;
    let token = platform_token(&fresh_user());

    for name in [
        "".to_string(),
        "   ".to_string(),
        "a".repeat(MAX_DOCUMENT_NAME_BYTES + 1),
        "line\nbreak".to_string(),
    ] {
        let response = app
            .client
            .post(format!("{}/documents", app.http_base))
            .bearer_auth(&token)
            .json(&json!({"name": name}))
            .send()
            .await
            .expect("create");
        assert_eq!(response.status(), 400, "name {name:?} was accepted");
    }

    let document_id = create_document(&app, &token, "name cap").await;
    let mut client = open(&app, document_id, &token, None).await;
    expect_join(&mut client).await;

    let long = send_and_refuse(
        &mut client,
        1,
        "meta/name",
        json!("a".repeat(MAX_DOCUMENT_NAME_BYTES + 1)),
    )
    .await;
    assert_eq!(long, "invalid document name");
    let wrong_type = send_and_refuse(&mut client, 2, "meta/name", json!(42)).await;
    assert_eq!(wrong_type, "invalid document name");
    let deleted = send_and_refuse(&mut client, 3, "meta/name", Value::Null).await;
    assert_eq!(deleted, "invalid document name");

    assert_eq!(
        send_and_settle(&mut client, 4, "meta/name", json!("renamed")).await,
        1
    );
    let stored: String = sqlx::query_scalar("select name from documents where id = $1")
        .bind(document_id)
        .fetch_one(&app.state.pool)
        .await
        .expect("read the name");
    assert_eq!(
        stored, "renamed",
        "meta/name did not reach the document row"
    );
}

#[tokio::test]
async fn an_oversized_frame_closes_the_connection() {
    let app = spawn_app().await;
    let token = platform_token(&fresh_user());
    let document_id = create_document(&app, &token, "frame cap").await;

    let mut client = open(&app, document_id, &token, None).await;
    expect_join(&mut client).await;

    let huge = "x".repeat(MAX_INBOUND_FRAME_BYTES + 1024);
    let _ = client.stream.send(Message::text(huge)).await;
    assert!(client.is_closed().await, "an oversized frame was accepted");
}

#[tokio::test]
async fn malformed_and_binary_frames_are_refused_without_closing() {
    let app = spawn_app().await;
    let token = platform_token(&fresh_user());
    let document_id = create_document(&app, &token, "malformed").await;

    let mut client = open(&app, document_id, &token, None).await;
    expect_join(&mut client).await;

    for text in [
        "not json",
        r#"{"type":"unknown"}"#,
        r#"{"type":"op","clientSeq":1,"key":"layers/a"}"#,
        r#"{"type":"presence","cursor":"here"}"#,
    ] {
        client.stream.send(Message::text(text)).await.expect("send");
        assert_eq!(
            client.expect_message("error").await["reason"],
            "malformed message",
            "frame {text:?}"
        );
    }

    client
        .stream
        .send(Message::binary(vec![0u8, 1, 2]))
        .await
        .expect("send");
    assert_eq!(
        client.expect_message("error").await["reason"],
        "binary frames are not accepted"
    );

    assert_eq!(
        send_and_settle(&mut client, 1, "layers/still-works", json!({"order": "a0"})).await,
        1
    );
}

#[tokio::test]
async fn the_subprotocol_handshake_echoes_only_the_marker() {
    let app = spawn_app().await;
    let token = platform_token(&fresh_user());
    let document_id = create_document(&app, &token, "handshake").await;

    let (mut client, response) = connect_with_subprotocol(&app, document_id, &token, None)
        .await
        .expect("handshake");
    let echoed = response
        .headers()
        .get("sec-websocket-protocol")
        .and_then(|value| value.to_str().ok())
        .expect("the marker is echoed");
    assert_eq!(echoed, "bearer");
    assert!(!echoed.contains(&token), "the token was echoed back");
    expect_join(&mut client).await;
}

#[tokio::test]
async fn a_header_or_a_query_param_also_authenticates_the_websocket() {
    let app = spawn_app().await;
    let token = platform_token(&fresh_user());
    let document_id = create_document(&app, &token, "fallbacks").await;

    let (mut by_header, response) = connect_with_header(&app, document_id, &token)
        .await
        .expect("header handshake");
    assert!(
        response.headers().get("sec-websocket-protocol").is_none(),
        "a subprotocol was selected without an offer"
    );
    expect_join(&mut by_header).await;

    let (mut by_query, _) = connect_with_query_param(&app, document_id, &token)
        .await
        .expect("query handshake");
    by_query.expect_message("snapshot").await;
}

#[tokio::test]
async fn a_websocket_without_a_usable_credential_is_refused_before_the_upgrade() {
    let app = spawn_app().await;
    let owner = fresh_user();
    let token = platform_token(&owner);
    let document_id = create_document(&app, &token, "gated").await;

    let no_token = connect_async(websocket_url(&app, document_id, None))
        .await
        .map(|(stream, response)| (WebsocketClient { stream }, response));
    assert_eq!(handshake_status(no_token), Some(401));

    let junk = connect_with_subprotocol(&app, document_id, "not.a.token", None).await;
    assert_eq!(handshake_status(junk), Some(401));

    let stranger = platform_token(&fresh_user());
    let outsider = connect_with_subprotocol(&app, document_id, &stranger, None).await;
    assert_eq!(handshake_status(outsider), Some(403));

    let other_document = create_document(&app, &token, "elsewhere").await;
    let session = guest_session(&app, &token, other_document, "edit").await;
    let wrong_document = connect_with_subprotocol(&app, document_id, &session, None).await;
    assert_eq!(
        handshake_status(wrong_document),
        Some(403),
        "a session token worked on another document"
    );
}

#[tokio::test]
async fn a_session_token_is_not_a_platform_token_on_the_http_api() {
    let app = spawn_app().await;
    let owner = fresh_user();
    let token = platform_token(&owner);
    let document_id = create_document(&app, &token, "escalation").await;
    let session = guest_session(&app, &token, document_id, "edit").await;

    let created = app
        .client
        .post(format!("{}/documents", app.http_base))
        .bearer_auth(&session)
        .json(&json!({"name": "not allowed"}))
        .send()
        .await
        .expect("create attempt");
    assert_eq!(created.status(), 401, "a share link minted a document");

    let listed = app
        .client
        .get(format!("{}/documents", app.http_base))
        .bearer_auth(&session)
        .send()
        .await
        .expect("list attempt");
    assert_eq!(listed.status(), 401);

    let minted = app
        .client
        .post(format!("{}/documents/{document_id}/links", app.http_base))
        .bearer_auth(&session)
        .json(&json!({"role": "edit"}))
        .send()
        .await
        .expect("link attempt");
    assert_eq!(minted.status(), 401, "a share link minted another link");
}

#[tokio::test]
async fn the_http_api_only_shows_a_caller_their_own_documents() {
    let app = spawn_app().await;
    let owner = fresh_user();
    let token = platform_token(&owner);
    let document_id = create_document(&app, &token, "mine").await;

    let listed: Value = app
        .client
        .get(format!("{}/documents", app.http_base))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list")
        .json()
        .await
        .expect("json");
    let listed = listed.as_array().expect("an array");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["id"], document_id.to_string());
    assert_eq!(listed[0]["role"], "edit");

    let detail: Value = app
        .client
        .get(format!("{}/documents/{document_id}", app.http_base))
        .bearer_auth(&token)
        .send()
        .await
        .expect("detail")
        .json()
        .await
        .expect("json");
    assert_eq!(detail["name"], "mine");
    assert_eq!(detail["createdBy"], owner.as_str());
    assert_eq!(detail["members"][0]["userId"], owner.as_str());
    assert_eq!(detail["members"][0]["role"], "edit");

    let stranger = platform_token(&fresh_user());
    let hidden = app
        .client
        .get(format!("{}/documents/{document_id}", app.http_base))
        .bearer_auth(&stranger)
        .send()
        .await
        .expect("detail as a stranger");
    assert_eq!(hidden.status(), 404, "a non member read a document");

    let empty: Value = app
        .client
        .get(format!("{}/documents", app.http_base))
        .bearer_auth(&stranger)
        .send()
        .await
        .expect("list as a stranger")
        .json()
        .await
        .expect("json");
    assert_eq!(empty.as_array().expect("an array").len(), 0);

    let unauthenticated = app
        .client
        .get(format!("{}/documents", app.http_base))
        .send()
        .await
        .expect("list with no token");
    assert_eq!(unauthenticated.status(), 401);
}

#[tokio::test]
async fn a_share_link_is_stored_only_as_a_hash() {
    let app = spawn_app().await;
    let token = platform_token(&fresh_user());
    let document_id = create_document(&app, &token, "hashed at rest").await;
    let link = mint_link(&app, &token, document_id, "edit").await;

    let stored: Vec<String> =
        sqlx::query_scalar("select token_hash from share_links where doc_id = $1")
            .bind(document_id)
            .fetch_all(&app.state.pool)
            .await
            .expect("read share_links");
    assert_eq!(stored.len(), 1);
    assert_ne!(stored[0], link, "the raw token is in the database");
    assert_eq!(stored[0], capability_token_hash(&link));

    // a database read hands over the hash, and the hash is not a credential
    let by_hash = app
        .client
        .get(format!("{}/links/{}", app.http_base, stored[0]))
        .send()
        .await
        .expect("resolve by the stored hash");
    assert_eq!(by_hash.status(), 404);

    assert_eq!(resolve_link(&app, &link).await["role"], "edit");
}

#[tokio::test]
async fn a_raw_token_still_revokes_its_link() {
    let app = spawn_app().await;
    let token = platform_token(&fresh_user());
    let document_id = create_document(&app, &token, "revoke by raw token").await;
    let link = mint_link(&app, &token, document_id, "view").await;
    let session = resolve_link(&app, &link).await["sessionToken"]
        .as_str()
        .expect("a session token")
        .to_string();

    let revoked = app
        .client
        .delete(format!("{}/links/{link}", app.http_base))
        .bearer_auth(&token)
        .send()
        .await
        .expect("revoke");
    assert_eq!(revoked.status(), 204);

    let flag: bool = sqlx::query_scalar("select revoked from share_links where token_hash = $1")
        .bind(capability_token_hash(&link))
        .fetch_one(&app.state.pool)
        .await
        .expect("read the revoked flag");
    assert!(flag, "revoking by the raw token missed the row");

    let gone = app
        .client
        .get(format!("{}/links/{link}", app.http_base))
        .send()
        .await
        .expect("resolve a revoked link");
    assert_eq!(gone.status(), 404);

    let refused = connect_with_subprotocol(&app, document_id, &session, None).await;
    assert_eq!(handshake_status(refused), Some(403));
}

#[tokio::test]
async fn only_an_editor_can_mint_or_revoke_a_share_link() {
    let app = spawn_app().await;
    let owner = fresh_user();
    let token = platform_token(&owner);
    let document_id = create_document(&app, &token, "link gate").await;
    let link = mint_link(&app, &token, document_id, "view").await;

    let reader = fresh_user();
    sqlx::query("insert into members (doc_id, user_id, role) values ($1, $2, 'view')")
        .bind(document_id)
        .bind(&reader)
        .execute(&app.state.pool)
        .await
        .expect("add a view member");
    let reader_token = platform_token(&reader);

    let minted = app
        .client
        .post(format!("{}/documents/{document_id}/links", app.http_base))
        .bearer_auth(&reader_token)
        .json(&json!({"role": "edit"}))
        .send()
        .await
        .expect("mint as a reader");
    assert_eq!(minted.status(), 403);

    let stranger = platform_token(&fresh_user());
    for caller in [reader_token.as_str(), stranger.as_str()] {
        let revoked = app
            .client
            .delete(format!("{}/links/{link}", app.http_base))
            .bearer_auth(caller)
            .send()
            .await
            .expect("revoke attempt");
        assert_eq!(revoked.status(), 404, "a non editor revoked a link");
    }

    let unknown = app
        .client
        .get(format!("{}/links/{}", app.http_base, "made-up-token"))
        .send()
        .await
        .expect("resolve an unknown link");
    assert_eq!(unknown.status(), 404);

    // the link still works, so none of the refused calls changed it
    assert_eq!(resolve_link(&app, &link).await["role"], "view");
}

#[tokio::test]
async fn an_editor_adds_a_member_and_changes_their_role() {
    let app = spawn_app().await;
    let owner = fresh_user();
    let owner_token = platform_token(&owner);
    let document_id = create_document(&app, &owner_token, "shared work").await;

    let invitee = fresh_user();
    let invitee_token = platform_token(&invitee);
    let before = app
        .client
        .get(format!("{}/documents/{document_id}", app.http_base))
        .bearer_auth(&invitee_token)
        .send()
        .await
        .expect("detail before joining");
    assert_eq!(before.status(), 404);

    assert_eq!(
        set_member(&app, &owner_token, document_id, &invitee, "view")
            .await
            .status(),
        204
    );

    let listed: Value = app
        .client
        .get(format!("{}/documents", app.http_base))
        .bearer_auth(&invitee_token)
        .send()
        .await
        .expect("list")
        .json()
        .await
        .expect("json");
    let listed = listed.as_array().expect("an array");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["id"], document_id.to_string());
    assert_eq!(listed[0]["role"], "view");

    // a view member cannot mint a link, an edit member can, so the stored role
    // is what actually decides
    let minted = app
        .client
        .post(format!("{}/documents/{document_id}/links", app.http_base))
        .bearer_auth(&invitee_token)
        .json(&json!({"role": "view"}))
        .send()
        .await
        .expect("mint as a view member");
    assert_eq!(minted.status(), 403);

    assert_eq!(
        set_member(&app, &owner_token, document_id, &invitee, "edit")
            .await
            .status(),
        204
    );
    let link = mint_link(&app, &invitee_token, document_id, "view").await;
    assert_eq!(resolve_link(&app, &link).await["role"], "view");

    // setting the same role again is the same operation, not a second member
    assert_eq!(
        set_member(&app, &owner_token, document_id, &invitee, "edit")
            .await
            .status(),
        204
    );
    let mut roles = member_roles(&app, &owner_token, document_id).await;
    roles.sort();
    let mut expected = vec![
        (owner.clone(), "edit".to_string()),
        (invitee.clone(), "edit".to_string()),
    ];
    expected.sort();
    assert_eq!(roles, expected);

    assert_eq!(
        remove_member(&app, &owner_token, document_id, &invitee)
            .await
            .status(),
        204
    );
    assert_eq!(
        member_roles(&app, &owner_token, document_id).await,
        vec![(owner, "edit".to_string())]
    );
    let after = app
        .client
        .get(format!("{}/documents/{document_id}", app.http_base))
        .bearer_auth(&invitee_token)
        .send()
        .await
        .expect("detail after removal");
    assert_eq!(after.status(), 404);
}

#[tokio::test]
async fn only_an_editor_can_manage_members() {
    let app = spawn_app().await;
    let owner = fresh_user();
    let owner_token = platform_token(&owner);
    let document_id = create_document(&app, &owner_token, "member gate").await;

    let reader = fresh_user();
    assert_eq!(
        set_member(&app, &owner_token, document_id, &reader, "view")
            .await
            .status(),
        204
    );
    let reader_token = platform_token(&reader);
    let stranger = fresh_user();
    let stranger_token = platform_token(&stranger);
    let session = guest_session(&app, &owner_token, document_id, "edit").await;
    let target = fresh_user();

    // a view member is told 403, a non member 404, so a document id cannot be
    // probed with a membership call
    for (caller, expected) in [
        (&reader_token, 403),
        (&stranger_token, 404),
        (&session, 401),
    ] {
        assert_eq!(
            set_member(&app, caller, document_id, &target, "edit")
                .await
                .status(),
            expected
        );
        assert_eq!(
            remove_member(&app, caller, document_id, &owner)
                .await
                .status(),
            expected
        );
    }

    let unauthenticated = app
        .client
        .put(format!(
            "{}/documents/{document_id}/members/{target}",
            app.http_base
        ))
        .json(&json!({"role": "edit"}))
        .send()
        .await
        .expect("set with no token");
    assert_eq!(unauthenticated.status(), 401);

    let mut roles = member_roles(&app, &owner_token, document_id).await;
    roles.sort();
    let mut expected = vec![(owner, "edit".to_string()), (reader, "view".to_string())];
    expected.sort();
    assert_eq!(roles, expected, "a refused call changed the member list");
}

/// The role that decides a membership call is read at mutation time, not
/// carried over from an earlier call, so losing edit role takes effect at once.
#[tokio::test]
async fn a_demoted_editor_can_no_longer_manage_members() {
    let app = spawn_app().await;
    let owner = fresh_user();
    let owner_token = platform_token(&owner);
    let document_id = create_document(&app, &owner_token, "role recheck").await;

    let successor = fresh_user();
    let successor_token = platform_token(&successor);
    assert_eq!(
        set_member(&app, &owner_token, document_id, &successor, "edit")
            .await
            .status(),
        204
    );

    let target = fresh_user();
    assert_eq!(
        set_member(&app, &owner_token, document_id, &target, "view")
            .await
            .status(),
        204,
        "an editor could not add a member"
    );

    assert_eq!(
        set_member(&app, &owner_token, document_id, &owner, "view")
            .await
            .status(),
        204
    );

    // the same caller, the same routes, one role change in between
    assert_eq!(
        set_member(&app, &owner_token, document_id, &target, "edit")
            .await
            .status(),
        403
    );
    assert_eq!(
        remove_member(&app, &owner_token, document_id, &target)
            .await
            .status(),
        403
    );

    let stranger_token = platform_token(&fresh_user());
    assert_eq!(
        set_member(&app, &stranger_token, document_id, &target, "edit")
            .await
            .status(),
        404
    );
    assert_eq!(
        remove_member(&app, &stranger_token, document_id, &target)
            .await
            .status(),
        404
    );

    let mut roles = member_roles(&app, &successor_token, document_id).await;
    roles.sort();
    let mut expected = vec![
        (owner, "view".to_string()),
        (successor.clone(), "edit".to_string()),
        (target.clone(), "view".to_string()),
    ];
    expected.sort();
    assert_eq!(roles, expected, "a refused call changed the member list");

    assert_eq!(
        remove_member(&app, &successor_token, document_id, &target)
            .await
            .status(),
        204,
        "the remaining editor lost member management"
    );
}

#[tokio::test]
async fn the_last_editor_cannot_be_removed_or_demoted() {
    let app = spawn_app().await;
    let owner = fresh_user();
    let owner_token = platform_token(&owner);
    let document_id = create_document(&app, &owner_token, "sole editor").await;

    let demoted = set_member(&app, &owner_token, document_id, &owner, "view").await;
    assert_eq!(demoted.status(), 400);
    let body: Value = demoted.json().await.expect("json");
    assert_eq!(body["error"], "the last editor cannot be demoted");

    let removed = remove_member(&app, &owner_token, document_id, &owner).await;
    assert_eq!(removed.status(), 400);
    let body: Value = removed.json().await.expect("json");
    assert_eq!(body["error"], "the last editor cannot be removed");

    // a view member is not a replacement, so the rule still holds
    let reader = fresh_user();
    assert_eq!(
        set_member(&app, &owner_token, document_id, &reader, "view")
            .await
            .status(),
        204
    );
    assert_eq!(
        remove_member(&app, &owner_token, document_id, &owner)
            .await
            .status(),
        400
    );

    assert_eq!(
        set_member(&app, &owner_token, document_id, &reader, "edit")
            .await
            .status(),
        204
    );
    assert_eq!(
        set_member(&app, &owner_token, document_id, &owner, "view")
            .await
            .status(),
        204,
        "an editor could not step down with another editor left"
    );

    let reader_token = platform_token(&reader);
    assert_eq!(
        remove_member(&app, &reader_token, document_id, &owner)
            .await
            .status(),
        204
    );
    assert_eq!(
        remove_member(&app, &reader_token, document_id, &reader)
            .await
            .status(),
        400,
        "the document was left with no editor"
    );
    assert_eq!(
        member_roles(&app, &reader_token, document_id).await,
        vec![(reader, "edit".to_string())]
    );
}

#[tokio::test]
async fn a_membership_call_refuses_an_unusable_user_id() {
    let app = spawn_app().await;
    let owner_token = platform_token(&fresh_user());
    let document_id = create_document(&app, &owner_token, "user id bounds").await;

    let too_long = "a".repeat(MAX_USER_ID_BYTES + 1);
    let refused = set_member(&app, &owner_token, document_id, &too_long, "view").await;
    assert_eq!(refused.status(), 400);
    let body: Value = refused.json().await.expect("json");
    assert_eq!(body["error"], "invalid user id");

    let at_the_cap = "a".repeat(MAX_USER_ID_BYTES);
    assert_eq!(
        set_member(&app, &owner_token, document_id, &at_the_cap, "view")
            .await
            .status(),
        204
    );

    let never_a_member = remove_member(&app, &owner_token, document_id, &fresh_user()).await;
    assert_eq!(never_a_member.status(), 404);
}

async fn list_notifications(app: &TestApp, token: &str) -> Value {
    let response = app
        .client
        .get(format!("{}/notifications", app.http_base))
        .bearer_auth(token)
        .send()
        .await
        .expect("list notifications");
    assert_eq!(response.status(), 200);
    response.json().await.expect("json body")
}

async fn mark_notifications_read(app: &TestApp, token: &str, body: Value) -> u16 {
    app.client
        .post(format!("{}/notifications/read", app.http_base))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .expect("mark notifications read")
        .status()
        .as_u16()
}

fn comment_mentioning(author_name: &str, text: &str, mentioned: &[&str]) -> Value {
    let mentions: Vec<Value> = mentioned
        .iter()
        .map(|user_id| json!({"userId": user_id, "name": user_id}))
        .collect();
    json!({
        "authorName": author_name,
        "text": text,
        "createdAt": 1,
        "mentions": mentions
    })
}

#[tokio::test]
async fn a_mention_notifies_the_member_and_nobody_else() {
    let app = spawn_app().await;
    let owner = fresh_user();
    let member = fresh_user();
    let stranger = fresh_user();
    let owner_token = platform_token(&owner);
    let document_id = create_document(&app, &owner_token, "mention map").await;
    assert_eq!(
        set_member(&app, &owner_token, document_id, &member, "view")
            .await
            .status(),
        204
    );

    let mut client = open(&app, document_id, &owner_token, None).await;
    expect_join(&mut client).await;
    // the member twice, the author and a non member: exactly one row comes out
    let comment = comment_mentioning(
        "Ada",
        "look at @this spot",
        &[&member, &member, &owner, &stranger],
    );
    send_and_settle(&mut client, 1, "comments/c1", comment).await;
    client.close().await;

    let notified = list_notifications(&app, &platform_token(&member)).await;
    let entries = notified.as_array().expect("an array");
    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    assert_eq!(entry["docId"], document_id.to_string());
    assert_eq!(entry["docName"], "mention map");
    assert_eq!(entry["commentId"], "c1");
    assert_eq!(entry["authorName"], "Ada");
    assert_eq!(entry["excerpt"], "look at @this spot");
    assert!(entry["readAt"].is_null());
    assert!(entry["createdAt"].is_string());

    for uninvolved in [&owner, &stranger] {
        let empty = list_notifications(&app, &platform_token(uninvolved)).await;
        assert_eq!(empty.as_array().expect("an array").len(), 0, "{uninvolved}");
    }
}

#[tokio::test]
async fn a_rewrite_only_notifies_the_mentions_it_adds() {
    let app = spawn_app().await;
    let owner = fresh_user();
    let first = fresh_user();
    let second = fresh_user();
    let owner_token = platform_token(&owner);
    let document_id = create_document(&app, &owner_token, "resolve map").await;
    for member in [&first, &second] {
        assert_eq!(
            set_member(&app, &owner_token, document_id, member, "edit")
                .await
                .status(),
            204
        );
    }

    let mut client = open(&app, document_id, &owner_token, None).await;
    expect_join(&mut client).await;
    send_and_settle(
        &mut client,
        1,
        "comments/c1",
        comment_mentioning("Ada", "first pass", &[&first]),
    )
    .await;

    // the resolve rewrite keeps the mention list, so nobody is pinged again
    let mut resolved = comment_mentioning("Ada", "first pass", &[&first]);
    resolved["resolved"] = json!(true);
    send_and_settle(&mut client, 2, "comments/c1", resolved).await;
    let first_entries = list_notifications(&app, &platform_token(&first)).await;
    assert_eq!(first_entries.as_array().expect("an array").len(), 1);

    let widened = comment_mentioning("Ada", "second pass", &[&first, &second]);
    send_and_settle(&mut client, 3, "comments/c1", widened).await;
    client.close().await;

    let first_entries = list_notifications(&app, &platform_token(&first)).await;
    assert_eq!(first_entries.as_array().expect("an array").len(), 1);
    let second_entries = list_notifications(&app, &platform_token(&second)).await;
    let second_entries = second_entries.as_array().expect("an array");
    assert_eq!(second_entries.len(), 1);
    assert_eq!(second_entries[0]["excerpt"], "second pass");
}

#[tokio::test]
async fn deleting_a_comment_clears_only_its_unread_notifications() {
    let app = spawn_app().await;
    let owner = fresh_user();
    let member = fresh_user();
    let owner_token = platform_token(&owner);
    let member_token = platform_token(&member);
    let document_id = create_document(&app, &owner_token, "delete map").await;
    assert_eq!(
        set_member(&app, &owner_token, document_id, &member, "view")
            .await
            .status(),
        204
    );

    let mut client = open(&app, document_id, &owner_token, None).await;
    expect_join(&mut client).await;
    send_and_settle(
        &mut client,
        1,
        "comments/kept",
        comment_mentioning("Ada", "kept and read", &[&member]),
    )
    .await;
    assert_eq!(
        mark_notifications_read(&app, &member_token, json!({})).await,
        204
    );
    send_and_settle(
        &mut client,
        2,
        "comments/dropped",
        comment_mentioning("Ada", "dropped unread", &[&member]),
    )
    .await;

    send_and_settle(&mut client, 3, "comments/kept", Value::Null).await;
    send_and_settle(&mut client, 4, "comments/dropped", Value::Null).await;
    client.close().await;

    let entries = list_notifications(&app, &member_token).await;
    let entries = entries.as_array().expect("an array");
    assert_eq!(entries.len(), 1, "only the read notification survives");
    assert_eq!(entries[0]["commentId"], "kept");
    assert!(entries[0]["readAt"].is_string());
}

#[tokio::test]
async fn marking_read_is_scoped_to_the_caller_and_the_ids_given() {
    let app = spawn_app().await;
    let owner = fresh_user();
    let first = fresh_user();
    let second = fresh_user();
    let owner_token = platform_token(&owner);
    let first_token = platform_token(&first);
    let document_id = create_document(&app, &owner_token, "read map").await;
    for member in [&first, &second] {
        assert_eq!(
            set_member(&app, &owner_token, document_id, member, "view")
                .await
                .status(),
            204
        );
    }

    let mut client = open(&app, document_id, &owner_token, None).await;
    expect_join(&mut client).await;
    send_and_settle(
        &mut client,
        1,
        "comments/c1",
        comment_mentioning("Ada", "both of you", &[&first, &second]),
    )
    .await;
    send_and_settle(
        &mut client,
        2,
        "comments/c2",
        comment_mentioning("Ada", "again", &[&first]),
    )
    .await;
    client.close().await;

    let entries = list_notifications(&app, &first_token).await;
    let entries = entries.as_array().expect("an array");
    assert_eq!(entries.len(), 2);
    let one_id = entries[0]["id"].as_str().expect("an id").to_string();

    assert_eq!(
        mark_notifications_read(&app, &first_token, json!({"ids": [one_id]})).await,
        204
    );
    let after_one = list_notifications(&app, &first_token).await;
    let unread: Vec<&Value> = after_one
        .as_array()
        .expect("an array")
        .iter()
        .filter(|entry| entry["readAt"].is_null())
        .collect();
    assert_eq!(unread.len(), 1);

    assert_eq!(
        mark_notifications_read(&app, &first_token, json!({})).await,
        204
    );
    let after_all = list_notifications(&app, &first_token).await;
    assert!(
        after_all
            .as_array()
            .expect("an array")
            .iter()
            .all(|entry| entry["readAt"].is_string())
    );

    let second_entries = list_notifications(&app, &platform_token(&second)).await;
    let second_entries = second_entries.as_array().expect("an array");
    assert_eq!(second_entries.len(), 1);
    assert!(
        second_entries[0]["readAt"].is_null(),
        "another member's marking must not touch these"
    );
}

#[tokio::test]
async fn removing_a_member_removes_their_notifications_for_that_document() {
    let app = spawn_app().await;
    let owner = fresh_user();
    let member = fresh_user();
    let owner_token = platform_token(&owner);
    let document_id = create_document(&app, &owner_token, "removal map").await;
    assert_eq!(
        set_member(&app, &owner_token, document_id, &member, "view")
            .await
            .status(),
        204
    );

    let mut client = open(&app, document_id, &owner_token, None).await;
    expect_join(&mut client).await;
    send_and_settle(
        &mut client,
        1,
        "comments/c1",
        comment_mentioning("Ada", "before removal", &[&member]),
    )
    .await;
    client.close().await;

    assert_eq!(
        remove_member(&app, &owner_token, document_id, &member)
            .await
            .status(),
        204
    );
    let entries = list_notifications(&app, &platform_token(&member)).await;
    assert_eq!(entries.as_array().expect("an array").len(), 0);
}

#[tokio::test]
async fn a_guest_mention_notifies_a_member_but_a_guest_cannot_list() {
    let app = spawn_app().await;
    let owner = fresh_user();
    let owner_token = platform_token(&owner);
    let document_id = create_document(&app, &owner_token, "guest map").await;
    let session_token = guest_session(&app, &owner_token, document_id, "edit").await;

    let mut guest = open(&app, document_id, &session_token, None).await;
    expect_join(&mut guest).await;
    send_and_settle(
        &mut guest,
        1,
        "comments/c1",
        comment_mentioning("guest", "a guest pings the owner", &[&owner]),
    )
    .await;
    guest.close().await;

    let entries = list_notifications(&app, &owner_token).await;
    let entries = entries.as_array().expect("an array");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["authorName"], "guest");

    let refused = app
        .client
        .get(format!("{}/notifications", app.http_base))
        .bearer_auth(&session_token)
        .send()
        .await
        .expect("guest list attempt");
    assert_eq!(refused.status(), 401);
}

/// A one pixel png, so the bytes a test round trips are a real image.
const PNG_BYTES: &[u8] = &[
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4,
    0x89,
];

async fn upload_attachment(
    app: &TestApp,
    token: Option<&str>,
    document_id: Uuid,
    content_type: &str,
    bytes: Vec<u8>,
) -> reqwest::Response {
    let request = app
        .client
        .post(format!(
            "{}/documents/{document_id}/attachments",
            app.http_base
        ))
        .header(reqwest::header::CONTENT_TYPE, content_type)
        .body(bytes);
    let request = match token {
        Some(token) => request.bearer_auth(token),
        None => request,
    };
    request.send().await.expect("upload attachment")
}

async fn upload_png(app: &TestApp, token: &str, document_id: Uuid) -> Value {
    let response = upload_attachment(
        app,
        Some(token),
        document_id,
        "image/png",
        PNG_BYTES.to_vec(),
    )
    .await;
    assert_eq!(response.status(), 201);
    response.json().await.expect("json body")
}

async fn attachment_rows(app: &TestApp, document_id: Uuid) -> Vec<String> {
    sqlx::query_scalar("select token_hash from attachments where doc_id = $1")
        .bind(document_id)
        .fetch_all(&app.state.pool)
        .await
        .expect("read attachments")
}

#[tokio::test]
async fn an_editor_uploads_an_attachment_and_anyone_with_the_url_reads_it() {
    let app = spawn_app().await;
    let owner_token = platform_token(&fresh_user());
    let document_id = create_document(&app, &owner_token, "overlay bitmap").await;

    let created = upload_png(&app, &owner_token, document_id).await;
    let attachment_token = created["token"].as_str().expect("an attachment token");
    assert_eq!(
        created["url"],
        format!("/attachments/{attachment_token}"),
        "the url does not reach the token"
    );

    // no credential at all, which is what an <img src> sends
    let read = app
        .client
        .get(format!(
            "{}{}",
            app.http_base,
            created["url"].as_str().expect("a url")
        ))
        .send()
        .await
        .expect("read attachment");
    assert_eq!(read.status(), 200);
    assert_eq!(read.headers()["content-type"], "image/png");
    assert_eq!(
        read.headers()["cache-control"],
        "public, max-age=31536000, immutable"
    );
    assert_eq!(read.headers()["x-content-type-options"], "nosniff");
    assert_eq!(read.bytes().await.expect("bytes").as_ref(), PNG_BYTES);

    let unknown = app
        .client
        .get(format!("{}/attachments/{}", app.http_base, "made-up-token"))
        .send()
        .await
        .expect("read an unknown attachment");
    assert_eq!(unknown.status(), 404);
}

#[tokio::test]
async fn an_attachment_is_stored_only_as_a_token_hash() {
    let app = spawn_app().await;
    let owner_token = platform_token(&fresh_user());
    let document_id = create_document(&app, &owner_token, "hashed attachment").await;
    let attachment_token = upload_png(&app, &owner_token, document_id).await["token"]
        .as_str()
        .expect("an attachment token")
        .to_string();

    let stored = attachment_rows(&app, document_id).await;
    assert_eq!(stored.len(), 1);
    assert_ne!(
        stored[0], attachment_token,
        "the raw token is in the database"
    );
    assert_eq!(stored[0], capability_token_hash(&attachment_token));

    // a database read hands over the hash, and the hash is not a credential
    let by_hash = app
        .client
        .get(format!("{}/attachments/{}", app.http_base, stored[0]))
        .send()
        .await
        .expect("read by the stored hash");
    assert_eq!(by_hash.status(), 404);
}

#[tokio::test]
async fn only_an_editor_can_upload_an_attachment() {
    let app = spawn_app().await;
    let owner_token = platform_token(&fresh_user());
    let document_id = create_document(&app, &owner_token, "attachment gate").await;

    let reader = fresh_user();
    assert_eq!(
        set_member(&app, &owner_token, document_id, &reader, "view")
            .await
            .status(),
        204
    );
    let refused = upload_attachment(
        &app,
        Some(&platform_token(&reader)),
        document_id,
        "image/png",
        PNG_BYTES.to_vec(),
    )
    .await;
    assert_eq!(refused.status(), 403);

    // a stranger is told the document does not exist, the same as a missing id
    let stranger = upload_attachment(
        &app,
        Some(&platform_token(&fresh_user())),
        document_id,
        "image/png",
        PNG_BYTES.to_vec(),
    )
    .await;
    assert_eq!(stranger.status(), 404);
    let body: Value = stranger.json().await.expect("json");
    assert_eq!(body["error"], "no such document");

    let missing = upload_attachment(
        &app,
        Some(&owner_token),
        Uuid::new_v4(),
        "image/png",
        PNG_BYTES.to_vec(),
    )
    .await;
    assert_eq!(missing.status(), 404);

    let anonymous =
        upload_attachment(&app, None, document_id, "image/png", PNG_BYTES.to_vec()).await;
    assert_eq!(anonymous.status(), 401);

    // a share link session token is not a platform token here either
    let session = guest_session(&app, &owner_token, document_id, "edit").await;
    let guest = upload_attachment(
        &app,
        Some(&session),
        document_id,
        "image/png",
        PNG_BYTES.to_vec(),
    )
    .await;
    assert_eq!(guest.status(), 401);

    assert!(attachment_rows(&app, document_id).await.is_empty());
}

#[tokio::test]
async fn a_content_type_a_browser_would_execute_is_refused() {
    let app = spawn_app().await;
    let owner_token = platform_token(&fresh_user());
    let document_id = create_document(&app, &owner_token, "content type gate").await;

    for content_type in [
        "text/html",
        "image/svg+xml",
        "application/octet-stream",
        "text/plain",
    ] {
        let refused = upload_attachment(
            &app,
            Some(&owner_token),
            document_id,
            content_type,
            b"<script>alert(1)</script>".to_vec(),
        )
        .await;
        assert_eq!(refused.status(), 400, "{content_type} was accepted");
    }

    let empty = upload_attachment(
        &app,
        Some(&owner_token),
        document_id,
        "image/png",
        Vec::new(),
    )
    .await;
    assert_eq!(empty.status(), 400);

    assert!(attachment_rows(&app, document_id).await.is_empty());
}

#[tokio::test]
async fn the_attachment_cap_takes_the_limit_and_refuses_one_byte_past_it() {
    let app = spawn_app().await;
    let owner_token = platform_token(&fresh_user());
    let document_id = create_document(&app, &owner_token, "attachment cap").await;

    let at_the_cap = upload_attachment(
        &app,
        Some(&owner_token),
        document_id,
        "image/png",
        vec![7u8; MAX_ATTACHMENT_BYTES],
    )
    .await;
    assert_eq!(at_the_cap.status(), 201);

    let past_the_cap = upload_attachment(
        &app,
        Some(&owner_token),
        document_id,
        "image/png",
        vec![7u8; MAX_ATTACHMENT_BYTES + 1],
    )
    .await;
    assert_eq!(past_the_cap.status(), 413);

    assert_eq!(
        attachment_rows(&app, document_id).await.len(),
        1,
        "the oversized upload was stored"
    );
}

#[tokio::test]
async fn deleting_a_document_deletes_its_attachments() {
    let app = spawn_app().await;
    let owner_token = platform_token(&fresh_user());
    let document_id = create_document(&app, &owner_token, "attachment cascade").await;
    let url = upload_png(&app, &owner_token, document_id).await["url"]
        .as_str()
        .expect("a url")
        .to_string();

    sqlx::query("delete from documents where id = $1")
        .bind(document_id)
        .execute(&app.state.pool)
        .await
        .expect("delete the document");

    assert!(attachment_rows(&app, document_id).await.is_empty());
    let gone = app
        .client
        .get(format!("{}{url}", app.http_base))
        .send()
        .await
        .expect("read a deleted attachment");
    assert_eq!(gone.status(), 404);
}

/// Point a layer at an attachment, the way an image overlay carries its bitmap.
async fn reference_attachment(app: &TestApp, token: &str, document_id: Uuid, url: &str) {
    let mut client = open(app, document_id, token, None).await;
    expect_join(&mut client).await;
    send_and_settle(&mut client, 1, "layers/overlay", json!({"image": url})).await;
    client.close().await;
}

async fn unreference_attachment(app: &TestApp, token: &str, document_id: Uuid) {
    let mut client = open(app, document_id, token, None).await;
    expect_join(&mut client).await;
    send_and_settle(&mut client, 2, "layers/overlay", Value::Null).await;
    client.close().await;
}

/// Move the liveness stamp into the past, which is how a test reaches the grace
/// period without waiting a week.
async fn age_attachments(app: &TestApp, document_id: Uuid, days: i64) {
    let stamp = time::OffsetDateTime::now_utc() - time::Duration::days(days);
    sqlx::query("update attachments set last_referenced_at = $2 where doc_id = $1")
        .bind(document_id)
        .bind(stamp)
        .execute(&app.state.pool)
        .await
        .expect("age attachments");
}

async fn last_referenced(app: &TestApp, document_id: Uuid) -> Option<time::OffsetDateTime> {
    sqlx::query_scalar("select last_referenced_at from attachments where doc_id = $1")
        .bind(document_id)
        .fetch_optional(&app.state.pool)
        .await
        .expect("read the liveness stamp")
}

async fn sweep(app: &TestApp) {
    agora_server::attachments::sweep(&app.state.pool)
        .await
        .expect("sweep");
}

#[tokio::test]
async fn an_attachment_the_document_points_at_survives_the_sweep() {
    let app = spawn_app().await;
    let owner_token = platform_token(&fresh_user());
    let document_id = create_document(&app, &owner_token, "referenced attachment").await;
    let created = upload_png(&app, &owner_token, document_id).await;
    let url = created["url"].as_str().expect("a url").to_string();
    reference_attachment(&app, &owner_token, document_id, &url).await;

    age_attachments(&app, document_id, ATTACHMENT_GRACE_DAYS + 1).await;
    sweep(&app).await;

    assert_eq!(attachment_rows(&app, document_id).await.len(), 1);
    let read = app
        .client
        .get(format!("{}{url}", app.http_base))
        .send()
        .await
        .expect("read a referenced attachment");
    assert_eq!(read.status(), 200);

    // the sweep found the reference and put the grace period back
    let stamp = last_referenced(&app, document_id).await.expect("a stamp");
    let cutoff = time::OffsetDateTime::now_utc() - time::Duration::days(ATTACHMENT_GRACE_DAYS);
    assert!(stamp > cutoff, "the stamp was left at {stamp}");
}

#[tokio::test]
async fn an_attachment_nothing_points_at_dies_once_the_grace_period_runs_out() {
    let app = spawn_app().await;
    let owner_token = platform_token(&fresh_user());
    let document_id = create_document(&app, &owner_token, "orphaned attachment").await;
    let created = upload_png(&app, &owner_token, document_id).await;
    let url = created["url"].as_str().expect("a url").to_string();
    reference_attachment(&app, &owner_token, document_id, &url).await;
    unreference_attachment(&app, &owner_token, document_id).await;

    age_attachments(&app, document_id, ATTACHMENT_GRACE_DAYS - 1).await;
    sweep(&app).await;
    assert_eq!(
        attachment_rows(&app, document_id).await.len(),
        1,
        "swept inside the grace period"
    );

    age_attachments(&app, document_id, ATTACHMENT_GRACE_DAYS + 1).await;
    sweep(&app).await;
    assert!(attachment_rows(&app, document_id).await.is_empty());

    let gone = app
        .client
        .get(format!("{}{url}", app.http_base))
        .send()
        .await
        .expect("read a swept attachment");
    assert_eq!(gone.status(), 404);
}

#[tokio::test]
async fn a_fresh_upload_survives_the_sweep_before_anything_points_at_it() {
    let app = spawn_app().await;
    let owner_token = platform_token(&fresh_user());
    let document_id = create_document(&app, &owner_token, "unreferenced upload").await;
    let created = upload_png(&app, &owner_token, document_id).await;

    // the op carrying the url has not been written yet, which is the window the
    // upload's own stamp covers
    sweep(&app).await;

    assert_eq!(attachment_rows(&app, document_id).await.len(), 1);
    let read = app
        .client
        .get(format!(
            "{}{}",
            app.http_base,
            created["url"].as_str().expect("a url")
        ))
        .send()
        .await
        .expect("read a fresh attachment");
    assert_eq!(read.status(), 200);
}

/// Short so a role change can be watched landing once the cache lets go, and
/// still long enough that two requests inside one test share an answer.
const TEST_CACHE_TTL: Duration = Duration::from_millis(500);

/// Short so the timeout test does not sit out the production ceiling.
const TEST_PTOLEMY_TIMEOUT: Duration = Duration::from_millis(300);

/// Roles the ptolemy stub hands out, and how it behaves while handing them out.
#[derive(Default)]
struct StubBehaviour {
    roles: HashMap<(Uuid, String), &'static str>,
    /// Answered to every caller the map does not name, which is what makes a
    /// test that must never reach ptolemy fail loudly when it does.
    everyone: Option<&'static str>,
    /// Answered instead of a role, so a test can make ptolemy refuse or break.
    status: Option<u16>,
    /// Sent as a `Location` beside the status, so a test can see whether a
    /// redirect carrying the caller's token would be followed.
    location: Option<String>,
    /// Answers without asking who is calling, which is what lets the far side of
    /// a redirect grant a role it was never handed a token for.
    anyone: bool,
    /// Stalled this long first, so a test can trip the client timeout.
    delay: Option<Duration>,
}

#[derive(Clone)]
struct StubState {
    behaviour: Arc<Mutex<StubBehaviour>>,
    calls: Arc<AtomicUsize>,
}

/// A stand in for ptolemy's project endpoint, the one external boundary the
/// project role resolver crosses.
struct PtolemyStub {
    base_url: String,
    state: StubState,
}

/// Who is asking, read out of the token the resolver forwarded. A request with
/// no usable token gets no subject, which is how a test proves the caller's own
/// credential is what travels.
fn bearer_subject(headers: &axum::http::HeaderMap) -> Option<String> {
    let raw = headers
        .get("authorization")?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")?;
    let claims = jsonwebtoken::decode::<Value>(
        raw,
        &jsonwebtoken::DecodingKey::from_secret(TEST_SECRET.as_bytes()),
        &jsonwebtoken::Validation::new(Algorithm::HS256),
    )
    .ok()?
    .claims;
    claims["sub"].as_str().map(str::to_string)
}

async fn stub_project(
    axum::extract::State(state): axum::extract::State<StubState>,
    axum::extract::Path(project_id): axum::extract::Path<Uuid>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    state.calls.fetch_add(1, Ordering::SeqCst);
    let (status, location, delay, anyone, everyone, roles) = {
        let behaviour = state.behaviour.lock().expect("stub behaviour");
        (
            behaviour.status,
            behaviour.location.clone(),
            behaviour.delay,
            behaviour.anyone,
            behaviour.everyone,
            behaviour.roles.clone(),
        )
    };
    let subject = bearer_subject(&headers);
    if subject.is_none() && !anyone {
        return (axum::http::StatusCode::UNAUTHORIZED, "no usable bearer").into_response();
    }
    let role = subject
        .and_then(|subject| roles.get(&(project_id, subject)).copied())
        .or(everyone);
    if let Some(delay) = delay {
        tokio::time::sleep(delay).await;
    }
    if let Some(status) = status {
        let status = axum::http::StatusCode::from_u16(status).expect("a status code");
        return match location {
            Some(location) => (status, [(axum::http::header::LOCATION, location)]).into_response(),
            None => (status, "the stub was told to refuse").into_response(),
        };
    }
    match role {
        Some(role) => axum::Json(json!({"id": project_id, "role": role})).into_response(),
        // ptolemy answers an error status for a caller who is not a member
        None => (axum::http::StatusCode::FORBIDDEN, "not a member").into_response(),
    }
}

/// A stand in for ptolemy's project listing, which agora asks once per document
/// listing. Answers from the same role map the single project route reads, so a
/// test grants a role in one place.
async fn stub_projects(
    axum::extract::State(state): axum::extract::State<StubState>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    state.calls.fetch_add(1, Ordering::SeqCst);
    let (status, delay, roles) = {
        let behaviour = state.behaviour.lock().expect("stub behaviour");
        (behaviour.status, behaviour.delay, behaviour.roles.clone())
    };
    if let Some(delay) = delay {
        tokio::time::sleep(delay).await;
    }
    if let Some(status) = status {
        let status = axum::http::StatusCode::from_u16(status).expect("a status code");
        return (status, "the stub was told to refuse").into_response();
    }
    let Some(subject) = bearer_subject(&headers) else {
        return (axum::http::StatusCode::UNAUTHORIZED, "no usable bearer").into_response();
    };
    let listed: Vec<Value> = roles
        .iter()
        .filter(|((_, user), _)| *user == subject)
        .map(|((project_id, _), role)| json!({"id": project_id, "role": role}))
        .collect();
    axum::Json(listed).into_response()
}

async fn spawn_ptolemy_stub() -> PtolemyStub {
    let state = StubState {
        behaviour: Arc::new(Mutex::new(StubBehaviour::default())),
        calls: Arc::new(AtomicUsize::new(0)),
    };
    // exactly the pinned path and nothing else, so a resolver asking elsewhere
    // gets a 404 and every project test fails
    let router = axum::Router::new()
        .route("/api/v1/projects", axum::routing::get(stub_projects))
        .route(
            "/api/v1/projects/{project_id}",
            axum::routing::get(stub_project),
        )
        .with_state(state.clone());
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the stub");
    let address = listener.local_addr().expect("stub address");
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    PtolemyStub {
        base_url: format!("http://{address}"),
        state,
    }
}

impl PtolemyStub {
    fn behaviour(&self) -> std::sync::MutexGuard<'_, StubBehaviour> {
        self.state.behaviour.lock().expect("stub behaviour")
    }

    fn grant(&self, project_id: Uuid, user_id: &str, role: &'static str) {
        self.behaviour()
            .roles
            .insert((project_id, user_id.to_string()), role);
    }

    fn revoke(&self, project_id: Uuid, user_id: &str) {
        self.behaviour()
            .roles
            .remove(&(project_id, user_id.to_string()));
    }

    fn grant_everyone(&self, role: &'static str) {
        self.behaviour().everyone = Some(role);
    }

    fn answer_with(&self, status: u16) {
        self.behaviour().status = Some(status);
    }

    fn redirect_to(&self, elsewhere: &PtolemyStub, project_id: Uuid) {
        let mut behaviour = self.behaviour();
        behaviour.status = Some(302);
        behaviour.location = Some(format!(
            "{}/api/v1/projects/{project_id}",
            elsewhere.base_url
        ));
    }

    fn answer_anyone(&self, role: &'static str) {
        let mut behaviour = self.behaviour();
        behaviour.anyone = true;
        behaviour.everyone = Some(role);
    }

    fn stall_past_the_timeout(&self) {
        self.behaviour().delay = Some(TEST_PTOLEMY_TIMEOUT * 4);
    }

    fn calls(&self) -> usize {
        self.state.calls.load(Ordering::SeqCst)
    }
}

async fn spawn_app_with_projects(stub: &PtolemyStub) -> TestApp {
    let auth = AuthConfig::new(TEST_SECRET).expect("test secret is long enough");
    let projects = ProjectAccess::new(&stub.base_url, TEST_CACHE_TTL, TEST_PTOLEMY_TIMEOUT)
        .expect("the stub url is usable");
    serve(AppState::new(test_pool().await, auth).with_projects(projects)).await
}

async fn create_document_in_project(
    app: &TestApp,
    token: &str,
    name: &str,
    project_id: Uuid,
) -> Uuid {
    let response = app
        .client
        .post(format!("{}/documents", app.http_base))
        .bearer_auth(token)
        .json(&json!({"name": name, "projectId": project_id}))
        .send()
        .await
        .expect("create a document in a project");
    assert_eq!(response.status(), 201);
    let body: Value = response.json().await.expect("json body");
    body["id"]
        .as_str()
        .and_then(|id| Uuid::parse_str(id).ok())
        .expect("a document id")
}

async fn set_document_project(
    app: &TestApp,
    token: &str,
    document_id: Uuid,
    project_id: Option<Uuid>,
) -> reqwest::Response {
    app.client
        .put(format!("{}/documents/{document_id}/project", app.http_base))
        .bearer_auth(token)
        .json(&json!({"projectId": project_id}))
        .send()
        .await
        .expect("set the document's project")
}

async fn get_document(app: &TestApp, token: &str, document_id: Uuid) -> reqwest::Response {
    app.client
        .get(format!("{}/documents/{document_id}", app.http_base))
        .bearer_auth(token)
        .send()
        .await
        .expect("get the document")
}

async fn stored_project(app: &TestApp, document_id: Uuid) -> Option<Uuid> {
    sqlx::query_scalar::<_, Option<Uuid>>("select project_id from documents where id = $1")
        .bind(document_id)
        .fetch_one(&app.state.pool)
        .await
        .expect("read the stored project")
}

async fn add_member_directly(app: &TestApp, document_id: Uuid, user_id: &str, role: &str) {
    sqlx::query("insert into members (doc_id, user_id, role) values ($1, $2, $3)")
        .bind(document_id)
        .bind(user_id)
        .bind(role)
        .execute(&app.state.pool)
        .await
        .expect("add a member");
}

#[tokio::test]
async fn a_project_viewer_reads_a_linked_document_but_cannot_edit_it() {
    let stub = spawn_ptolemy_stub().await;
    let app = spawn_app_with_projects(&stub).await;
    let project_id = Uuid::new_v4();
    let owner = fresh_user();
    let reader = fresh_user();
    stub.grant(project_id, &owner, "editor");
    stub.grant(project_id, &reader, "viewer");
    let owner_token = platform_token(&owner);
    let reader_token = platform_token(&reader);

    let document_id =
        create_document_in_project(&app, &owner_token, "project reading", project_id).await;
    assert_eq!(stored_project(&app, document_id).await, Some(project_id));

    assert_eq!(
        get_document(&app, &reader_token, document_id)
            .await
            .status(),
        200
    );
    // the project link is the whole reason they got in: they have no members row
    assert_eq!(
        member_roles(&app, &owner_token, document_id).await,
        vec![(owner.clone(), "edit".to_string())]
    );

    let mut client = open(&app, document_id, &reader_token, None).await;
    let (snapshot, _) = expect_join(&mut client).await;
    assert_eq!(snapshot["role"], "view");
    let reason = send_and_refuse(&mut client, 1, "layers/sneaky", json!({"order": "a0"})).await;
    assert_eq!(reason, "edit role required");

    // and the editor only http routes stay shut
    assert_eq!(
        set_member(&app, &reader_token, document_id, &fresh_user(), "view")
            .await
            .status(),
        403
    );
    assert_eq!(
        mint_link_response(&app, &reader_token, document_id, "view")
            .await
            .status(),
        403
    );
}

async fn mint_link_response(
    app: &TestApp,
    token: &str,
    document_id: Uuid,
    role: &str,
) -> reqwest::Response {
    app.client
        .post(format!("{}/documents/{document_id}/links", app.http_base))
        .bearer_auth(token)
        .json(&json!({"role": role}))
        .send()
        .await
        .expect("mint a link")
}

#[tokio::test]
async fn a_project_editor_and_a_project_owner_both_edit_a_linked_document() {
    let stub = spawn_ptolemy_stub().await;
    let app = spawn_app_with_projects(&stub).await;
    let project_id = Uuid::new_v4();
    let creator = fresh_user();
    let editor = fresh_user();
    let owner = fresh_user();
    stub.grant(project_id, &creator, "editor");
    stub.grant(project_id, &editor, "editor");
    stub.grant(project_id, &owner, "owner");
    let creator_token = platform_token(&creator);

    let document_id =
        create_document_in_project(&app, &creator_token, "project editing", project_id).await;

    for (user, token) in [
        (&editor, platform_token(&editor)),
        (&owner, platform_token(&owner)),
    ] {
        let mut client = open(&app, document_id, &token, None).await;
        let (snapshot, _) = expect_join(&mut client).await;
        assert_eq!(snapshot["role"], "edit", "{user} was not given edit");
        let seq = send_and_settle(
            &mut client,
            1,
            &format!("layers/{user}"),
            json!({"order": "a0"}),
        )
        .await;
        assert!(seq > 0);
        client.close().await;

        // an editor only http route works for them too
        assert_eq!(
            mint_link_response(&app, &token, document_id, "view")
                .await
                .status(),
            201
        );
    }
}

#[tokio::test]
async fn no_membership_and_no_project_role_is_no_such_document() {
    let stub = spawn_ptolemy_stub().await;
    let app = spawn_app_with_projects(&stub).await;
    let project_id = Uuid::new_v4();
    let owner = fresh_user();
    stub.grant(project_id, &owner, "editor");
    let owner_token = platform_token(&owner);
    let document_id = create_document_in_project(&app, &owner_token, "no way in", project_id).await;

    // the stub names nobody else, so ptolemy refuses this caller
    let stranger_token = platform_token(&fresh_user());
    let refused = get_document(&app, &stranger_token, document_id).await;
    assert_eq!(refused.status(), 404);
    let body: Value = refused.json().await.expect("json body");
    assert_eq!(body["error"], "no such document");

    // indistinguishable from a document that was never there
    let missing = get_document(&app, &stranger_token, Uuid::new_v4()).await;
    assert_eq!(missing.status(), 404);
    let missing: Value = missing.json().await.expect("json body");
    assert_eq!(missing["error"], "no such document");

    let refused = connect_with_subprotocol(&app, document_id, &stranger_token, None).await;
    assert_eq!(handshake_status(refused), Some(403));
}

#[tokio::test]
async fn the_members_table_role_wins_when_it_is_wider_than_the_project_role() {
    let stub = spawn_ptolemy_stub().await;
    let app = spawn_app_with_projects(&stub).await;
    let project_id = Uuid::new_v4();
    let owner = fresh_user();
    let member = fresh_user();
    stub.grant(project_id, &owner, "editor");
    // only a reader on the project, but an editor on this one document
    stub.grant(project_id, &member, "viewer");
    let owner_token = platform_token(&owner);
    let member_token = platform_token(&member);

    let document_id =
        create_document_in_project(&app, &owner_token, "members win", project_id).await;
    assert_eq!(
        set_member(&app, &owner_token, document_id, &member, "edit")
            .await
            .status(),
        204
    );

    let mut client = open(&app, document_id, &member_token, None).await;
    let (snapshot, _) = expect_join(&mut client).await;
    assert_eq!(
        snapshot["role"], "edit",
        "a project viewer lost their edit row"
    );
    let seq = send_and_settle(&mut client, 1, "layers/kept", json!({"order": "a0"})).await;
    assert!(seq > 0);
}

#[tokio::test]
async fn a_refusing_ptolemy_leaves_only_the_members_table_role() {
    let stub = spawn_ptolemy_stub().await;
    let app = spawn_app_with_projects(&stub).await;
    let project_id = Uuid::new_v4();
    let owner = fresh_user();
    let project_only = fresh_user();
    let direct = fresh_user();
    stub.grant(project_id, &owner, "editor");
    stub.grant(project_id, &project_only, "editor");
    let owner_token = platform_token(&owner);
    let document_id =
        create_document_in_project(&app, &owner_token, "ptolemy is down", project_id).await;
    add_member_directly(&app, document_id, &direct, "view").await;

    let project_only_token = platform_token(&project_only);
    let direct_token = platform_token(&direct);
    assert_eq!(
        get_document(&app, &project_only_token, document_id)
            .await
            .status(),
        200,
        "the project editor could not get in while ptolemy was healthy"
    );

    stub.answer_with(403);
    // the healthy answer is cached, so wait it out before reading again
    tokio::time::sleep(TEST_CACHE_TTL * 2).await;
    assert_eq!(
        get_document(&app, &project_only_token, document_id)
            .await
            .status(),
        404,
        "a project only caller kept access through a refusal"
    );
    assert_eq!(
        get_document(&app, &direct_token, document_id)
            .await
            .status(),
        200,
        "a direct member lost access to a refusal that was not about them"
    );
}

#[tokio::test]
async fn a_stalled_ptolemy_leaves_only_the_members_table_role() {
    let stub = spawn_ptolemy_stub().await;
    let app = spawn_app_with_projects(&stub).await;
    let project_id = Uuid::new_v4();
    let owner = fresh_user();
    let project_only = fresh_user();
    let direct = fresh_user();
    stub.grant(project_id, &owner, "editor");
    stub.grant(project_id, &project_only, "editor");
    let owner_token = platform_token(&owner);
    let document_id =
        create_document_in_project(&app, &owner_token, "ptolemy is slow", project_id).await;
    add_member_directly(&app, document_id, &direct, "view").await;

    stub.stall_past_the_timeout();
    tokio::time::sleep(TEST_CACHE_TTL * 2).await;

    assert_eq!(
        get_document(&app, &platform_token(&project_only), document_id)
            .await
            .status(),
        404,
        "a project only caller kept access through a timeout"
    );
    assert_eq!(
        get_document(&app, &platform_token(&direct), document_id)
            .await
            .status(),
        200,
        "a direct member lost access to a timeout"
    );
}

#[tokio::test]
async fn linking_a_document_to_a_project_needs_document_edit_and_project_edit() {
    let stub = spawn_ptolemy_stub().await;
    let app = spawn_app_with_projects(&stub).await;
    let project_id = Uuid::new_v4();
    let owner = fresh_user();
    let outsider = fresh_user();
    let owner_token = platform_token(&owner);
    let document_id = create_document(&app, &owner_token, "to be linked").await;

    // an editor on the document who only reads the project cannot pull it in
    stub.grant(project_id, &owner, "viewer");
    let refused = set_document_project(&app, &owner_token, document_id, Some(project_id)).await;
    assert_eq!(refused.status(), 403);
    assert_eq!(stored_project(&app, document_id).await, None);

    // an editor on the project with no role on the document learns nothing
    stub.grant(project_id, &outsider, "owner");
    let refused = set_document_project(
        &app,
        &platform_token(&outsider),
        document_id,
        Some(project_id),
    )
    .await;
    assert_eq!(refused.status(), 404);
    assert_eq!(stored_project(&app, document_id).await, None);

    // both halves, so the link lands and a project reader gets in behind it
    stub.grant(project_id, &owner, "editor");
    let reader = fresh_user();
    stub.grant(project_id, &reader, "viewer");
    let reader_token = platform_token(&reader);
    assert_eq!(
        get_document(&app, &reader_token, document_id)
            .await
            .status(),
        404
    );
    let linked = set_document_project(&app, &owner_token, document_id, Some(project_id)).await;
    assert_eq!(linked.status(), 204);
    assert_eq!(stored_project(&app, document_id).await, Some(project_id));

    let detail = get_document(&app, &reader_token, document_id).await;
    assert_eq!(detail.status(), 200);
    let detail: Value = detail.json().await.expect("json body");
    assert_eq!(detail["projectId"], project_id.to_string());
}

#[tokio::test]
async fn unlinking_a_document_takes_document_edit_alone_and_shuts_the_project_out() {
    let stub = spawn_ptolemy_stub().await;
    let app = spawn_app_with_projects(&stub).await;
    let project_id = Uuid::new_v4();
    let owner = fresh_user();
    let reader = fresh_user();
    stub.grant(project_id, &owner, "editor");
    stub.grant(project_id, &reader, "viewer");
    let owner_token = platform_token(&owner);
    let reader_token = platform_token(&reader);
    let document_id = create_document_in_project(&app, &owner_token, "to be cut", project_id).await;
    assert_eq!(
        get_document(&app, &reader_token, document_id)
            .await
            .status(),
        200
    );

    // dropped to a reader on the project, which is still enough to unlink
    stub.grant(project_id, &owner, "viewer");
    let unlinked = set_document_project(&app, &owner_token, document_id, None).await;
    assert_eq!(unlinked.status(), 204);
    assert_eq!(stored_project(&app, document_id).await, None);

    assert_eq!(
        get_document(&app, &reader_token, document_id)
            .await
            .status(),
        404,
        "an unlinked document still answered a project reader"
    );
    // a caller with no role on the document cannot unlink one either
    assert_eq!(
        set_document_project(&app, &reader_token, document_id, None)
            .await
            .status(),
        404
    );
}

#[tokio::test]
async fn a_project_role_is_reused_until_the_cache_ttl_runs_out() {
    let stub = spawn_ptolemy_stub().await;
    let app = spawn_app_with_projects(&stub).await;
    let project_id = Uuid::new_v4();
    let owner = fresh_user();
    let reader = fresh_user();
    stub.grant(project_id, &owner, "editor");
    stub.grant(project_id, &reader, "viewer");
    let owner_token = platform_token(&owner);
    let reader_token = platform_token(&reader);
    let document_id = create_document_in_project(&app, &owner_token, "cached", project_id).await;

    assert_eq!(
        get_document(&app, &reader_token, document_id)
            .await
            .status(),
        200
    );
    let after_first = stub.calls();

    stub.revoke(project_id, &reader);
    assert_eq!(
        get_document(&app, &reader_token, document_id)
            .await
            .status(),
        200,
        "the cached role was not reused"
    );
    assert_eq!(
        stub.calls(),
        after_first,
        "ptolemy was asked again inside the ttl"
    );

    tokio::time::sleep(TEST_CACHE_TTL * 2).await;
    assert_eq!(
        get_document(&app, &reader_token, document_id)
            .await
            .status(),
        404,
        "a revoked project role outlived the ttl"
    );
    assert!(
        stub.calls() > after_first,
        "ptolemy was never asked again after the ttl"
    );
}

#[tokio::test]
async fn a_share_link_visitor_never_gets_a_project_role() {
    let stub = spawn_ptolemy_stub().await;
    let app = spawn_app_with_projects(&stub).await;
    let project_id = Uuid::new_v4();
    let owner = fresh_user();
    stub.grant(project_id, &owner, "editor");
    // anyone who asks is an owner, so a link visitor that resolved would edit
    stub.grant_everyone("owner");
    let owner_token = platform_token(&owner);
    let document_id =
        create_document_in_project(&app, &owner_token, "shared out", project_id).await;

    let guest_token = guest_session(&app, &owner_token, document_id, "view").await;
    let before_the_guest = stub.calls();

    let mut guest = open(&app, document_id, &guest_token, None).await;
    let (snapshot, _) = expect_join(&mut guest).await;
    assert_eq!(
        snapshot["role"], "view",
        "a link visitor picked up a project role"
    );
    let reason = send_and_refuse(&mut guest, 1, "layers/guest", json!({"order": "a0"})).await;
    assert_eq!(reason, "edit role required");
    assert_eq!(
        stub.calls(),
        before_the_guest,
        "a link visitor was taken to ptolemy"
    );
}

#[tokio::test]
async fn a_document_in_no_project_never_reaches_ptolemy() {
    let stub = spawn_ptolemy_stub().await;
    let app = spawn_app_with_projects(&stub).await;
    stub.grant_everyone("owner");
    let owner_token = platform_token(&fresh_user());
    let document_id = create_document(&app, &owner_token, "unlinked").await;

    assert_eq!(
        get_document(&app, &owner_token, document_id).await.status(),
        200
    );
    let stranger_token = platform_token(&fresh_user());
    assert_eq!(
        get_document(&app, &stranger_token, document_id)
            .await
            .status(),
        404,
        "an unlinked document let a stranger in"
    );
    assert_eq!(
        stub.calls(),
        0,
        "an unlinked document sent the caller to ptolemy"
    );
}

#[tokio::test]
async fn without_a_configured_ptolemy_only_the_members_table_grants_access() {
    let app = spawn_app().await;
    let owner_token = platform_token(&fresh_user());
    let document_id = create_document(&app, &owner_token, "no resolver").await;
    let project_id = Uuid::new_v4();

    // the route refuses to link at all when resolution is off, so there is
    // nothing that could hand out a project role
    let refused = set_document_project(&app, &owner_token, document_id, Some(project_id)).await;
    assert_eq!(refused.status(), 400);

    sqlx::query("update documents set project_id = $2 where id = $1")
        .bind(document_id)
        .bind(project_id)
        .execute(&app.state.pool)
        .await
        .expect("link the document behind the api");

    let stranger_token = platform_token(&fresh_user());
    assert_eq!(
        get_document(&app, &stranger_token, document_id)
            .await
            .status(),
        404,
        "a linked document granted access with no way to check the project"
    );
    assert_eq!(
        get_document(&app, &owner_token, document_id).await.status(),
        200
    );
}

#[tokio::test]
async fn a_scoped_tool_token_gets_no_project_role() {
    let stub = spawn_ptolemy_stub().await;
    let app = spawn_app_with_projects(&stub).await;
    let project_id = Uuid::new_v4();
    let owner = fresh_user();
    stub.grant(project_id, &owner, "editor");
    stub.grant_everyone("owner");
    let owner_token = platform_token(&owner);
    let document_id =
        create_document_in_project(&app, &owner_token, "tool token", project_id).await;

    // a tool token is minted to reach agora, so it is never spent on ptolemy
    let tool = fresh_user();
    let tool_token = tool_token(&tool, &["agora:read", "agora:write"]);
    assert_eq!(
        get_document(&app, &tool_token, document_id).await.status(),
        404,
        "a tool token picked up a project role"
    );

    add_member_directly(&app, document_id, &tool, "view").await;
    assert_eq!(
        get_document(&app, &tool_token, document_id).await.status(),
        200,
        "a tool token lost its members table role"
    );
}

fn tool_token(subject: &str, scopes: &[&str]) -> String {
    let expires_at = time::OffsetDateTime::now_utc().unix_timestamp() + 3600;
    let claims = json!({
        "sub": subject,
        "exp": expires_at,
        "token_use": "tool",
        "scope": scopes,
    });
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(TEST_SECRET.as_bytes()),
    )
    .expect("sign a tool token")
}

#[tokio::test]
async fn a_redirecting_ptolemy_grants_nothing() {
    let stub = spawn_ptolemy_stub().await;
    let app = spawn_app_with_projects(&stub).await;
    let project_id = Uuid::new_v4();
    let owner = fresh_user();
    let project_only = fresh_user();
    stub.grant(project_id, &owner, "editor");
    stub.grant(project_id, &project_only, "owner");
    let owner_token = platform_token(&owner);
    let document_id =
        create_document_in_project(&app, &owner_token, "redirected", project_id).await;

    // somewhere else entirely, handing out owner to anyone who arrives
    let elsewhere = spawn_ptolemy_stub().await;
    elsewhere.answer_anyone("owner");
    stub.redirect_to(&elsewhere, project_id);
    tokio::time::sleep(TEST_CACHE_TTL * 2).await;

    assert_eq!(
        get_document(&app, &platform_token(&project_only), document_id)
            .await
            .status(),
        404,
        "a redirect was followed or taken as an answer"
    );
    assert_eq!(
        elsewhere.calls(),
        0,
        "the caller's token was carried to the redirect target"
    );
}

/// The listing as the caller sees it: document id and the role it reports.
async fn listed_documents(app: &TestApp, token: &str) -> Vec<(Uuid, String)> {
    let response = app
        .client
        .get(format!("{}/documents", app.http_base))
        .bearer_auth(token)
        .send()
        .await
        .expect("list documents");
    assert_eq!(response.status(), 200);
    let body: Vec<Value> = response.json().await.expect("json body");
    body.iter()
        .map(|entry| {
            (
                entry["id"]
                    .as_str()
                    .and_then(|id| Uuid::parse_str(id).ok())
                    .expect("a document id"),
                entry["role"].as_str().expect("a role").to_string(),
            )
        })
        .collect()
}

#[tokio::test]
async fn a_project_member_finds_a_linked_document_in_their_listing() {
    let stub = spawn_ptolemy_stub().await;
    let app = spawn_app_with_projects(&stub).await;
    let project_id = Uuid::new_v4();
    let owner = fresh_user();
    let editor = fresh_user();
    let viewer = fresh_user();
    let outsider = fresh_user();
    stub.grant(project_id, &owner, "owner");
    stub.grant(project_id, &editor, "editor");
    stub.grant(project_id, &viewer, "viewer");
    let owner_token = platform_token(&owner);

    let document_id =
        create_document_in_project(&app, &owner_token, "shared by project", project_id).await;

    // neither of them has a members row: the project link is the whole reason
    assert_eq!(
        member_roles(&app, &owner_token, document_id).await,
        vec![(owner.clone(), "edit".to_string())]
    );
    assert_eq!(
        listed_documents(&app, &platform_token(&editor)).await,
        vec![(document_id, "edit".to_string())]
    );
    assert_eq!(
        listed_documents(&app, &platform_token(&viewer)).await,
        vec![(document_id, "view".to_string())]
    );
    assert_eq!(listed_documents(&app, &platform_token(&outsider)).await, []);
}

#[tokio::test]
async fn a_listing_holds_a_document_once_at_the_wider_of_its_two_roles() {
    let stub = spawn_ptolemy_stub().await;
    let app = spawn_app_with_projects(&stub).await;
    let project_id = Uuid::new_v4();
    let owner = fresh_user();
    let member = fresh_user();
    stub.grant(project_id, &owner, "editor");
    stub.grant(project_id, &member, "editor");
    let owner_token = platform_token(&owner);

    let document_id =
        create_document_in_project(&app, &owner_token, "both ways in", project_id).await;
    // a members row on top of the project role must not list the document twice
    set_member(&app, &owner_token, document_id, &member, "view").await;

    assert_eq!(
        listed_documents(&app, &platform_token(&member)).await,
        vec![(document_id, "edit".to_string())]
    );
}

#[tokio::test]
async fn a_listing_asks_ptolemy_once_however_many_documents_it_holds() {
    let stub = spawn_ptolemy_stub().await;
    let app = spawn_app_with_projects(&stub).await;
    let project_id = Uuid::new_v4();
    let owner = fresh_user();
    let editor = fresh_user();
    stub.grant(project_id, &owner, "editor");
    stub.grant(project_id, &editor, "editor");
    let owner_token = platform_token(&owner);

    for name in ["first", "second", "third"] {
        create_document_in_project(&app, &owner_token, name, project_id).await;
    }

    let before = stub.calls();
    assert_eq!(
        listed_documents(&app, &platform_token(&editor)).await.len(),
        3
    );
    assert_eq!(stub.calls() - before, 1);
}

#[tokio::test]
async fn a_listing_falls_back_to_the_members_table_when_ptolemy_says_nothing() {
    let stub = spawn_ptolemy_stub().await;
    let app = spawn_app_with_projects(&stub).await;
    let project_id = Uuid::new_v4();
    let owner = fresh_user();
    let editor = fresh_user();
    stub.grant(project_id, &owner, "editor");
    stub.grant(project_id, &editor, "editor");
    let owner_token = platform_token(&owner);
    let editor_token = platform_token(&editor);

    let linked = create_document_in_project(&app, &owner_token, "linked", project_id).await;
    let own = create_document(&app, &editor_token, "their own").await;
    assert_eq!(listed_documents(&app, &editor_token).await.len(), 2);

    stub.answer_with(500);
    tokio::time::sleep(TEST_CACHE_TTL * 2).await;

    // the project half is gone, the members row is not
    assert_eq!(
        listed_documents(&app, &editor_token).await,
        vec![(own, "edit".to_string())]
    );
    assert_eq!(
        listed_documents(&app, &owner_token).await,
        vec![(linked, "edit".to_string())]
    );
}

async fn create_feed(
    app: &TestApp,
    token: &str,
    document_id: Uuid,
    name: &str,
    interval_seconds: i64,
) -> reqwest::Response {
    app.client
        .post(format!("{}/documents/{document_id}/feeds", app.http_base))
        .bearer_auth(token)
        .json(&json!({"name": name, "intervalSeconds": interval_seconds}))
        .send()
        .await
        .expect("create feed")
}

/// Register a feed and keep both halves of the reply a producer needs.
async fn feed_credential(
    app: &TestApp,
    token: &str,
    document_id: Uuid,
    interval_seconds: i64,
) -> (Uuid, String) {
    let response = create_feed(app, token, document_id, "sensors", interval_seconds).await;
    assert_eq!(response.status(), 201);
    let body: Value = response.json().await.expect("json body");
    (
        body["id"]
            .as_str()
            .and_then(|id| Uuid::parse_str(id).ok())
            .expect("a feed id"),
        body["token"].as_str().expect("a feed token").to_string(),
    )
}

async fn list_feeds(app: &TestApp, token: &str, document_id: Uuid) -> reqwest::Response {
    app.client
        .get(format!("{}/documents/{document_id}/feeds", app.http_base))
        .bearer_auth(token)
        .send()
        .await
        .expect("list feeds")
}

async fn delete_feed(
    app: &TestApp,
    token: &str,
    document_id: Uuid,
    feed_id: Uuid,
) -> reqwest::Response {
    app.client
        .delete(format!(
            "{}/documents/{document_id}/feeds/{feed_id}",
            app.http_base
        ))
        .bearer_auth(token)
        .send()
        .await
        .expect("delete feed")
}

#[tokio::test]
async fn an_editor_registers_a_feed_lists_it_and_deletes_it() {
    let app = spawn_app().await;
    let owner = fresh_user();
    let owner_token = platform_token(&owner);
    let document_id = create_document(&app, &owner_token, "twins").await;

    let response = create_feed(&app, &owner_token, document_id, "roof sensors", 5).await;
    assert_eq!(response.status(), 201);
    let created: Value = response.json().await.expect("json body");
    assert_eq!(created["name"], "roof sensors");
    assert_eq!(created["intervalSeconds"], 5);
    let feed_id = Uuid::parse_str(created["id"].as_str().expect("a feed id")).expect("a uuid");
    assert!(
        created["token"].as_str().expect("a token").len() > 20,
        "no feed token came back"
    );

    let listed: Value = list_feeds(&app, &owner_token, document_id)
        .await
        .json()
        .await
        .expect("json");
    let listed = listed.as_array().expect("an array").clone();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["id"], created["id"]);
    assert_eq!(listed[0]["name"], "roof sensors");
    assert_eq!(listed[0]["intervalSeconds"], 5);
    assert_eq!(listed[0]["createdBy"], owner.as_str());
    assert!(
        time::OffsetDateTime::parse(
            listed[0]["createdAt"].as_str().expect("a timestamp"),
            &time::format_description::well_known::Rfc3339,
        )
        .is_ok(),
        "createdAt is not rfc 3339"
    );
    assert!(
        listed[0].get("token").is_none(),
        "the listing handed the feed token back"
    );

    assert_eq!(
        delete_feed(&app, &owner_token, document_id, feed_id)
            .await
            .status(),
        204
    );
    let listed: Value = list_feeds(&app, &owner_token, document_id)
        .await
        .json()
        .await
        .expect("json");
    assert!(listed.as_array().expect("an array").is_empty());
}

#[tokio::test]
async fn only_an_editor_registers_or_deletes_a_feed() {
    let app = spawn_app().await;
    let owner_token = platform_token(&fresh_user());
    let document_id = create_document(&app, &owner_token, "twins").await;
    let viewer = fresh_user();
    set_member(&app, &owner_token, document_id, &viewer, "view").await;
    let viewer_token = platform_token(&viewer);
    let (feed_id, _) = feed_credential(&app, &owner_token, document_id, 5).await;

    assert_eq!(
        create_feed(&app, &viewer_token, document_id, "sneaky", 5)
            .await
            .status(),
        403
    );
    assert_eq!(
        delete_feed(&app, &viewer_token, document_id, feed_id)
            .await
            .status(),
        403
    );
    // a viewer still reads the listing
    assert_eq!(
        list_feeds(&app, &viewer_token, document_id).await.status(),
        200
    );

    let stranger_token = platform_token(&fresh_user());
    assert_eq!(
        create_feed(&app, &stranger_token, document_id, "sneaky", 5)
            .await
            .status(),
        404
    );
    assert_eq!(
        list_feeds(&app, &stranger_token, document_id)
            .await
            .status(),
        404
    );
}

#[tokio::test]
async fn a_feed_on_another_document_is_not_found() {
    let app = spawn_app().await;
    let owner_token = platform_token(&fresh_user());
    let mine = create_document(&app, &owner_token, "mine").await;
    let other = create_document(&app, &owner_token, "other").await;
    let (feed_id, _) = feed_credential(&app, &owner_token, mine, 5).await;

    assert_eq!(
        delete_feed(&app, &owner_token, other, feed_id)
            .await
            .status(),
        404
    );
    assert_eq!(
        delete_feed(&app, &owner_token, mine, Uuid::new_v4())
            .await
            .status(),
        404
    );
}

#[tokio::test]
async fn a_feed_name_and_interval_are_bounded() {
    let app = spawn_app().await;
    let owner_token = platform_token(&fresh_user());
    let document_id = create_document(&app, &owner_token, "twins").await;

    for (name, interval) in [
        ("", 5),
        ("   ", 5),
        ("line\nbreak", 5),
        ("ok", 0),
        ("ok", -1),
        ("ok", 3601),
    ] {
        assert_eq!(
            create_feed(&app, &owner_token, document_id, name, interval)
                .await
                .status(),
            400,
            "{name:?} at {interval}"
        );
    }
    let too_long = "a".repeat(MAX_DOCUMENT_NAME_BYTES + 1);
    assert_eq!(
        create_feed(&app, &owner_token, document_id, &too_long, 5)
            .await
            .status(),
        400
    );
    assert_eq!(
        create_feed(&app, &owner_token, document_id, "ok", 3600)
            .await
            .status(),
        201
    );
}

#[tokio::test]
async fn a_feed_token_is_refused_everywhere_a_caller_is_expected() {
    let app = spawn_app().await;
    let owner_token = platform_token(&fresh_user());
    let document_id = create_document(&app, &owner_token, "twins").await;
    let (_, feed_token) = feed_credential(&app, &owner_token, document_id, 5).await;

    assert_eq!(
        get_document(&app, &feed_token, document_id).await.status(),
        401
    );
    assert_eq!(
        list_feeds(&app, &feed_token, document_id).await.status(),
        401
    );
    assert_eq!(
        create_feed(&app, &feed_token, document_id, "another", 5)
            .await
            .status(),
        401
    );
    assert_eq!(
        app.client
            .get(format!("{}/documents", app.http_base))
            .bearer_auth(&feed_token)
            .send()
            .await
            .expect("list documents")
            .status(),
        401
    );
    assert_eq!(
        handshake_status(connect_with_subprotocol(&app, document_id, &feed_token, None).await),
        Some(401),
        "a feed token opened the document socket"
    );
}

/// The ingest handshake, with the feed token in the subprotocol offer.
async fn connect_ingest(
    app: &TestApp,
    token: &str,
) -> Result<(WebsocketClient, Response), WebsocketError> {
    let mut request = format!("{}/feeds/ws", app.websocket_base).into_client_request()?;
    let offer = HeaderValue::from_str(&format!("bearer, {token}")).expect("header value");
    request
        .headers_mut()
        .insert("sec-websocket-protocol", offer);
    let (stream, response) = connect_async(request).await?;
    Ok((WebsocketClient { stream }, response))
}

async fn open_ingest(app: &TestApp, token: &str) -> WebsocketClient {
    connect_ingest(app, token).await.expect("handshake").0
}

fn readings_frame(readings: Vec<Value>) -> Value {
    json!({"type": "readings", "readings": readings})
}

fn reading(asset: &str, kind: &str, value: f64) -> Value {
    json!({"asset": asset, "kind": kind, "value": value})
}

fn reading_at(asset: &str, kind: &str, value: f64, at: &str) -> Value {
    json!({"asset": asset, "kind": kind, "value": value, "at": at})
}

/// Push one frame and settle it, so the readings are stored before the caller
/// reads them back.
async fn ingest_and_settle(producer: &mut WebsocketClient, readings: Vec<Value>) -> usize {
    let count = readings.len();
    producer.send(readings_frame(readings)).await;
    let ack = producer.expect_message("ack").await;
    assert_eq!(ack["count"], count);
    count
}

async fn assets_of(app: &TestApp, token: &str, document_id: Uuid) -> Value {
    let response = app
        .client
        .get(format!("{}/documents/{document_id}/assets", app.http_base))
        .bearer_auth(token)
        .send()
        .await
        .expect("list assets");
    assert_eq!(response.status(), 200);
    response.json().await.expect("json body")
}

async fn assets_at(
    app: &TestApp,
    token: &str,
    document_id: Uuid,
    query: &str,
) -> reqwest::Response {
    app.client
        .get(format!(
            "{}/documents/{document_id}/assets/at?{query}",
            app.http_base
        ))
        .bearer_auth(token)
        .send()
        .await
        .expect("list assets at")
}

/// The one asset in a document that has exactly one.
fn only_asset(body: &Value) -> &Value {
    let assets = body["assets"].as_array().expect("an asset array");
    assert_eq!(assets.len(), 1, "{body}");
    &assets[0]
}

fn value_of(asset: &Value, kind: &str) -> Value {
    asset["values"]
        .as_array()
        .expect("a value array")
        .iter()
        .find(|value| value["kind"] == kind)
        .unwrap_or_else(|| panic!("no {kind} in {asset}"))
        .clone()
}

#[tokio::test]
async fn readings_reach_everyone_on_the_document_and_the_assets_route() {
    let app = spawn_app().await;
    let token = platform_token(&fresh_user());
    let document_id = create_document(&app, &token, "twins").await;
    let (feed_id, feed_token) = feed_credential(&app, &token, document_id, 5).await;

    let mut viewer = open(&app, document_id, &token, None).await;
    expect_join(&mut viewer).await;

    let mut producer = open_ingest(&app, &feed_token).await;
    ingest_and_settle(
        &mut producer,
        vec![
            reading("TWIN-03", "temperature", 21.5),
            reading("TWIN-03", "humidity", 0.4),
        ],
    )
    .await;

    let relayed = viewer.expect_message("readings").await;
    assert_eq!(relayed["feed"], feed_id.to_string());
    let relayed = relayed["readings"].as_array().expect("readings").clone();
    assert_eq!(relayed.len(), 2);
    assert_eq!(relayed[0]["asset"], "TWIN-03");
    assert_eq!(relayed[0]["kind"], "temperature");
    assert_eq!(relayed[0]["value"], 21.5);
    assert!(
        time::OffsetDateTime::parse(
            relayed[0]["at"].as_str().expect("a reading time"),
            &time::format_description::well_known::Rfc3339,
        )
        .is_ok(),
        "a relayed reading time is not rfc 3339"
    );

    // an asset nobody had heard from is reporting now
    let liveness = viewer.expect_message("liveness").await;
    assert_eq!(liveness["asset"], "TWIN-03");
    assert_eq!(liveness["online"], true);

    let body = assets_of(&app, &token, document_id).await;
    let asset = only_asset(&body);
    assert_eq!(asset["asset"], "TWIN-03");
    assert_eq!(asset["feed"], feed_id.to_string());
    assert_eq!(asset["online"], true);
    assert_eq!(value_of(asset, "temperature")["value"], 21.5);
    assert_eq!(value_of(asset, "humidity")["value"], 0.4);
}

#[tokio::test]
async fn the_latest_reading_wins_and_the_history_route_answers_an_earlier_one() {
    let app = spawn_app().await;
    let token = platform_token(&fresh_user());
    let document_id = create_document(&app, &token, "twins").await;
    let (_, feed_token) = feed_credential(&app, &token, document_id, 5).await;
    let mut producer = open_ingest(&app, &feed_token).await;

    ingest_and_settle(
        &mut producer,
        vec![reading_at(
            "TWIN-03",
            "temperature",
            21.5,
            "2026-08-25T12:00:00Z",
        )],
    )
    .await;
    ingest_and_settle(
        &mut producer,
        vec![reading_at(
            "TWIN-03",
            "temperature",
            25.0,
            "2026-08-25T12:00:10Z",
        )],
    )
    .await;

    let body = assets_of(&app, &token, document_id).await;
    assert_eq!(value_of(only_asset(&body), "temperature")["value"], 25.0);

    let earlier: Value = assets_at(&app, &token, document_id, "t=2026-08-25T12:00:05Z")
        .await
        .json()
        .await
        .expect("json body");
    let asset = only_asset(&earlier);
    assert_eq!(value_of(asset, "temperature")["value"], 21.5);
    assert_eq!(value_of(asset, "temperature")["at"], "2026-08-25T12:00:00Z");
    assert_eq!(asset["online"], true, "online is judged against t");

    // before anything was reported the document has no assets at all
    let before: Value = assets_at(&app, &token, document_id, "t=2026-08-25T11:59:59Z")
        .await
        .json()
        .await
        .expect("json body");
    assert!(before["assets"].as_array().expect("an array").is_empty());

    // and far enough after the last reading the asset has gone quiet
    let later: Value = assets_at(&app, &token, document_id, "t=2026-08-25T12:01:00Z")
        .await
        .json()
        .await
        .expect("json body");
    assert_eq!(only_asset(&later)["online"], false);

    for query in ["", "t=", "t=yesterday", "t=1756123200"] {
        assert_eq!(
            assets_at(&app, &token, document_id, query).await.status(),
            400,
            "{query:?}"
        );
    }
}

#[tokio::test]
async fn a_repeated_reading_is_stored_once() {
    let app = spawn_app().await;
    let token = platform_token(&fresh_user());
    let document_id = create_document(&app, &token, "twins").await;
    let (feed_id, feed_token) = feed_credential(&app, &token, document_id, 5).await;
    let mut producer = open_ingest(&app, &feed_token).await;

    let frame = vec![reading_at(
        "TWIN-03",
        "temperature",
        21.5,
        "2026-08-25T12:00:00Z",
    )];
    ingest_and_settle(&mut producer, frame.clone()).await;
    ingest_and_settle(&mut producer, frame).await;

    let stored: i64 = sqlx::query_scalar("select count(*) from readings where feed_id = $1")
        .bind(feed_id)
        .fetch_one(&app.state.pool)
        .await
        .expect("count readings");
    assert_eq!(stored, 1);
}

#[tokio::test]
async fn the_assets_routes_need_a_role_on_the_document() {
    let app = spawn_app().await;
    let token = platform_token(&fresh_user());
    let document_id = create_document(&app, &token, "twins").await;
    let stranger_token = platform_token(&fresh_user());

    assert_eq!(
        app.client
            .get(format!("{}/documents/{document_id}/assets", app.http_base))
            .bearer_auth(&stranger_token)
            .send()
            .await
            .expect("list assets")
            .status(),
        404
    );
    assert_eq!(
        assets_at(&app, &stranger_token, document_id, "t=2026-08-25T12:00:00Z")
            .await
            .status(),
        404
    );
}

#[tokio::test]
async fn a_bad_ingest_frame_closes_the_socket() {
    let app = spawn_app().await;
    let token = platform_token(&fresh_user());
    let document_id = create_document(&app, &token, "twins").await;
    let (_, feed_token) = feed_credential(&app, &token, document_id, 5).await;

    let over_long_asset = readings_frame(vec![reading(&"a".repeat(129), "temperature", 1.0)]);
    for (frame, expected) in [
        ("not json".to_string(), "malformed message"),
        (json!({"type": "nonsense"}).to_string(), "malformed message"),
        (json!("not even an object").to_string(), "malformed message"),
        (
            readings_frame(vec![]).to_string(),
            "frame carries no readings",
        ),
        // a value past f64 never reaches the finite check, since serde_json
        // refuses the number itself
        (
            r#"{"type":"readings","readings":[{"asset":"TWIN-03","kind":"temperature","value":1e400}]}"#
                .to_string(),
            "malformed message",
        ),
        (over_long_asset.to_string(), "invalid asset id"),
        (
            readings_frame(vec![reading("TWIN 03", "temperature", 1.0)]).to_string(),
            "invalid asset id",
        ),
        (
            readings_frame(vec![reading("TWIN-03", "", 1.0)]).to_string(),
            "invalid reading kind",
        ),
        (
            readings_frame(vec![reading_at("TWIN-03", "temperature", 1.0, "yesterday")]).to_string(),
            "invalid reading time",
        ),
    ] {
        let mut producer = open_ingest(&app, &feed_token).await;
        producer.send_text(&frame).await;
        let refusal = producer.expect_message("error").await;
        assert_eq!(refusal["reason"], expected, "{frame}");
        assert!(producer.is_closed().await, "{frame} left the socket open");
    }

    // nothing from any of those frames was stored
    let body = assets_of(&app, &token, document_id).await;
    assert!(body["assets"].as_array().expect("an array").is_empty());
}

#[tokio::test]
async fn an_ingest_frame_past_the_reading_cap_closes_the_socket() {
    let app = spawn_app().await;
    let token = platform_token(&fresh_user());
    let document_id = create_document(&app, &token, "twins").await;
    let (_, feed_token) = feed_credential(&app, &token, document_id, 5).await;

    let over_cap = (0..MAX_FEED_READINGS_PER_FRAME + 1)
        .map(|index| reading(&format!("TWIN-{index}"), "temperature", 1.0))
        .collect();
    let mut producer = open_ingest(&app, &feed_token).await;
    producer.send(readings_frame(over_cap)).await;
    let refusal = producer.expect_message("error").await;
    assert_eq!(refusal["reason"], "too many readings");
    assert!(producer.is_closed().await);

    // the rate limiter charges a frame per reading, so the budget runs out
    // before the frame cap does
    let at_cap: Vec<Value> = (0..MAX_FEED_READINGS_PER_FRAME)
        .map(|index| reading(&format!("TWIN-{index}"), "temperature", 1.0))
        .collect();
    let mut producer = open_ingest(&app, &feed_token).await;
    producer.send(readings_frame(at_cap)).await;
    let refusal = producer.expect_message("error").await;
    assert_eq!(refusal["reason"], "rate limit exceeded");
    assert!(producer.is_closed().await);
}

#[tokio::test]
async fn only_a_feed_token_opens_the_ingest_socket() {
    let app = spawn_app().await;
    let token = platform_token(&fresh_user());
    let document_id = create_document(&app, &token, "twins").await;
    let session_token = guest_session(&app, &token, document_id, "edit").await;
    let tool = tool_token(&fresh_user(), &["agora:read", "agora:write"]);

    for refused in [
        token.clone(),
        session_token,
        tool,
        "not.a.token".to_string(),
    ] {
        assert_eq!(
            handshake_status(connect_ingest(&app, &refused).await),
            Some(401),
            "a token that is not a feed token opened the ingest socket"
        );
    }
    assert_eq!(
        handshake_status(
            connect_async(format!("{}/feeds/ws", app.websocket_base))
                .await
                .map(|(stream, response)| (WebsocketClient { stream }, response))
        ),
        Some(401),
        "the ingest socket opened with no token at all"
    );
}

#[tokio::test]
async fn a_feed_token_reaches_only_its_own_live_feed() {
    let app = spawn_app().await;
    let token = platform_token(&fresh_user());
    let document_id = create_document(&app, &token, "twins").await;
    let other_document_id = create_document(&app, &token, "somewhere else").await;
    let (feed_id, feed_token) = feed_credential(&app, &token, document_id, 5).await;

    // the same feed, claiming to report to a document it is not on
    let forged = encode(
        &Header::new(Algorithm::HS256),
        &json!({
            "sub": feed_id,
            "exp": time::OffsetDateTime::now_utc().unix_timestamp() + 3600,
            "doc": other_document_id,
            "agora_use": "feed"
        }),
        &EncodingKey::from_secret(TEST_SECRET.as_bytes()),
    )
    .expect("sign a forged feed token");
    assert_eq!(
        handshake_status(connect_ingest(&app, &forged).await),
        Some(401)
    );

    // a feed that never existed
    let unknown = encode(
        &Header::new(Algorithm::HS256),
        &json!({
            "sub": Uuid::new_v4(),
            "exp": time::OffsetDateTime::now_utc().unix_timestamp() + 3600,
            "doc": document_id,
            "agora_use": "feed"
        }),
        &EncodingKey::from_secret(TEST_SECRET.as_bytes()),
    )
    .expect("sign an unknown feed token");
    assert_eq!(
        handshake_status(connect_ingest(&app, &unknown).await),
        Some(401)
    );

    // the real one works until the feed is deleted
    open_ingest(&app, &feed_token).await.close().await;
    assert_eq!(
        delete_feed(&app, &token, document_id, feed_id)
            .await
            .status(),
        204
    );
    assert_eq!(
        handshake_status(connect_ingest(&app, &feed_token).await),
        Some(401)
    );
}

#[tokio::test]
async fn deleting_a_feed_closes_a_socket_still_holding_its_token() {
    let app = spawn_app().await;
    let token = platform_token(&fresh_user());
    let document_id = create_document(&app, &token, "twins").await;
    let (feed_id, feed_token) = feed_credential(&app, &token, document_id, 5).await;

    let mut producer = open_ingest(&app, &feed_token).await;
    ingest_and_settle(&mut producer, vec![reading("TWIN-03", "temperature", 21.5)]).await;

    assert_eq!(
        delete_feed(&app, &token, document_id, feed_id)
            .await
            .status(),
        204
    );
    producer
        .send(readings_frame(vec![reading(
            "TWIN-03",
            "temperature",
            22.0,
        )]))
        .await;
    let refusal = producer.expect_message("error").await;
    assert_eq!(refusal["reason"], "feed revoked");
    assert!(producer.is_closed().await);

    // the readings went with the feed
    let body = assets_of(&app, &token, document_id).await;
    assert!(body["assets"].as_array().expect("an array").is_empty());
}

#[tokio::test]
async fn a_join_after_readings_gets_the_assets_before_the_peers() {
    let app = spawn_app().await;
    let token = platform_token(&fresh_user());
    let document_id = create_document(&app, &token, "twins").await;
    let (feed_id, feed_token) = feed_credential(&app, &token, document_id, 5).await;

    let mut producer = open_ingest(&app, &feed_token).await;
    ingest_and_settle(&mut producer, vec![reading("TWIN-03", "temperature", 21.5)]).await;

    let mut client = open(&app, document_id, &token, None).await;
    client.expect_message("snapshot").await;
    let assets = client.expect_message("assets").await;
    client.expect_message("watches").await;
    let asset = only_asset(&assets);
    assert_eq!(asset["asset"], "TWIN-03");
    assert_eq!(asset["feed"], feed_id.to_string());
    assert_eq!(asset["online"], true);
    assert_eq!(value_of(asset, "temperature")["value"], 21.5);
    client.expect_message("peers").await;
}

/// Readings written straight into the table at a chosen age, which is how a
/// retention test gets old rows without waiting for them.
async fn age_readings(app: &TestApp, feed_id: Uuid, asset: &str, days_ago: i64) {
    sqlx::query(
        "insert into readings (feed_id, asset_id, kind, at, value)
         values ($1, $2, 'temperature', now() - make_interval(days => $3::int), 1.0)",
    )
    .bind(feed_id)
    .bind(asset)
    .bind(i32::try_from(days_ago).expect("a day count"))
    .execute(&app.state.pool)
    .await
    .expect("insert an aged reading");
}

async fn stored_assets(app: &TestApp, feed_id: Uuid) -> Vec<String> {
    sqlx::query_scalar("select asset_id from readings where feed_id = $1 order by asset_id")
        .bind(feed_id)
        .fetch_all(&app.state.pool)
        .await
        .expect("read back the readings")
}

#[tokio::test]
async fn an_asset_that_stops_reporting_goes_offline_and_comes_back_on_the_next_reading() {
    let app = spawn_app().await;
    let token = platform_token(&fresh_user());
    let document_id = create_document(&app, &token, "twins").await;
    let (_, feed_token) = feed_credential(&app, &token, document_id, 1).await;

    let mut viewer = open(&app, document_id, &token, None).await;
    expect_join(&mut viewer).await;
    let mut producer = open_ingest(&app, &feed_token).await;
    ingest_and_settle(&mut producer, vec![reading("TWIN-03", "temperature", 21.5)]).await;
    viewer.expect_message("readings").await;
    assert_eq!(viewer.expect_message("liveness").await["online"], true);

    // an interval of one second and three missed reports, so four seconds on
    // means it has gone quiet. the clock is handed in rather than waited out.
    let quiet_at = time::OffsetDateTime::now_utc() + time::Duration::seconds(4);
    agora_server::assets::mark_stale(&app.state.rooms, quiet_at).await;

    let gone = viewer.expect_message("liveness").await;
    assert_eq!(gone["asset"], "TWIN-03");
    assert_eq!(gone["online"], false);
    assert!(
        time::OffsetDateTime::parse(
            gone["at"].as_str().expect("a time"),
            &time::format_description::well_known::Rfc3339,
        )
        .is_ok()
    );

    agora_server::assets::mark_stale(&app.state.rooms, quiet_at).await;
    assert!(
        viewer.try_next_message().await.is_none(),
        "an asset already offline was marked offline again"
    );

    // the route agrees with the frame the room sent
    let body = assets_of(&app, &token, document_id).await;
    assert_eq!(only_asset(&body)["online"], true, "it is not stale yet");

    ingest_and_settle(&mut producer, vec![reading("TWIN-03", "temperature", 22.0)]).await;
    viewer.expect_message("readings").await;
    let back = viewer.expect_message("liveness").await;
    assert_eq!(back["asset"], "TWIN-03");
    assert_eq!(back["online"], true);
}

#[tokio::test]
async fn a_room_that_loads_after_an_asset_went_quiet_starts_it_offline() {
    let app = spawn_app().await;
    let token = platform_token(&fresh_user());
    let document_id = create_document(&app, &token, "twins").await;
    let (feed_id, _) = feed_credential(&app, &token, document_id, 1).await;
    age_readings(&app, feed_id, "TWIN-03", 1).await;

    let mut client = open(&app, document_id, &token, None).await;
    client.expect_message("snapshot").await;
    let assets = client.expect_message("assets").await;
    client.expect_message("watches").await;
    assert_eq!(only_asset(&assets)["online"], false);
    client.expect_message("peers").await;

    // and the stale pass has nothing left to say about it
    agora_server::assets::mark_stale(&app.state.rooms, time::OffsetDateTime::now_utc()).await;
    assert!(client.try_next_message().await.is_none());
}

#[tokio::test]
async fn the_sweep_deletes_readings_past_the_retention_window() {
    let _background = background_lock().await;
    let app = spawn_app().await;
    let token = platform_token(&fresh_user());
    let document_id = create_document(&app, &token, "twins").await;
    let (feed_id, _) = feed_credential(&app, &token, document_id, 5).await;

    age_readings(&app, feed_id, "old", READINGS_RETENTION_DAYS + 1).await;
    age_readings(&app, feed_id, "recent", READINGS_RETENTION_DAYS - 1).await;
    assert_eq!(stored_assets(&app, feed_id).await, vec!["old", "recent"]);

    agora_server::assets::sweep(&app.state.pool)
        .await
        .expect("sweep readings");
    assert_eq!(stored_assets(&app, feed_id).await, vec!["recent"]);
}

/// A body serde cannot deserialize reaches axum's `Json` rejection, which is
/// 422, the same answer a missing field already gets. A query string reaches
/// the `Query` rejection instead, which is 400.
const UNKNOWN_BODY_KEY_STATUS: u16 = 422;
const UNKNOWN_QUERY_KEY_STATUS: u16 = 400;

async fn status_of(request: reqwest::RequestBuilder) -> u16 {
    request.send().await.expect("send").status().as_u16()
}

/// The bug DESIGN_TODO records: a client sending `project_id` where the server
/// reads `projectId` used to create a document with no project and say nothing.
#[tokio::test]
async fn an_unknown_key_on_create_document_is_refused() {
    let app = spawn_app().await;
    let token = platform_token(&fresh_user());
    assert_eq!(
        status_of(
            app.client
                .post(format!("{}/documents", app.http_base))
                .bearer_auth(&token)
                .json(&json!({"name": "twins", "project_id": Uuid::new_v4()}))
        )
        .await,
        UNKNOWN_BODY_KEY_STATUS
    );
}

#[tokio::test]
async fn an_unknown_key_on_set_document_project_is_refused() {
    let app = spawn_app().await;
    let token = platform_token(&fresh_user());
    let document_id = create_document(&app, &token, "twins").await;
    assert_eq!(
        status_of(
            app.client
                .put(format!("{}/documents/{document_id}/project", app.http_base))
                .bearer_auth(&token)
                .json(&json!({"projectId": null, "project_id": null}))
        )
        .await,
        UNKNOWN_BODY_KEY_STATUS
    );
}

#[tokio::test]
async fn an_unknown_key_on_set_member_is_refused() {
    let app = spawn_app().await;
    let token = platform_token(&fresh_user());
    let document_id = create_document(&app, &token, "twins").await;
    let member = fresh_user();
    assert_eq!(
        status_of(
            app.client
                .put(format!(
                    "{}/documents/{document_id}/members/{member}",
                    app.http_base
                ))
                .bearer_auth(&token)
                .json(&json!({"role": "edit", "expiresAt": "2027-01-01T00:00:00Z"}))
        )
        .await,
        UNKNOWN_BODY_KEY_STATUS
    );
}

#[tokio::test]
async fn an_unknown_key_on_create_link_is_refused() {
    let app = spawn_app().await;
    let token = platform_token(&fresh_user());
    let document_id = create_document(&app, &token, "twins").await;
    assert_eq!(
        status_of(
            app.client
                .post(format!("{}/documents/{document_id}/links", app.http_base))
                .bearer_auth(&token)
                .json(&json!({"role": "view", "uses": 1}))
        )
        .await,
        UNKNOWN_BODY_KEY_STATUS
    );
}

#[tokio::test]
async fn an_unknown_key_on_create_feed_is_refused() {
    let app = spawn_app().await;
    let token = platform_token(&fresh_user());
    let document_id = create_document(&app, &token, "twins").await;
    assert_eq!(
        status_of(
            app.client
                .post(format!("{}/documents/{document_id}/feeds", app.http_base))
                .bearer_auth(&token)
                .json(&json!({"name": "sensors", "intervalSeconds": 5, "interval_seconds": 5}))
        )
        .await,
        UNKNOWN_BODY_KEY_STATUS
    );
}

#[tokio::test]
async fn an_unknown_key_on_mark_notifications_read_is_refused() {
    let app = spawn_app().await;
    let token = platform_token(&fresh_user());
    assert_eq!(
        status_of(
            app.client
                .post(format!("{}/notifications/read", app.http_base))
                .bearer_auth(&token)
                .json(&json!({"ids": [], "all": true}))
        )
        .await,
        UNKNOWN_BODY_KEY_STATUS
    );
}

#[tokio::test]
async fn an_unknown_query_key_on_assets_at_is_refused() {
    let app = spawn_app().await;
    let token = platform_token(&fresh_user());
    let document_id = create_document(&app, &token, "twins").await;
    let at = "2026-08-25T12:00:00Z";
    assert_eq!(
        status_of(
            app.client
                .get(format!(
                    "{}/documents/{document_id}/assets/at?t={at}",
                    app.http_base
                ))
                .bearer_auth(&token)
        )
        .await,
        200
    );
    assert_eq!(
        status_of(
            app.client
                .get(format!(
                    "{}/documents/{document_id}/assets/at?t={at}&cacheBust=1",
                    app.http_base
                ))
                .bearer_auth(&token)
        )
        .await,
        UNKNOWN_QUERY_KEY_STATUS
    );
}

/// Both socket queries are refused before the token is read, so an unknown key
/// answers 400 rather than the 401 an anonymous handshake gets.
#[tokio::test]
async fn an_unknown_query_key_on_either_socket_is_refused() {
    let app = spawn_app().await;
    let token = platform_token(&fresh_user());
    let document_id = create_document(&app, &token, "twins").await;

    for url in [
        format!(
            "{}/ws?doc={document_id}&token={token}&cacheBust=1",
            app.websocket_base
        ),
        format!("{}/feeds/ws?token={token}&cacheBust=1", app.websocket_base),
    ] {
        assert_eq!(
            handshake_status(
                connect_async(url.clone())
                    .await
                    .map(|(stream, response)| (WebsocketClient { stream }, response))
            ),
            Some(UNKNOWN_QUERY_KEY_STATUS),
            "{url}"
        );
    }
}

// ── Region watches ────────────────────────────────────────────────────────

/// The one layer the geoplumb stub serves, so a watch naming anything else is
/// an unknown layer.
const STUB_LAYER: &str = "hillshade";

/// The reduction the stub answers with unless a test says otherwise.
const STUB_COUNT: i64 = 4096;
const STUB_MEAN: f64 = 0.31;

/// A stand in for geoplumb, the one external boundary a watch crosses.
struct GeoplumbStub {
    base_url: String,
    state: GeoplumbStubState,
}

#[derive(Clone)]
struct GeoplumbStubState {
    row: Arc<Mutex<Value>>,
    /// Set to answer this status instead of reducing anything.
    status: Arc<Mutex<Option<u16>>>,
    /// Every zonal body the stub was sent, so a test can pin the request shape.
    bodies: Arc<Mutex<Vec<Value>>>,
}

async fn stub_layers() -> axum::Json<Value> {
    axum::Json(json!([{"name": STUB_LAYER, "source": "cog", "collection": null}]))
}

async fn stub_zonal(
    axum::extract::State(state): axum::extract::State<GeoplumbStubState>,
    axum::extract::Path(layer): axum::extract::Path<String>,
    axum::Json(body): axum::Json<Value>,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    state.bodies.lock().expect("stub bodies").push(body);
    if layer != STUB_LAYER {
        return (
            axum::http::StatusCode::NOT_FOUND,
            format!("unknown layer {layer}"),
        )
            .into_response();
    }
    if let Some(status) = *state.status.lock().expect("stub status") {
        let status = axum::http::StatusCode::from_u16(status).expect("a status code");
        return (status, "the stub was told to refuse").into_response();
    }
    let row = state.row.lock().expect("stub row").clone();
    axum::Json(json!({"rows": [row]})).into_response()
}

async fn spawn_geoplumb_stub() -> GeoplumbStub {
    let state = GeoplumbStubState {
        row: Arc::new(Mutex::new(json!({
            "id": 0,
            "count": STUB_COUNT,
            "sum": 1269.76,
            "minimum": 0.1,
            "maximum": 0.9,
            "mean": STUB_MEAN
        }))),
        status: Arc::new(Mutex::new(None)),
        bodies: Arc::new(Mutex::new(Vec::new())),
    };
    // exactly the pinned paths and nothing else, so a client asking elsewhere
    // gets a 404 and every watch test fails
    let router = axum::Router::new()
        .route("/layers", axum::routing::get(stub_layers))
        .route("/zonal/{layer}", axum::routing::post(stub_zonal))
        .with_state(state.clone());
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the stub");
    let address = listener.local_addr().expect("stub address");
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    GeoplumbStub {
        base_url: format!("http://{address}"),
        state,
    }
}

impl GeoplumbStub {
    fn answer_with(&self, status: u16) {
        *self.state.status.lock().expect("stub status") = Some(status);
    }

    fn reduce_to(&self, row: Value) {
        *self.state.row.lock().expect("stub row") = row;
    }

    fn zonal_bodies(&self) -> Vec<Value> {
        self.state.bodies.lock().expect("stub bodies").clone()
    }
}

/// The scheduler and the readings sweep both walk the whole database rather
/// than one document, the way the background tasks in the binary do, so one
/// test drives one of them at a time and never two at once.
///
/// A test that asserts a watch has *not* run holds this too: without it another
/// test's tick reaches its watch, since a fresh watch is due the moment it is
/// stored.
static BACKGROUND: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn background_lock() -> tokio::sync::MutexGuard<'static, ()> {
    BACKGROUND.lock().await
}

/// Sort this watch ahead of every leftover in the shared database, so one tick
/// is certain to reach it.
async fn make_watch_oldest(app: &TestApp, watch_id: Uuid) {
    sqlx::query("update watches set created_at = to_timestamp(0) where id = $1")
        .bind(watch_id)
        .execute(&app.state.pool)
        .await
        .expect("age the watch");
}

/// Put the watch's last run far enough back that its interval has run out.
async fn make_watch_due(app: &TestApp, watch_id: Uuid) {
    sqlx::query("update watches set last_run_at = to_timestamp(0) where id = $1")
        .bind(watch_id)
        .execute(&app.state.pool)
        .await
        .expect("make the watch due");
}

async fn watch_run_state(
    app: &TestApp,
    watch_id: Uuid,
) -> (Option<time::OffsetDateTime>, Option<String>) {
    let row = sqlx::query("select last_run_at, last_error from watches where id = $1")
        .bind(watch_id)
        .fetch_one(&app.state.pool)
        .await
        .expect("read the watch");
    (
        row.try_get("last_run_at").expect("last_run_at"),
        row.try_get("last_error").expect("last_error"),
    )
}

/// Postgres keeps microseconds and `OffsetDateTime::now_utc` carries
/// nanoseconds, so a stored run time is the one handed in, truncated.
fn is_the_same_moment(stored: Option<time::OffsetDateTime>, now: time::OffsetDateTime) -> bool {
    stored.is_some_and(|stored| (now - stored).abs() < time::Duration::microseconds(1))
}

async fn stored_readings(app: &TestApp, watch_id: Uuid) -> i64 {
    sqlx::query_scalar("select count(*) from watch_readings where watch_id = $1")
        .bind(watch_id)
        .fetch_one(&app.state.pool)
        .await
        .expect("count the readings")
}

/// The wait before a retried delivery. Milliseconds, so the attempts a test
/// counts do not cost it seconds.
const TEST_WEBHOOK_BACKOFF: Duration = Duration::from_millis(5);

/// Every webhook receiver in this suite is a loopback port, which is what the
/// binary refuses, so the tests are the one caller that reaches one.
async fn spawn_app_with_geoplumb(stub: &GeoplumbStub) -> TestApp {
    let auth = AuthConfig::new(TEST_SECRET).expect("test secret is long enough");
    let geoplumb = Geoplumb::new(&stub.base_url).expect("the stub url is usable");
    serve(
        AppState::new(test_pool().await, auth)
            .with_geoplumb(geoplumb)
            .with_webhooks(Webhooks::new(TEST_WEBHOOK_BACKOFF, PrivateHosts::Allowed)),
    )
    .await
}

/// The same app the binary runs: a webhook naming the platform's own network
/// is refused.
async fn spawn_app_refusing_private_webhooks(stub: &GeoplumbStub) -> TestApp {
    let auth = AuthConfig::new(TEST_SECRET).expect("test secret is long enough");
    let geoplumb = Geoplumb::new(&stub.base_url).expect("the stub url is usable");
    serve(AppState::new(test_pool().await, auth).with_geoplumb(geoplumb)).await
}

fn region() -> Value {
    json!({
        "type": "Polygon",
        "coordinates": [[[0.0, 0.0], [0.1, 0.0], [0.1, 0.1], [0.0, 0.0]]]
    })
}

fn watch_body() -> Value {
    json!({
        "name": "reservoir",
        "layer": STUB_LAYER,
        "region": region(),
        "reducer": "mean",
        "intervalSeconds": MIN_WATCH_INTERVAL_SECONDS,
    })
}

async fn create_watch(
    app: &TestApp,
    token: &str,
    document_id: Uuid,
    body: &Value,
) -> reqwest::Response {
    app.client
        .post(format!("{}/documents/{document_id}/watches", app.http_base))
        .bearer_auth(token)
        .json(body)
        .send()
        .await
        .expect("create watch")
}

async fn created_watch(app: &TestApp, token: &str, document_id: Uuid, body: &Value) -> Uuid {
    let response = create_watch(app, token, document_id, body).await;
    assert_eq!(response.status(), 201);
    let created: Value = response.json().await.expect("json body");
    Uuid::parse_str(created["id"].as_str().expect("a watch id")).expect("a uuid")
}

async fn list_watches(app: &TestApp, token: &str, document_id: Uuid) -> reqwest::Response {
    app.client
        .get(format!("{}/documents/{document_id}/watches", app.http_base))
        .bearer_auth(token)
        .send()
        .await
        .expect("list watches")
}

async fn delete_watch(
    app: &TestApp,
    token: &str,
    document_id: Uuid,
    watch_id: Uuid,
) -> reqwest::Response {
    app.client
        .delete(format!(
            "{}/documents/{document_id}/watches/{watch_id}",
            app.http_base
        ))
        .bearer_auth(token)
        .send()
        .await
        .expect("delete watch")
}

async fn list_watch_readings(
    app: &TestApp,
    token: &str,
    document_id: Uuid,
    watch_id: Uuid,
    query: &str,
) -> reqwest::Response {
    app.client
        .get(format!(
            "{}/documents/{document_id}/watches/{watch_id}/readings{query}",
            app.http_base
        ))
        .bearer_auth(token)
        .send()
        .await
        .expect("list watch readings")
}

#[tokio::test]
async fn an_editor_creates_a_watch_lists_it_and_deletes_it() {
    let stub = spawn_geoplumb_stub().await;
    let app = spawn_app_with_geoplumb(&stub).await;
    let owner = fresh_user();
    let owner_token = platform_token(&owner);
    let document_id = create_document(&app, &owner_token, "basin").await;

    let response = create_watch(&app, &owner_token, document_id, &watch_body()).await;
    assert_eq!(response.status(), 201);
    let created: Value = response.json().await.expect("json body");
    assert_eq!(created["name"], "reservoir");
    assert_eq!(created["layer"], STUB_LAYER);
    assert_eq!(created["reducer"], "mean");
    assert_eq!(created["intervalSeconds"], MIN_WATCH_INTERVAL_SECONDS);
    assert_eq!(created["region"], region());
    assert_eq!(created["createdBy"], owner.as_str());
    assert_eq!(created["thresholdOp"], Value::Null);
    assert_eq!(created["lastRunAt"], Value::Null);
    assert_eq!(created["lastError"], Value::Null);
    let watch_id = Uuid::parse_str(created["id"].as_str().expect("a watch id")).expect("a uuid");

    let listed: Value = list_watches(&app, &owner_token, document_id)
        .await
        .json()
        .await
        .expect("json");
    let listed = listed.as_array().expect("an array").clone();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["id"], created["id"]);

    assert_eq!(
        delete_watch(&app, &owner_token, document_id, watch_id)
            .await
            .status(),
        204
    );
    let listed: Value = list_watches(&app, &owner_token, document_id)
        .await
        .json()
        .await
        .expect("json");
    assert!(listed.as_array().expect("an array").is_empty());
}

#[tokio::test]
async fn only_an_editor_creates_or_deletes_a_watch() {
    let stub = spawn_geoplumb_stub().await;
    let app = spawn_app_with_geoplumb(&stub).await;
    let owner_token = platform_token(&fresh_user());
    let document_id = create_document(&app, &owner_token, "basin").await;
    let viewer = fresh_user();
    set_member(&app, &owner_token, document_id, &viewer, "view").await;
    let viewer_token = platform_token(&viewer);
    let watch_id = created_watch(&app, &owner_token, document_id, &watch_body()).await;

    assert_eq!(
        create_watch(&app, &viewer_token, document_id, &watch_body())
            .await
            .status(),
        403
    );
    assert_eq!(
        delete_watch(&app, &viewer_token, document_id, watch_id)
            .await
            .status(),
        403
    );
    // a viewer still reads the listing and the history
    assert_eq!(
        list_watches(&app, &viewer_token, document_id)
            .await
            .status(),
        200
    );
    assert_eq!(
        list_watch_readings(&app, &viewer_token, document_id, watch_id, "")
            .await
            .status(),
        200
    );

    let stranger_token = platform_token(&fresh_user());
    assert_eq!(
        create_watch(&app, &stranger_token, document_id, &watch_body())
            .await
            .status(),
        404
    );
    assert_eq!(
        list_watches(&app, &stranger_token, document_id)
            .await
            .status(),
        404
    );
    assert_eq!(
        list_watch_readings(&app, &stranger_token, document_id, watch_id, "")
            .await
            .status(),
        404
    );
}

#[tokio::test]
async fn the_webhook_reaches_an_editor_and_nobody_else() {
    let stub = spawn_geoplumb_stub().await;
    let app = spawn_app_with_geoplumb(&stub).await;
    let owner_token = platform_token(&fresh_user());
    let document_id = create_document(&app, &owner_token, "basin").await;
    let viewer = fresh_user();
    set_member(&app, &owner_token, document_id, &viewer, "view").await;
    let viewer_token = platform_token(&viewer);

    let mut body = watch_body();
    body["webhookUrl"] = json!("https://hooks.example.test/basin");
    body["webhookSecret"] = json!("a shared signing secret");
    let response = create_watch(&app, &owner_token, document_id, &body).await;
    assert_eq!(response.status(), 201);
    let created: Value = response.json().await.expect("json body");
    assert_eq!(created["webhookUrl"], "https://hooks.example.test/basin");
    assert_eq!(created["webhookSecret"], "a shared signing secret");

    let seen_by_editor: Value = list_watches(&app, &owner_token, document_id)
        .await
        .json()
        .await
        .expect("json");
    assert_eq!(
        seen_by_editor[0]["webhookUrl"],
        "https://hooks.example.test/basin"
    );

    let seen_by_viewer: Value = list_watches(&app, &viewer_token, document_id)
        .await
        .json()
        .await
        .expect("json");
    assert!(
        seen_by_viewer[0].get("webhookUrl").is_none(),
        "a viewer was handed the webhook url"
    );
    assert!(
        seen_by_viewer[0].get("webhookSecret").is_none(),
        "a viewer was handed the webhook secret"
    );
    assert_eq!(seen_by_viewer[0]["name"], "reservoir");
}

#[tokio::test]
async fn a_watch_naming_a_layer_geoplumb_does_not_serve_is_refused() {
    let stub = spawn_geoplumb_stub().await;
    let app = spawn_app_with_geoplumb(&stub).await;
    let owner_token = platform_token(&fresh_user());
    let document_id = create_document(&app, &owner_token, "basin").await;

    let mut body = watch_body();
    body["layer"] = json!("no-such-layer");
    let response = create_watch(&app, &owner_token, document_id, &body).await;
    assert_eq!(response.status(), 422);
    let refusal: Value = response.json().await.expect("json body");
    assert!(
        refusal["error"]
            .as_str()
            .expect("a reason")
            .contains("no-such-layer"),
        "the refusal did not name the layer: {refusal}"
    );
}

#[tokio::test]
async fn a_watch_is_refused_when_geoplumb_is_not_configured() {
    let app = spawn_app().await;
    let owner_token = platform_token(&fresh_user());
    let document_id = create_document(&app, &owner_token, "basin").await;
    assert_eq!(
        create_watch(&app, &owner_token, document_id, &watch_body())
            .await
            .status(),
        400
    );
}

#[tokio::test]
async fn a_watch_name_layer_region_interval_threshold_and_webhook_are_bounded() {
    let stub = spawn_geoplumb_stub().await;
    let app = spawn_app_with_geoplumb(&stub).await;
    let owner_token = platform_token(&fresh_user());
    let document_id = create_document(&app, &owner_token, "basin").await;

    let mut refused = Vec::new();
    for (field, value) in [
        ("name", json!("")),
        ("name", json!("   ")),
        ("name", json!("line\nbreak")),
        ("name", json!("a".repeat(MAX_DOCUMENT_NAME_BYTES + 1))),
        ("layer", json!("")),
        ("layer", json!("../etc/passwd")),
        ("layer", json!("two words")),
        ("intervalSeconds", json!(MIN_WATCH_INTERVAL_SECONDS - 1)),
        ("intervalSeconds", json!(0)),
        ("intervalSeconds", json!(-60)),
        (
            "region",
            json!({"type": "Point", "coordinates": [0.0, 0.0]}),
        ),
        (
            "region",
            json!({"type": "Polygon", "coordinates": [[[0.0, 0.0], [1.0, 0.0]]]}),
        ),
        (
            "region",
            json!({"type": "Polygon", "coordinates": [[[181.0, 0.0], [1.0, 0.0], [1.0, 1.0], [181.0, 0.0]]]}),
        ),
        ("thresholdOp", json!("gt")),
        ("webhookUrl", json!("file:///etc/passwd")),
        ("webhookUrl", json!("not a url")),
        ("webhookSecret", json!("")),
    ] {
        let mut body = watch_body();
        body[field] = value.clone();
        let status = create_watch(&app, &owner_token, document_id, &body)
            .await
            .status()
            .as_u16();
        if status != 400 {
            refused.push(format!("{field} = {value} answered {status}"));
        }
    }
    assert!(refused.is_empty(), "{refused:?}");

    // a threshold needs both halves, and then it is taken
    let mut body = watch_body();
    body["thresholdOp"] = json!("gt");
    body["thresholdValue"] = json!(0.4);
    let response = create_watch(&app, &owner_token, document_id, &body).await;
    assert_eq!(response.status(), 201);
    let created: Value = response.json().await.expect("json body");
    assert_eq!(created["thresholdOp"], "gt");
    assert_eq!(created["thresholdValue"], 0.4);
}

#[tokio::test]
async fn a_region_past_the_position_cap_is_refused() {
    let stub = spawn_geoplumb_stub().await;
    let app = spawn_app_with_geoplumb(&stub).await;
    let owner_token = platform_token(&fresh_user());
    let document_id = create_document(&app, &owner_token, "basin").await;

    let ring: Vec<Value> = (0..=MAX_REGION_POSITIONS)
        .map(|index| json!([(index % 90) as f64 * 0.001, 0.0]))
        .collect();
    let mut body = watch_body();
    body["region"] = json!({"type": "Polygon", "coordinates": [ring]});
    assert_eq!(
        create_watch(&app, &owner_token, document_id, &body)
            .await
            .status(),
        400
    );
}

#[tokio::test]
async fn a_reducer_or_threshold_operator_outside_the_set_is_refused() {
    let stub = spawn_geoplumb_stub().await;
    let app = spawn_app_with_geoplumb(&stub).await;
    let owner_token = platform_token(&fresh_user());
    let document_id = create_document(&app, &owner_token, "basin").await;

    let mut body = watch_body();
    body["reducer"] = json!("median");
    assert_eq!(
        create_watch(&app, &owner_token, document_id, &body)
            .await
            .status(),
        UNKNOWN_BODY_KEY_STATUS
    );

    let mut body = watch_body();
    body["thresholdOp"] = json!("ge");
    body["thresholdValue"] = json!(1.0);
    assert_eq!(
        create_watch(&app, &owner_token, document_id, &body)
            .await
            .status(),
        UNKNOWN_BODY_KEY_STATUS
    );
}

#[tokio::test]
async fn an_unknown_key_on_create_watch_is_refused() {
    let stub = spawn_geoplumb_stub().await;
    let app = spawn_app_with_geoplumb(&stub).await;
    let token = platform_token(&fresh_user());
    let document_id = create_document(&app, &token, "basin").await;

    let mut body = watch_body();
    body["interval_seconds"] = json!(MIN_WATCH_INTERVAL_SECONDS);
    assert_eq!(
        create_watch(&app, &token, document_id, &body)
            .await
            .status(),
        UNKNOWN_BODY_KEY_STATUS
    );
}

#[tokio::test]
async fn a_watch_on_another_document_is_not_found() {
    let stub = spawn_geoplumb_stub().await;
    let app = spawn_app_with_geoplumb(&stub).await;
    let owner_token = platform_token(&fresh_user());
    let mine = create_document(&app, &owner_token, "mine").await;
    let other = create_document(&app, &owner_token, "other").await;
    let watch_id = created_watch(&app, &owner_token, mine, &watch_body()).await;

    assert_eq!(
        delete_watch(&app, &owner_token, other, watch_id)
            .await
            .status(),
        404
    );
    assert_eq!(
        delete_watch(&app, &owner_token, mine, Uuid::new_v4())
            .await
            .status(),
        404
    );
    assert_eq!(
        list_watch_readings(&app, &owner_token, other, watch_id, "")
            .await
            .status(),
        404
    );
}

#[tokio::test]
async fn a_watch_history_starts_empty_and_bounds_its_query() {
    // this asserts a watch has not run, and a tick runs every due watch in the
    // database, so it holds the lock for as long as the watch exists
    let _background = background_lock().await;
    let stub = spawn_geoplumb_stub().await;
    let app = spawn_app_with_geoplumb(&stub).await;
    let owner_token = platform_token(&fresh_user());
    let document_id = create_document(&app, &owner_token, "basin").await;
    let watch_id = created_watch(&app, &owner_token, document_id, &watch_body()).await;

    let response = list_watch_readings(&app, &owner_token, document_id, watch_id, "").await;
    assert_eq!(response.status(), 200);
    let readings: Value = response.json().await.expect("json");
    assert!(readings.as_array().expect("an array").is_empty());

    for query in [
        "?since=yesterday",
        "?limit=0",
        &format!("?limit={}", MAX_WATCH_READINGS_PAGE + 1),
    ] {
        assert_eq!(
            list_watch_readings(&app, &owner_token, document_id, watch_id, query)
                .await
                .status(),
            400,
            "{query}"
        );
    }
    assert_eq!(
        list_watch_readings(
            &app,
            &owner_token,
            document_id,
            watch_id,
            "?since=2026-08-30T00:00:00Z&limit=10"
        )
        .await
        .status(),
        200
    );
    assert_eq!(
        list_watch_readings(&app, &owner_token, document_id, watch_id, "?cacheBust=1")
            .await
            .status(),
        UNKNOWN_QUERY_KEY_STATUS
    );
}

/// A guest holds a session token and never a platform one, so every watch route
/// answers them exactly what `POST /documents` does.
#[tokio::test]
async fn a_session_token_reaches_no_watch_route() {
    let stub = spawn_geoplumb_stub().await;
    let app = spawn_app_with_geoplumb(&stub).await;
    let owner_token = platform_token(&fresh_user());
    let document_id = create_document(&app, &owner_token, "basin").await;
    let watch_id = created_watch(&app, &owner_token, document_id, &watch_body()).await;
    let session = guest_session(&app, &owner_token, document_id, "edit").await;

    let baseline = app
        .client
        .post(format!("{}/documents", app.http_base))
        .bearer_auth(&session)
        .json(&json!({"name": "not allowed"}))
        .send()
        .await
        .expect("create attempt")
        .status()
        .as_u16();
    assert_eq!(baseline, 401);

    assert_eq!(
        create_watch(&app, &session, document_id, &watch_body())
            .await
            .status(),
        baseline
    );
    assert_eq!(
        list_watches(&app, &session, document_id).await.status(),
        baseline
    );
    assert_eq!(
        delete_watch(&app, &session, document_id, watch_id)
            .await
            .status(),
        baseline
    );
    assert_eq!(
        list_watch_readings(&app, &session, document_id, watch_id, "")
            .await
            .status(),
        baseline
    );
}

#[tokio::test]
async fn a_join_carries_the_documents_watches_and_never_their_webhooks() {
    let stub = spawn_geoplumb_stub().await;
    let app = spawn_app_with_geoplumb(&stub).await;
    let owner_token = platform_token(&fresh_user());
    let document_id = create_document(&app, &owner_token, "basin").await;
    let mut body = watch_body();
    body["webhookUrl"] = json!("https://hooks.example.test/basin");
    body["webhookSecret"] = json!("a shared signing secret");
    let watch_id = created_watch(&app, &owner_token, document_id, &body).await;
    let guest_token = guest_session(&app, &owner_token, document_id, "view").await;

    let mut guest = open(&app, document_id, &guest_token, None).await;
    guest.expect_message("snapshot").await;
    guest.expect_message("assets").await;
    let frame = guest.expect_message("watches").await;

    let watches = frame["watches"].as_array().expect("a watch array");
    assert_eq!(watches.len(), 1);
    assert_eq!(watches[0]["id"], watch_id.to_string());
    assert_eq!(watches[0]["name"], "reservoir");
    assert_eq!(watches[0]["layer"], STUB_LAYER);
    assert_eq!(watches[0]["reducer"], "mean");
    assert_eq!(watches[0]["region"], region());
    let rendered = frame.to_string();
    assert!(
        !rendered.contains("webhook") && !rendered.contains("signing secret"),
        "the watches frame carried a webhook: {rendered}"
    );
}

#[tokio::test]
async fn a_due_watch_stores_a_reading_and_relays_it_to_the_room() {
    let _background = background_lock().await;
    let stub = spawn_geoplumb_stub().await;
    let app = spawn_app_with_geoplumb(&stub).await;
    let owner_token = platform_token(&fresh_user());
    let document_id = create_document(&app, &owner_token, "basin").await;
    let watch_id = created_watch(&app, &owner_token, document_id, &watch_body()).await;
    make_watch_oldest(&app, watch_id).await;

    let mut client = open(&app, document_id, &owner_token, None).await;
    expect_join(&mut client).await;

    let now = time::OffsetDateTime::now_utc();
    assert!(run_due(&app.state, now).await >= 1);

    let frame = client.expect_message("watchReading").await;
    assert_eq!(frame["watch"], watch_id.to_string());
    assert_eq!(frame["value"], STUB_MEAN);
    assert_eq!(frame["count"], STUB_COUNT);
    assert_eq!(frame["tripped"], false);

    let readings: Value = list_watch_readings(&app, &owner_token, document_id, watch_id, "")
        .await
        .json()
        .await
        .expect("json");
    let readings = readings.as_array().expect("an array").clone();
    assert_eq!(readings.len(), 1);
    assert_eq!(readings[0]["value"], STUB_MEAN);
    assert_eq!(readings[0]["count"], STUB_COUNT);

    let (last_run_at, last_error) = watch_run_state(&app, watch_id).await;
    assert!(is_the_same_moment(last_run_at, now), "{last_run_at:?}");
    assert_eq!(last_error, None);

    // the body geoplumb was sent is the one feature collection its zonal
    // endpoint reads. a tick runs every due watch in the database, so this
    // stub may have been asked about more than the one this test made
    let bodies = stub.zonal_bodies();
    let sent = bodies
        .iter()
        .find(|body| body["features"][0]["geometry"] == region())
        .expect("the region was never reduced");
    assert_eq!(sent["type"], "FeatureCollection");
    assert_eq!(sent["features"].as_array().expect("features").len(), 1);
    assert_eq!(sent["features"][0]["type"], "Feature");
    assert_eq!(sent["features"][0]["properties"], json!({}));
    assert!(sent["resolution"].as_f64().expect("a resolution") > 0.0);
    assert!(sent.get("t").is_none(), "the run pinned a time window");

    // a second tick at the same moment leaves it alone: its interval has not
    // run out
    run_due(&app.state, now).await;
    assert_eq!(stored_readings(&app, watch_id).await, 1);
}

#[tokio::test]
async fn a_watch_runs_again_once_its_interval_has_run_out() {
    let _background = background_lock().await;
    let stub = spawn_geoplumb_stub().await;
    let app = spawn_app_with_geoplumb(&stub).await;
    let owner_token = platform_token(&fresh_user());
    let document_id = create_document(&app, &owner_token, "basin").await;
    let watch_id = created_watch(&app, &owner_token, document_id, &watch_body()).await;
    make_watch_oldest(&app, watch_id).await;

    run_due(&app.state, time::OffsetDateTime::now_utc()).await;
    assert_eq!(stored_readings(&app, watch_id).await, 1);

    make_watch_due(&app, watch_id).await;
    run_due(&app.state, time::OffsetDateTime::now_utc()).await;
    assert_eq!(stored_readings(&app, watch_id).await, 2);
}

#[tokio::test]
async fn a_refusing_geoplumb_lands_in_last_error_and_stores_no_reading() {
    let _background = background_lock().await;
    let stub = spawn_geoplumb_stub().await;
    let app = spawn_app_with_geoplumb(&stub).await;
    let owner_token = platform_token(&fresh_user());
    let document_id = create_document(&app, &owner_token, "basin").await;
    let watch_id = created_watch(&app, &owner_token, document_id, &watch_body()).await;
    make_watch_oldest(&app, watch_id).await;
    stub.answer_with(503);

    let now = time::OffsetDateTime::now_utc();
    run_due(&app.state, now).await;

    assert_eq!(stored_readings(&app, watch_id).await, 0);
    let (last_run_at, last_error) = watch_run_state(&app, watch_id).await;
    // the run is marked so the watch retries on its own interval and not on
    // every tick
    assert!(is_the_same_moment(last_run_at, now), "{last_run_at:?}");
    assert!(
        last_error.expect("a reason").contains("503"),
        "the failure was not recorded"
    );

    // the next run clears it
    stub.reduce_to(
        json!({"id": 0, "count": 8, "mean": 0.5, "sum": 4.0, "minimum": 0.5, "maximum": 0.5}),
    );
    *stub.state.status.lock().expect("stub status") = None;
    make_watch_due(&app, watch_id).await;
    run_due(&app.state, time::OffsetDateTime::now_utc()).await;
    let (_, last_error) = watch_run_state(&app, watch_id).await;
    assert_eq!(last_error, None);
    assert_eq!(stored_readings(&app, watch_id).await, 1);
}

#[tokio::test]
async fn a_region_that_caught_no_pixels_records_a_failure_rather_than_a_reading() {
    let _background = background_lock().await;
    let stub = spawn_geoplumb_stub().await;
    let app = spawn_app_with_geoplumb(&stub).await;
    let owner_token = platform_token(&fresh_user());
    let document_id = create_document(&app, &owner_token, "basin").await;
    let watch_id = created_watch(&app, &owner_token, document_id, &watch_body()).await;
    make_watch_oldest(&app, watch_id).await;
    // what geoplumb answers for a zone that caught nothing: a count and no
    // statistics, since json has no NaN
    stub.reduce_to(json!({
        "id": 0, "count": 0, "sum": null, "minimum": null, "maximum": null, "mean": null
    }));

    run_due(&app.state, time::OffsetDateTime::now_utc()).await;
    assert_eq!(stored_readings(&app, watch_id).await, 0);
    let (_, last_error) = watch_run_state(&app, watch_id).await;
    assert!(last_error.expect("a reason").contains("no pixels"));
}

#[tokio::test]
async fn a_watch_keeps_only_its_newest_readings() {
    let _background = background_lock().await;
    let stub = spawn_geoplumb_stub().await;
    let app = spawn_app_with_geoplumb(&stub).await;
    let owner_token = platform_token(&fresh_user());
    let document_id = create_document(&app, &owner_token, "basin").await;
    let watch_id = created_watch(&app, &owner_token, document_id, &watch_body()).await;
    make_watch_oldest(&app, watch_id).await;

    // fill the watch to its cap, oldest first, so the run below is one past it
    sqlx::query(
        "insert into watch_readings (watch_id, at, value, count)
         select $1, now() - (step || ' seconds')::interval, 1.0, 1
         from generate_series(1, $2) as step",
    )
    .bind(watch_id)
    .bind(MAX_READINGS_PER_WATCH)
    .execute(&app.state.pool)
    .await
    .expect("fill the watch");
    assert_eq!(
        stored_readings(&app, watch_id).await,
        MAX_READINGS_PER_WATCH
    );
    let oldest: time::OffsetDateTime =
        sqlx::query_scalar("select min(at) from watch_readings where watch_id = $1")
            .bind(watch_id)
            .fetch_one(&app.state.pool)
            .await
            .expect("the oldest reading");

    run_due(&app.state, time::OffsetDateTime::now_utc()).await;

    assert_eq!(
        stored_readings(&app, watch_id).await,
        MAX_READINGS_PER_WATCH,
        "the cap did not hold"
    );
    let still_oldest: time::OffsetDateTime =
        sqlx::query_scalar("select min(at) from watch_readings where watch_id = $1")
            .bind(watch_id)
            .fetch_one(&app.state.pool)
            .await
            .expect("the oldest reading");
    assert!(
        still_oldest > oldest,
        "the oldest reading survived the insert past the cap"
    );
}

#[tokio::test]
async fn the_sweep_deletes_watch_readings_past_the_retention_window() {
    let _background = background_lock().await;
    let stub = spawn_geoplumb_stub().await;
    let app = spawn_app_with_geoplumb(&stub).await;
    let owner_token = platform_token(&fresh_user());
    let document_id = create_document(&app, &owner_token, "basin").await;
    let watch_id = created_watch(&app, &owner_token, document_id, &watch_body()).await;

    sqlx::query(
        "insert into watch_readings (watch_id, at, value, count)
         values ($1, now() - ($2 || ' days')::interval, 1.0, 1), ($1, now(), 2.0, 2)",
    )
    .bind(watch_id)
    .bind(READINGS_RETENTION_DAYS + 1)
    .execute(&app.state.pool)
    .await
    .expect("store readings");
    assert_eq!(stored_readings(&app, watch_id).await, 2);

    agora_server::assets::sweep(&app.state.pool)
        .await
        .expect("sweep");
    assert_eq!(stored_readings(&app, watch_id).await, 1);
}

/// One webhook post as the receiver saw it.
#[derive(Clone)]
struct Delivered {
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

#[derive(Clone)]
struct ReceiverState {
    delivered: Arc<Mutex<Vec<Delivered>>>,
    status: Arc<Mutex<u16>>,
}

/// A webhook receiver, and what it was sent.
struct Receiver {
    url: String,
    state: ReceiverState,
}

async fn receive_hook(
    axum::extract::State(state): axum::extract::State<ReceiverState>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> axum::http::StatusCode {
    let headers = headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_lowercase(), value.to_string()))
        })
        .collect();
    state.delivered.lock().expect("delivered").push(Delivered {
        headers,
        body: body.to_vec(),
    });
    axum::http::StatusCode::from_u16(*state.status.lock().expect("receiver status"))
        .expect("a status code")
}

async fn spawn_receiver() -> Receiver {
    let state = ReceiverState {
        delivered: Arc::new(Mutex::new(Vec::new())),
        status: Arc::new(Mutex::new(204)),
    };
    let router = axum::Router::new()
        .route("/hook", axum::routing::post(receive_hook))
        .with_state(state.clone());
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the receiver");
    let address = listener.local_addr().expect("receiver address");
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    Receiver {
        url: format!("http://{address}/hook"),
        state,
    }
}

impl Receiver {
    fn answer_with(&self, status: u16) {
        *self.state.status.lock().expect("receiver status") = status;
    }

    fn delivered(&self) -> Vec<Delivered> {
        self.state.delivered.lock().expect("delivered").clone()
    }
}

/// A watch over a threshold, which is what a trip needs.
fn watch_over(threshold: f64) -> Value {
    let mut body = watch_body();
    body["thresholdOp"] = json!("gt");
    body["thresholdValue"] = json!(threshold);
    body
}

fn reduction(mean: f64) -> Value {
    json!({"id": 0, "count": 16, "sum": mean * 16.0, "minimum": mean, "maximum": mean, "mean": mean})
}

/// Run the watch once over this reading.
async fn run_reading(app: &TestApp, stub: &GeoplumbStub, watch_id: Uuid, mean: f64) {
    stub.reduce_to(reduction(mean));
    make_watch_due(app, watch_id).await;
    run_due(&app.state, time::OffsetDateTime::now_utc()).await;
}

/// How many times this watch has told the document's members it tripped.
async fn trip_notifications(app: &TestApp, watch_id: Uuid) -> i64 {
    sqlx::query_scalar("select count(*) from notifications where watch_id = $1")
        .bind(watch_id)
        .fetch_one(&app.state.pool)
        .await
        .expect("count the notifications")
}

#[tokio::test]
async fn a_watch_trips_when_it_crosses_and_not_again_while_it_stays_over() {
    let _background = background_lock().await;
    let stub = spawn_geoplumb_stub().await;
    let app = spawn_app_with_geoplumb(&stub).await;
    let owner = fresh_user();
    let owner_token = platform_token(&owner);
    let document_id = create_document(&app, &owner_token, "basin").await;
    let watch_id = created_watch(&app, &owner_token, document_id, &watch_over(1.0)).await;
    make_watch_oldest(&app, watch_id).await;

    // under the line, so nothing to say
    stub.reduce_to(reduction(0.5));
    run_due(&app.state, time::OffsetDateTime::now_utc()).await;
    assert_eq!(trip_notifications(&app, watch_id).await, 0);

    // over it, which is the crossing
    run_reading(&app, &stub, watch_id, 2.0).await;
    assert_eq!(trip_notifications(&app, watch_id).await, 1);

    // still over, so nothing crossed
    run_reading(&app, &stub, watch_id, 3.0).await;
    assert_eq!(trip_notifications(&app, watch_id).await, 1);

    // back under, and over again, which is a second crossing
    run_reading(&app, &stub, watch_id, 0.5).await;
    assert_eq!(trip_notifications(&app, watch_id).await, 1);
    run_reading(&app, &stub, watch_id, 2.5).await;
    assert_eq!(trip_notifications(&app, watch_id).await, 2);

    assert_eq!(stored_readings(&app, watch_id).await, 5);
}

#[tokio::test]
async fn a_trip_notifies_every_member_and_lists_cleanly() {
    let _background = background_lock().await;
    let stub = spawn_geoplumb_stub().await;
    let app = spawn_app_with_geoplumb(&stub).await;
    let owner = fresh_user();
    let owner_token = platform_token(&owner);
    let document_id = create_document(&app, &owner_token, "basin").await;
    let viewer = fresh_user();
    set_member(&app, &owner_token, document_id, &viewer, "view").await;
    let viewer_token = platform_token(&viewer);
    let stranger_token = platform_token(&fresh_user());
    let watch_id = created_watch(&app, &owner_token, document_id, &watch_over(1.0)).await;
    make_watch_oldest(&app, watch_id).await;

    stub.reduce_to(reduction(2.0));
    run_due(&app.state, time::OffsetDateTime::now_utc()).await;

    for token in [&owner_token, &viewer_token] {
        let listed = list_notifications(&app, token).await;
        let listed = listed.as_array().expect("an array");
        assert_eq!(listed.len(), 1, "{listed:?}");
        assert_eq!(listed[0]["watchId"], watch_id.to_string());
        assert_eq!(listed[0]["commentId"], Value::Null);
        assert_eq!(listed[0]["authorName"], "reservoir");
        assert_eq!(listed[0]["docName"], "basin");
        assert_eq!(listed[0]["excerpt"], "reservoir: mean 2 gt 1");
        assert_eq!(listed[0]["readAt"], Value::Null);
    }
    assert!(
        list_notifications(&app, &stranger_token)
            .await
            .as_array()
            .expect("an array")
            .is_empty(),
        "a stranger was notified"
    );

    // and deleting the watch takes them with it
    assert_eq!(
        delete_watch(&app, &owner_token, document_id, watch_id)
            .await
            .status(),
        204
    );
    assert!(
        list_notifications(&app, &owner_token)
            .await
            .as_array()
            .expect("an array")
            .is_empty()
    );
}

#[tokio::test]
async fn a_trip_posts_a_signed_webhook() {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let _background = background_lock().await;
    let stub = spawn_geoplumb_stub().await;
    let app = spawn_app_with_geoplumb(&stub).await;
    let receiver = spawn_receiver().await;
    let owner_token = platform_token(&fresh_user());
    let document_id = create_document(&app, &owner_token, "basin").await;

    let secret = "a shared signing secret";
    let mut body = watch_over(1.0);
    body["webhookUrl"] = json!(receiver.url);
    body["webhookSecret"] = json!(secret);
    let watch_id = created_watch(&app, &owner_token, document_id, &body).await;
    make_watch_oldest(&app, watch_id).await;

    stub.reduce_to(reduction(2.0));
    let now = time::OffsetDateTime::now_utc();
    run_due(&app.state, now).await;

    let delivered = receiver.delivered();
    assert_eq!(delivered.len(), 1);
    let posted = &delivered[0];
    assert_eq!(
        posted.headers.get("x-agora-event").map(String::as_str),
        Some("watch.tripped")
    );
    assert!(
        Uuid::parse_str(
            posted
                .headers
                .get("x-agora-delivery")
                .expect("a delivery id")
        )
        .is_ok(),
        "the delivery id is not a uuid"
    );

    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("any key length");
    mac.update(&posted.body);
    let expected = format!("sha256={}", hex_of(&mac.finalize().into_bytes()));
    assert_eq!(
        posted.headers.get("x-agora-signature").map(String::as_str),
        Some(expected.as_str()),
        "the signature does not cover the body that arrived"
    );

    let event: Value = serde_json::from_slice(&posted.body).expect("json body");
    assert_eq!(event["event"], "watch.tripped");
    assert!(
        time::OffsetDateTime::parse(
            event["occurredAt"].as_str().expect("a time"),
            &time::format_description::well_known::Rfc3339,
        )
        .is_ok()
    );
    assert_eq!(event["data"]["watchId"], watch_id.to_string());
    assert_eq!(event["data"]["documentId"], document_id.to_string());
    assert_eq!(event["data"]["name"], "reservoir");
    assert_eq!(event["data"]["layer"], STUB_LAYER);
    assert_eq!(event["data"]["reducer"], "mean");
    assert_eq!(event["data"]["value"], 2.0);
    assert_eq!(event["data"]["count"], 16);
    assert!(event["data"]["at"].as_str().is_some());

    let (_, last_error) = watch_run_state(&app, watch_id).await;
    assert_eq!(last_error, None, "a delivered webhook left an error");
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[tokio::test]
async fn a_webhook_that_refuses_is_retried_and_leaves_the_reading_alone() {
    let _background = background_lock().await;
    let stub = spawn_geoplumb_stub().await;
    let app = spawn_app_with_geoplumb(&stub).await;
    let receiver = spawn_receiver().await;
    receiver.answer_with(500);
    let owner_token = platform_token(&fresh_user());
    let document_id = create_document(&app, &owner_token, "basin").await;

    let mut body = watch_over(1.0);
    body["webhookUrl"] = json!(receiver.url);
    let watch_id = created_watch(&app, &owner_token, document_id, &body).await;
    make_watch_oldest(&app, watch_id).await;

    stub.reduce_to(reduction(2.0));
    run_due(&app.state, time::OffsetDateTime::now_utc()).await;

    assert_eq!(
        receiver.delivered().len(),
        WEBHOOK_ATTEMPTS as usize,
        "the delivery was not retried"
    );
    // an unsigned webhook carries no signature at all
    assert!(
        !receiver.delivered()[0]
            .headers
            .contains_key("x-agora-signature")
    );

    let (last_run_at, last_error) = watch_run_state(&app, watch_id).await;
    assert!(last_run_at.is_some());
    assert!(
        last_error.expect("a reason").contains("500"),
        "the failed delivery was not recorded"
    );
    // the reading and the notification stand: only the alert did not arrive
    assert_eq!(stored_readings(&app, watch_id).await, 1);
    assert_eq!(trip_notifications(&app, watch_id).await, 1);
}

#[tokio::test]
async fn a_webhook_pointing_inside_the_platform_is_refused_at_create() {
    let stub = spawn_geoplumb_stub().await;
    let app = spawn_app_refusing_private_webhooks(&stub).await;
    let owner_token = platform_token(&fresh_user());
    let document_id = create_document(&app, &owner_token, "basin").await;

    for url in [
        "http://127.0.0.1:9000/hook",
        "http://localhost:9000/hook",
        "http://[::1]:9000/hook",
        "http://10.0.0.7/hook",
        "http://169.254.169.254/latest/meta-data/",
    ] {
        let mut body = watch_body();
        body["webhookUrl"] = json!(url);
        assert_eq!(
            create_watch(&app, &owner_token, document_id, &body)
                .await
                .status(),
            400,
            "{url} was accepted"
        );
    }

    // a name nothing answers for is taken, and refused when the delivery is
    // tried instead
    let mut body = watch_body();
    body["webhookUrl"] = json!("https://hooks.example.test/basin");
    assert_eq!(
        create_watch(&app, &owner_token, document_id, &body)
            .await
            .status(),
        201
    );
}
