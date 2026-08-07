use std::time::Duration;

use agora_server::auth::{AuthConfig, share_token_hash};
use agora_server::limits::{
    MAX_CLIENT_MESSAGES_PER_SECOND, MAX_DOCUMENT_NAME_BYTES, MAX_INBOUND_FRAME_BYTES,
    MAX_KEY_BYTES, MAX_OP_VALUE_BYTES, MAX_PEERS_PER_DOCUMENT, MAX_PRESENCE_BYTES,
    MAX_USER_ID_BYTES,
};
use agora_server::protocol::Peer;
use agora_server::role::DocumentRole;
use agora_server::{AppState, migrate, router};
use futures_util::{SinkExt, StreamExt};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};
use sqlx::PgPool;
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
    let state = AppState::new(pool, auth);
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

    async fn send(&mut self, message: Value) {
        self.stream
            .send(Message::text(message.to_string()))
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

/// The whole join sequence: a snapshot, then the peer list.
async fn expect_join(client: &mut WebsocketClient) -> (Value, Value) {
    let snapshot = client.expect_message("snapshot").await;
    let peers = client.expect_message("peers").await;
    (snapshot, peers)
}

/// Ops applied straight through the room, which is the same path the websocket
/// takes but without a connection rate limit in the way.
async fn apply_ops_directly(app: &TestApp, document_id: Uuid, actor: &str, count: usize) -> i64 {
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
    for index in 0..count {
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
async fn a_join_receives_a_snapshot_then_the_peer_list() {
    let app = spawn_app().await;
    let owner = fresh_user();
    let token = platform_token(&owner);
    let document_id = create_document(&app, &token, "city plan").await;

    let mut client = open(&app, document_id, &token, None).await;
    let snapshot = client.expect_message("snapshot").await;
    assert_eq!(snapshot["seq"], 0);
    assert_eq!(snapshot["state"]["meta"]["name"], "city plan");
    for namespace in ["layers", "annotations", "bookmarks"] {
        assert!(snapshot["state"][namespace].is_object(), "{namespace}");
    }
    // a client learns who it is and what it may do from the snapshot itself
    assert_eq!(snapshot["actor"], owner.as_str());
    assert_eq!(snapshot["role"], "edit");

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
    reconnected.expect_message("peers").await;
    assert!(
        reconnected.try_next_message().await.is_none(),
        "a replay sent more than the gap"
    );

    let mut caught_up = open(&app, document_id, &token, Some(3)).await;
    let peers = caught_up.expect_message("peers").await;
    assert!(peers["peers"].is_array(), "a caught up client got a replay");
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

    guest_client
        .send(json!({
            "type": "presence",
            "cursor": [12.5, -3.25],
            "selection": ["layers/roads"],
            "viewport": {"zoom": 6},
            "actor": "someone-else"
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
    client.expect_message("snapshot").await;
    client.expect_message("peers").await;
    let reason = send_and_refuse(&mut client, 1, "layers/one-more", json!(chunk)).await;
    assert_eq!(reason, "document state limit reached");

    app.state
        .rooms
        .leave(document_id, joined.connection_id)
        .await;
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

    let cap = MAX_CLIENT_MESSAGES_PER_SECOND as usize;
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
    let reply = flooder.next_message().await;
    assert!(
        matches!(reply["type"].as_str(), Some("ack") | Some("error")),
        "the connection stopped answering: {reply}"
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
    assert_eq!(stored[0], share_token_hash(&link));

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
        .bind(share_token_hash(&link))
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
