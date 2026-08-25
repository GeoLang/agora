use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::Value;
use sqlx::{PgPool, Row};
use tokio::sync::{Mutex, broadcast};
use uuid::Uuid;

use crate::limits::{
    CHECKPOINT_INTERVAL_OPS, MAX_DOCUMENT_STATE_BYTES, MAX_PEERS_PER_DOCUMENT,
    ROOM_BROADCAST_CAPACITY, oldest_op_to_keep,
};
use crate::notifications::record_comment_mentions;
use crate::protocol::{AppliedOp, BatchOp, OpValue, Peer, ServerMessage};
use crate::state::{
    DocumentState, KeyError, META_NAME_KEY, op_value_within_cap, parse_key, valid_name,
};

#[derive(Debug)]
pub enum OpError {
    Key(KeyError),
    ValueTooLarge,
    StateTooLarge,
    InvalidName,
    Database(sqlx::Error),
}

impl OpError {
    pub fn reason(&self) -> &'static str {
        match self {
            OpError::Key(error) => error.reason(),
            OpError::ValueTooLarge => "op value too large",
            OpError::StateTooLarge => "document state limit reached",
            OpError::InvalidName => "invalid document name",
            OpError::Database(_) => "database error",
        }
    }
}

/// Why a batch was refused, and which entry is to blame when one of them is.
/// The cumulative state cap and a database failure belong to the whole frame,
/// so there `index` is `None`.
#[derive(Debug)]
pub struct BatchError {
    pub index: Option<usize>,
    pub error: OpError,
}

impl BatchError {
    fn entry(index: usize, error: OpError) -> Self {
        Self {
            index: Some(index),
            error,
        }
    }

    fn whole(error: OpError) -> Self {
        Self { index: None, error }
    }

    fn database(error: sqlx::Error) -> Self {
        Self::whole(OpError::Database(error))
    }

    pub fn reason(&self) -> String {
        match self.index {
            Some(index) => format!("op {index}: {}", self.error.reason()),
            None => self.error.reason().to_string(),
        }
    }
}

#[derive(Debug)]
pub enum JoinError {
    DocumentNotFound,
    RoomFull,
    Database(sqlx::Error),
}

struct PeerEntry {
    connection_id: u64,
    peer: Peer,
}

struct RoomInner {
    state: DocumentState,
    seq: i64,
    checkpoint_seq: i64,
    peers: Vec<PeerEntry>,
}

impl RoomInner {
    fn peer_list(&self) -> Vec<Peer> {
        self.peers.iter().map(|entry| entry.peer.clone()).collect()
    }
}

/// A message on its way to every connection in a room.
///
/// `skip_connection` is set for presence, which never goes back to the peer that
/// sent it. It is a connection and not an actor, so two tabs of one account
/// still see each other.
#[derive(Clone)]
pub struct RoomEvent {
    pub skip_connection: Option<u64>,
    pub text: Arc<str>,
}

/// One document held in memory while at least one connection is on it. Every
/// op for the document passes through [`Room::apply_op`], which is what makes
/// the server the single order authority.
pub struct Room {
    pub document_id: Uuid,
    sender: broadcast::Sender<RoomEvent>,
    inner: Mutex<RoomInner>,
}

impl Room {
    async fn load(pool: &PgPool, document_id: Uuid) -> Result<Self, JoinError> {
        let (state, seq, checkpoint_seq) = current_state(pool, document_id)
            .await
            .map_err(JoinError::Database)?
            .ok_or(JoinError::DocumentNotFound)?;

        let (sender, _) = broadcast::channel(ROOM_BROADCAST_CAPACITY);
        Ok(Self {
            document_id,
            sender,
            inner: Mutex::new(RoomInner {
                state,
                seq,
                checkpoint_seq,
                peers: Vec::new(),
            }),
        })
    }

    pub async fn snapshot(&self) -> (i64, Value) {
        let inner = self.inner.lock().await;
        (inner.seq, inner.state.snapshot())
    }

    /// Fan a message out to every connection on the document. A connection too
    /// far behind loses messages and is resynced with a snapshot, which is what
    /// keeps presence from queueing up behind a slow peer.
    pub fn relay(&self, message: &ServerMessage) {
        let _ = self.sender.send(RoomEvent {
            skip_connection: None,
            text: message.encode(),
        });
    }

    /// Fan out to everyone except one connection, which is how presence reaches
    /// the room without the sender being drawn its own cursor.
    pub fn relay_excluding(&self, connection_id: u64, message: &ServerMessage) {
        let _ = self.sender.send(RoomEvent {
            skip_connection: Some(connection_id),
            text: message.encode(),
        });
    }

    /// Validate, order, persist, apply and fan out one op. Returns the seq the
    /// server assigned.
    pub async fn apply_op(
        &self,
        pool: &PgPool,
        actor: &str,
        client_seq: i64,
        key: &str,
        value: Option<Value>,
    ) -> Result<i64, OpError> {
        let op = BatchOp {
            key: key.to_string(),
            value: OpValue(value),
        };
        self.apply_batch(pool, actor, client_seq, &[op])
            .await
            .map_err(|failure| failure.error)
    }

    /// Validate, order, persist, apply and fan out several ops as one unit.
    /// Returns the seq of the last one.
    ///
    /// Nothing is written and no seq is spent until every entry has passed, so
    /// a refused batch leaves the document exactly as it was. Duplicate keys are
    /// allowed and settle last writer wins, the same as two separate ops would.
    ///
    /// The ops take consecutive seqs, one row each, because the `ops` table is
    /// keyed by them. Every row also carries the seq of the frame's first op as
    /// its `batch_seq`, which is what lets a replay hand back the same frame.
    ///
    /// An empty batch is refused before this, in the websocket handler.
    pub async fn apply_batch(
        &self,
        pool: &PgPool,
        actor: &str,
        client_seq: i64,
        ops: &[BatchOp],
    ) -> Result<i64, BatchError> {
        let mut document_name = None;
        for (index, op) in ops.iter().enumerate() {
            let named = self
                .validate(&op.key, op.value.0.as_ref())
                .map_err(|error| BatchError::entry(index, error))?;
            if let Some(name) = named {
                document_name = Some(name);
            }
        }

        let mut inner = self.inner.lock().await;
        let writes = ops.iter().map(|op| (op.key.as_str(), op.value.0.as_ref()));
        if inner.state.projected_bytes(writes) > MAX_DOCUMENT_STATE_BYTES {
            return Err(BatchError::whole(OpError::StateTooLarge));
        }

        let mut seq = inner.seq;
        let batch_seq = seq + 1;
        let mut applied = Vec::with_capacity(ops.len());
        // earlier writes in this batch, so a key written twice diffs against
        // its in-batch predecessor rather than the stored value
        let mut written: HashMap<&str, Option<&Value>> = HashMap::new();
        let mut transaction = pool.begin().await.map_err(BatchError::database)?;
        for op in ops {
            seq += 1;
            sqlx::query(
                "insert into ops (doc_id, seq, actor, key, value, client_seq, batch_seq)
                 values ($1, $2, $3, $4, $5, $6, $7)",
            )
            .bind(self.document_id)
            .bind(seq)
            .bind(actor)
            .bind(&op.key)
            .bind(&op.value.0)
            .bind(client_seq)
            .bind(batch_seq)
            .execute(&mut *transaction)
            .await
            .map_err(BatchError::database)?;
            if let Ok(("comments", comment_id)) = parse_key(&op.key) {
                let previous = match written.get(op.key.as_str()) {
                    Some(value) => *value,
                    None => inner.state.value(&op.key),
                };
                record_comment_mentions(
                    &mut transaction,
                    self.document_id,
                    comment_id,
                    actor,
                    previous,
                    op.value.0.as_ref(),
                )
                .await
                .map_err(BatchError::database)?;
            }
            written.insert(op.key.as_str(), op.value.0.as_ref());
            applied.push(AppliedOp {
                seq,
                key: op.key.clone(),
                value: op.value.0.clone(),
            });
        }
        if let Some(name) = document_name {
            sqlx::query("update documents set name = $1 where id = $2")
                .bind(name)
                .bind(self.document_id)
                .execute(&mut *transaction)
                .await
                .map_err(BatchError::database)?;
        }
        transaction.commit().await.map_err(BatchError::database)?;

        for op in &applied {
            inner.state.apply(&op.key, op.value.clone());
        }
        inner.seq = seq;

        self.relay(&relay_frame(actor, applied));

        if inner.seq - inner.checkpoint_seq >= CHECKPOINT_INTERVAL_OPS as i64 {
            let folded = inner.state.snapshot();
            // a failed checkpoint is not an op failure: the op rows are already
            // committed, so the next op retries the fold
            if self.checkpoint(pool, folded, seq).await.is_ok() {
                inner.checkpoint_seq = seq;
            }
        }
        Ok(seq)
    }

    /// Everything that can refuse an op before the server orders it, and the
    /// document name to store when the op carries one.
    fn validate(&self, key: &str, value: Option<&Value>) -> Result<Option<String>, OpError> {
        parse_key(key).map_err(OpError::Key)?;
        if let Some(value) = value
            && !op_value_within_cap(value)
        {
            return Err(OpError::ValueTooLarge);
        }
        self.document_name_from(key, value)
    }

    /// `meta/name` is the one key with server meaning, so it has to hold a name
    /// the document row can carry.
    fn document_name_from(
        &self,
        key: &str,
        value: Option<&Value>,
    ) -> Result<Option<String>, OpError> {
        if key != META_NAME_KEY {
            return Ok(None);
        }
        let Some(name) = value.and_then(Value::as_str) else {
            return Err(OpError::InvalidName);
        };
        if !valid_name(name) {
            return Err(OpError::InvalidName);
        }
        Ok(Some(name.to_string()))
    }

    async fn checkpoint(&self, pool: &PgPool, folded: Value, seq: i64) -> Result<(), sqlx::Error> {
        let mut transaction = pool.begin().await?;
        sqlx::query("update documents set checkpoint = $1, checkpoint_seq = $2 where id = $3")
            .bind(folded)
            .bind(seq)
            .bind(self.document_id)
            .execute(&mut *transaction)
            .await?;
        if let Some(oldest) = oldest_op_to_keep(seq) {
            sqlx::query("delete from ops where doc_id = $1 and seq < $2")
                .bind(self.document_id)
                .bind(oldest)
                .execute(&mut *transaction)
                .await?;
        }
        transaction.commit().await
    }
}

/// One op goes out as an `op` and several as a `batch`, so a batch is on the
/// wire only when there is something to hold together.
fn relay_frame(actor: &str, applied: Vec<AppliedOp>) -> ServerMessage {
    match <[AppliedOp; 1]>::try_from(applied) {
        Ok([single]) => ServerMessage::Op {
            seq: single.seq,
            actor: actor.to_string(),
            key: single.key,
            value: single.value,
        },
        Err(several) => ServerMessage::Batch {
            actor: actor.to_string(),
            ops: several,
        },
    }
}

/// What a connection needs after it has been admitted to a room.
pub struct Joined {
    pub room: Arc<Room>,
    pub connection_id: u64,
    pub receiver: broadcast::Receiver<RoomEvent>,
    pub seq: i64,
    pub state: Value,
}

/// The live rooms. A room is loaded on the first join and dropped when the last
/// connection leaves, so an idle document costs nothing.
pub struct RoomRegistry {
    rooms: Mutex<HashMap<Uuid, Arc<Room>>>,
    next_connection_id: AtomicU64,
}

impl RoomRegistry {
    pub fn new() -> Self {
        Self {
            rooms: Mutex::new(HashMap::new()),
            next_connection_id: AtomicU64::new(1),
        }
    }

    /// Subscribe, register the peer and capture the state under one lock, so no
    /// op can slip between the snapshot a client gets and the stream it starts
    /// listening to.
    pub async fn join(
        &self,
        pool: &PgPool,
        document_id: Uuid,
        peer: Peer,
    ) -> Result<Joined, JoinError> {
        let mut rooms = self.rooms.lock().await;
        let room = match rooms.get(&document_id) {
            Some(room) => Arc::clone(room),
            None => {
                let room = Arc::new(Room::load(pool, document_id).await?);
                rooms.insert(document_id, Arc::clone(&room));
                room
            }
        };

        let mut inner = room.inner.lock().await;
        if inner.peers.len() >= MAX_PEERS_PER_DOCUMENT {
            return Err(JoinError::RoomFull);
        }

        let connection_id = self.next_connection_id.fetch_add(1, Ordering::Relaxed);
        let receiver = room.sender.subscribe();
        inner.peers.push(PeerEntry {
            connection_id,
            peer,
        });
        let joined = Joined {
            room: Arc::clone(&room),
            connection_id,
            receiver,
            seq: inner.seq,
            state: inner.state.snapshot(),
        };
        room.relay(&ServerMessage::Peers {
            peers: inner.peer_list(),
        });
        Ok(joined)
    }

    pub async fn leave(&self, document_id: Uuid, connection_id: u64) {
        let mut rooms = self.rooms.lock().await;
        let Some(room) = rooms.get(&document_id).map(Arc::clone) else {
            return;
        };
        let mut inner = room.inner.lock().await;
        inner
            .peers
            .retain(|entry| entry.connection_id != connection_id);
        if inner.peers.is_empty() {
            rooms.remove(&document_id);
            return;
        }
        room.relay(&ServerMessage::Peers {
            peers: inner.peer_list(),
        });
    }

    pub async fn is_loaded(&self, document_id: Uuid) -> bool {
        self.rooms.lock().await.contains_key(&document_id)
    }
}

impl Default for RoomRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// A document as a joining client would see it: the stored checkpoint with
/// every op after it applied, the seq that leaves it at, and the seq the
/// checkpoint was folded at. `None` when there is no such document.
///
/// Read from the database rather than from a live room, so a caller outside the
/// room registry sees the same document a join would build.
pub async fn current_state(
    pool: &PgPool,
    document_id: Uuid,
) -> Result<Option<(DocumentState, i64, i64)>, sqlx::Error> {
    let Some(row) = sqlx::query("select checkpoint, checkpoint_seq from documents where id = $1")
        .bind(document_id)
        .fetch_optional(pool)
        .await?
    else {
        return Ok(None);
    };
    let checkpoint: Value = row.try_get("checkpoint")?;
    let checkpoint_seq: i64 = row.try_get("checkpoint_seq")?;

    let mut state = DocumentState::from_checkpoint(&checkpoint);
    let tail =
        sqlx::query("select seq, key, value from ops where doc_id = $1 and seq > $2 order by seq")
            .bind(document_id)
            .bind(checkpoint_seq)
            .fetch_all(pool)
            .await?;

    let mut seq = checkpoint_seq;
    for row in tail {
        let op_seq: i64 = row.try_get("seq")?;
        let key: String = row.try_get("key")?;
        let value: Option<Value> = row.try_get("value")?;
        if parse_key(&key).is_ok() {
            state.apply(&key, value);
        }
        seq = op_seq;
    }
    Ok(Some((state, seq, checkpoint_seq)))
}

/// The lowest op seq still stored for a document, or `None` once every op has
/// been folded into the checkpoint and pruned.
pub async fn oldest_retained_op(
    pool: &PgPool,
    document_id: Uuid,
) -> Result<Option<i64>, sqlx::Error> {
    let row = sqlx::query("select min(seq) as oldest from ops where doc_id = $1")
        .bind(document_id)
        .fetch_one(pool)
        .await?;
    row.try_get::<Option<i64>, _>("oldest")
}

/// The ops after `after` and up to `through`, as the frames they were applied
/// in: rows sharing a `batch_seq` come back as the one batch they went out as
/// live, so a resuming client never sees a batch torn into single ops.
pub async fn ops_between(
    pool: &PgPool,
    document_id: Uuid,
    after: i64,
    through: i64,
) -> Result<Vec<ServerMessage>, sqlx::Error> {
    let rows = sqlx::query(
        "select seq, actor, key, value, batch_seq from ops
         where doc_id = $1 and seq > $2 and seq <= $3 order by seq",
    )
    .bind(document_id)
    .bind(after)
    .bind(through)
    .fetch_all(pool)
    .await?;

    let mut messages = Vec::new();
    let mut frame: Option<(i64, String, Vec<AppliedOp>)> = None;
    for row in rows {
        let batch_seq: i64 = row.try_get("batch_seq")?;
        let actor: String = row.try_get("actor")?;
        let op = AppliedOp {
            seq: row.try_get("seq")?,
            key: row.try_get("key")?,
            value: row.try_get("value")?,
        };
        match frame.take() {
            Some((open_seq, open_actor, mut ops)) if open_seq == batch_seq => {
                ops.push(op);
                frame = Some((open_seq, open_actor, ops));
            }
            closed => {
                if let Some((_, closed_actor, ops)) = closed {
                    messages.push(relay_frame(&closed_actor, ops));
                }
                frame = Some((batch_seq, actor, vec![op]));
            }
        }
    }
    if let Some((_, actor, ops)) = frame {
        messages.push(relay_frame(&actor, ops));
    }
    Ok(messages)
}
