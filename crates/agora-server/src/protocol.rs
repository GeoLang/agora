use std::sync::Arc;

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::role::DocumentRole;

/// What goes out when a frame cannot be serialized, so a client can never turn
/// an encoding failure into a panic.
const ENCODE_FAILURE: &str = r#"{"type":"error","reason":"could not encode message"}"#;

fn encode_frame(message: &impl Serialize) -> Arc<str> {
    match serde_json::to_string(message) {
        Ok(text) => Arc::from(text),
        Err(_) => Arc::from(ENCODE_FAILURE),
    }
}

/// The `value` on an op: required on the wire, and `null` deletes the key.
///
/// A plain `Option` will not do. Serde fills a missing option with null, so a
/// client that forgot the field would silently delete a key. Going through
/// `Value` instead means the deserializer is asked for any value, which is the
/// one thing serde refuses to invent for an absent field.
#[derive(Debug, Clone, PartialEq)]
pub struct OpValue(pub Option<Value>);

impl<'de> Deserialize<'de> for OpValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match Value::deserialize(deserializer)? {
            Value::Null => Ok(OpValue(None)),
            present => Ok(OpValue(Some(present))),
        }
    }
}

/// One entry of a batch: what an op carries minus the `clientSeq`, which the
/// frame holds once for the whole batch.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchOp {
    pub key: String,
    pub value: OpValue,
}

/// A message a client may send.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum ClientMessage {
    Op {
        #[serde(rename = "clientSeq")]
        client_seq: i64,
        key: String,
        value: OpValue,
    },
    /// Ops the server applies all or nothing, so peers never render a torn
    /// intermediate state.
    Batch {
        #[serde(rename = "clientSeq")]
        client_seq: i64,
        ops: Vec<BatchOp>,
    },
    Presence {
        #[serde(default)]
        cursor: Option<[f64; 2]>,
        #[serde(default)]
        selection: Vec<String>,
        #[serde(default)]
        viewport: Option<Value>,
    },
}

/// A message a sensor feed may send on the ingest socket.
///
/// Unknown keys are tolerated here, unlike everywhere else agora reads input.
/// The senders are devices nobody on this side controls, and a firmware that
/// adds a field must not start losing readings.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum FeedMessage {
    Readings { readings: Vec<FeedReading> },
}

/// One reading as a feed sends it. `at` is optional and defaults to the time
/// the server took the frame, which is what a device with no clock relies on.
#[derive(Debug, Clone, Deserialize)]
pub struct FeedReading {
    pub asset: String,
    pub kind: String,
    pub value: f64,
    #[serde(default)]
    pub at: Option<String>,
}

/// What the ingest socket answers with. Its `ack` counts readings, so it is not
/// the document socket's `ack`, and the two sockets share no message type.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum FeedReply {
    Ack { count: usize },
    Error { reason: String },
}

impl FeedReply {
    pub fn error(reason: impl Into<String>) -> Self {
        FeedReply::Error {
            reason: reason.into(),
        }
    }

    pub fn encode(&self) -> Arc<str> {
        encode_frame(self)
    }
}

/// One reading as it is relayed to everyone on the document, `at` in RFC 3339.
#[derive(Debug, Clone, Serialize)]
pub struct Reading {
    pub asset: String,
    pub kind: String,
    pub value: f64,
    pub at: String,
}

/// The latest reading of one kind for an asset.
#[derive(Debug, Clone, Serialize)]
pub struct AssetValue {
    pub kind: String,
    pub value: f64,
    pub at: String,
}

/// One asset as of some moment: which feed reports it, whether it is still
/// reporting, and its latest value of every kind.
#[derive(Debug, Clone, Serialize)]
pub struct AssetState {
    pub asset: String,
    pub feed: Uuid,
    pub online: bool,
    pub values: Vec<AssetValue>,
}

/// One op the server has ordered, as it appears inside a relayed batch. Each
/// carries its own seq, and a reconnect replays the batch as the same frame.
#[derive(Debug, Clone, Serialize)]
pub struct AppliedOp {
    pub seq: i64,
    pub key: String,
    pub value: Option<Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Peer {
    pub actor: String,
    pub name: String,
    pub role: DocumentRole,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ServerMessage {
    Snapshot {
        seq: i64,
        state: Value,
        /// The caller's own actor id, so a client can tell itself apart in the
        /// peer list, and its role, so it knows before an op is refused.
        actor: String,
        role: DocumentRole,
    },
    Op {
        seq: i64,
        actor: String,
        key: String,
        value: Option<Value>,
    },
    Batch {
        actor: String,
        ops: Vec<AppliedOp>,
    },
    Ack {
        #[serde(rename = "clientSeq")]
        client_seq: i64,
        seq: i64,
    },
    Peers {
        peers: Vec<Peer>,
    },
    Presence {
        actor: String,
        cursor: Option<[f64; 2]>,
        selection: Vec<String>,
        viewport: Option<Value>,
    },
    /// What a feed just reported, on its way to everyone looking at the
    /// document.
    Readings {
        feed: Uuid,
        readings: Vec<Reading>,
    },
    /// Every asset the document's feeds report, sent on join.
    Assets {
        assets: Vec<AssetState>,
    },
    /// An asset started or stopped reporting.
    Liveness {
        asset: String,
        online: bool,
        at: String,
    },
    Error {
        reason: String,
    },
}

impl ServerMessage {
    pub fn error(reason: impl Into<String>) -> Self {
        ServerMessage::Error {
            reason: reason.into(),
        }
    }

    /// Encode once so the room can hand the same bytes to every peer.
    pub fn encode(&self) -> Arc<str> {
        encode_frame(self)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use serde_json::json;

    fn parse(text: &str) -> Result<ClientMessage, serde_json::Error> {
        serde_json::from_str(text)
    }

    #[test]
    fn ops_parse_with_a_value_and_with_an_explicit_null() {
        let set = parse(r#"{"type":"op","clientSeq":4,"key":"layers/a","value":{"order":"a0"}}"#)
            .unwrap();
        match set {
            ClientMessage::Op {
                client_seq,
                key,
                value,
            } => {
                assert_eq!(client_seq, 4);
                assert_eq!(key, "layers/a");
                assert_eq!(value, OpValue(Some(json!({"order": "a0"}))));
            }
            other => panic!("{other:?}"),
        }

        let delete = parse(r#"{"type":"op","clientSeq":5,"key":"layers/a","value":null}"#).unwrap();
        match delete {
            ClientMessage::Op { value, .. } => assert_eq!(value, OpValue(None)),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn an_op_without_a_value_field_is_refused() {
        assert!(parse(r#"{"type":"op","clientSeq":1,"key":"layers/a"}"#).is_err());
        assert!(parse(r#"{"type":"op","key":"layers/a","value":null}"#).is_err());
        assert!(parse(r#"{"type":"op","clientSeq":1,"value":null}"#).is_err());
    }

    #[test]
    fn a_batch_parses_its_ops_in_order_with_null_as_a_delete() {
        let parsed = parse(
            r#"{"type":"batch","clientSeq":9,"ops":[
                {"key":"layers/a","value":{"order":"a0"}},
                {"key":"layers/b","value":null}
            ]}"#,
        )
        .unwrap();
        match parsed {
            ClientMessage::Batch { client_seq, ops } => {
                assert_eq!(client_seq, 9);
                assert_eq!(
                    ops,
                    vec![
                        BatchOp {
                            key: "layers/a".to_string(),
                            value: OpValue(Some(json!({"order": "a0"}))),
                        },
                        BatchOp {
                            key: "layers/b".to_string(),
                            value: OpValue(None),
                        },
                    ]
                );
            }
            other => panic!("{other:?}"),
        }

        assert!(parse(r#"{"type":"batch","clientSeq":9,"ops":[]}"#).is_ok());
    }

    #[test]
    fn a_batch_entry_without_a_value_field_is_refused() {
        assert!(
            parse(
                r#"{"type":"batch","clientSeq":9,"ops":[
                    {"key":"layers/a","value":null},
                    {"key":"layers/b"}
                ]}"#
            )
            .is_err()
        );
        for text in [
            r#"{"type":"batch","clientSeq":9}"#,
            r#"{"type":"batch","ops":[]}"#,
            r#"{"type":"batch","clientSeq":9,"ops":{"key":"layers/a","value":null}}"#,
            r#"{"type":"batch","clientSeq":9,"ops":[{"value":null}]}"#,
        ] {
            assert!(parse(text).is_err(), "{text:?}");
        }
    }

    /// Every shape the viewer and the python client send, so the strictness
    /// above cannot start refusing a frame either of them still produces.
    #[test]
    fn the_frames_our_clients_send_still_parse() {
        for text in [
            r#"{"type":"op","clientSeq":1,"key":"layers/a","value":{"order":"a0"}}"#,
            r#"{"type":"op","clientSeq":1,"key":"comments/c1","value":null}"#,
            r#"{"type":"batch","clientSeq":2,"ops":[{"key":"layers/a","value":1},{"key":"layers/b","value":null}]}"#,
            r#"{"type":"presence","cursor":[1.0,2.0],"selection":[],"viewport":{"center":[1.0,2.0],"zoom":4}}"#,
            r#"{"type":"presence","cursor":null,"selection":[],"viewport":null}"#,
        ] {
            assert!(parse(text).is_ok(), "{text:?}");
        }
    }

    #[test]
    fn an_unknown_key_on_a_client_message_is_refused() {
        for text in [
            r#"{"type":"op","clientSeq":1,"key":"layers/a","value":null,"actor":"someone"}"#,
            r#"{"type":"batch","clientSeq":1,"ops":[],"seq":9}"#,
            r#"{"type":"batch","clientSeq":1,"ops":[{"key":"layers/a","value":null,"seq":9}]}"#,
            r#"{"type":"presence","cursor":null,"selection":[],"viewport":null,"actor":"someone"}"#,
        ] {
            assert!(parse(text).is_err(), "{text:?}");
        }
    }

    #[test]
    fn unknown_message_types_and_junk_are_refused() {
        for text in [
            r#"{"type":"checkpoint"}"#,
            r#"{"type":"OP","clientSeq":1,"key":"layers/a","value":null}"#,
            r#"{}"#,
            "[]",
            "null",
            "not json",
            r#"{"type":"op","clientSeq":"one","key":"layers/a","value":null}"#,
        ] {
            assert!(parse(text).is_err(), "{text:?}");
        }
    }

    #[test]
    fn presence_accepts_a_cursor_or_null_and_refuses_a_malformed_one() {
        let full = parse(
            r#"{"type":"presence","cursor":[1.5,-2.5],"selection":["layers/a"],"viewport":{"zoom":4}}"#,
        )
        .unwrap();
        match full {
            ClientMessage::Presence {
                cursor,
                selection,
                viewport,
            } => {
                assert_eq!(cursor, Some([1.5, -2.5]));
                assert_eq!(selection, vec!["layers/a".to_string()]);
                assert_eq!(viewport, Some(json!({"zoom": 4})));
            }
            other => panic!("{other:?}"),
        }

        assert!(parse(r#"{"type":"presence","cursor":null,"selection":[]}"#).is_ok());
        assert!(parse(r#"{"type":"presence"}"#).is_ok());
        for text in [
            r#"{"type":"presence","cursor":[1.0]}"#,
            r#"{"type":"presence","cursor":[1.0,2.0,3.0]}"#,
            r#"{"type":"presence","cursor":"here"}"#,
            r#"{"type":"presence","selection":"layers/a"}"#,
        ] {
            assert!(parse(text).is_err(), "{text:?}");
        }
    }

    #[test]
    fn server_messages_match_the_pinned_wire_shape() {
        let snapshot = ServerMessage::Snapshot {
            seq: 7,
            state: json!({"meta": {"name": "plan"}}),
            actor: "user-1".to_string(),
            role: DocumentRole::Edit,
        };
        assert_eq!(
            serde_json::from_str::<Value>(&snapshot.encode()).unwrap(),
            json!({
                "type": "snapshot",
                "seq": 7,
                "state": {"meta": {"name": "plan"}},
                "actor": "user-1",
                "role": "edit"
            })
        );

        let op = ServerMessage::Op {
            seq: 8,
            actor: "user-1".to_string(),
            key: "layers/a".to_string(),
            value: None,
        };
        assert_eq!(
            serde_json::from_str::<Value>(&op.encode()).unwrap(),
            json!({"type": "op", "seq": 8, "actor": "user-1", "key": "layers/a", "value": null})
        );

        let batch = ServerMessage::Batch {
            actor: "user-1".to_string(),
            ops: vec![
                AppliedOp {
                    seq: 9,
                    key: "layers/a".to_string(),
                    value: Some(json!({"order": "a0"})),
                },
                AppliedOp {
                    seq: 10,
                    key: "layers/b".to_string(),
                    value: None,
                },
            ],
        };
        assert_eq!(
            serde_json::from_str::<Value>(&batch.encode()).unwrap(),
            json!({
                "type": "batch",
                "actor": "user-1",
                "ops": [
                    {"seq": 9, "key": "layers/a", "value": {"order": "a0"}},
                    {"seq": 10, "key": "layers/b", "value": null}
                ]
            })
        );

        let ack = ServerMessage::Ack {
            client_seq: 3,
            seq: 8,
        };
        assert_eq!(
            serde_json::from_str::<Value>(&ack.encode()).unwrap(),
            json!({"type": "ack", "clientSeq": 3, "seq": 8})
        );

        let peers = ServerMessage::Peers {
            peers: vec![Peer {
                actor: "guest-1".to_string(),
                name: "guest".to_string(),
                role: DocumentRole::View,
            }],
        };
        assert_eq!(
            serde_json::from_str::<Value>(&peers.encode()).unwrap(),
            json!({"type": "peers", "peers": [{"actor": "guest-1", "name": "guest", "role": "view"}]})
        );

        let presence = ServerMessage::Presence {
            actor: "user-1".to_string(),
            cursor: Some([1.0, 2.0]),
            selection: vec!["layers/a".to_string()],
            viewport: None,
        };
        assert_eq!(
            serde_json::from_str::<Value>(&presence.encode()).unwrap(),
            json!({
                "type": "presence",
                "actor": "user-1",
                "cursor": [1.0, 2.0],
                "selection": ["layers/a"],
                "viewport": null
            })
        );

        assert_eq!(
            serde_json::from_str::<Value>(&ServerMessage::error("nope").encode()).unwrap(),
            json!({"type": "error", "reason": "nope"})
        );
    }

    #[test]
    fn the_twin_frames_match_the_pinned_wire_shape() {
        let feed = Uuid::new_v4();
        let readings = ServerMessage::Readings {
            feed,
            readings: vec![Reading {
                asset: "TWIN-03".to_string(),
                kind: "temperature".to_string(),
                value: 21.5,
                at: "2026-08-25T12:00:00Z".to_string(),
            }],
        };
        assert_eq!(
            serde_json::from_str::<Value>(&readings.encode()).unwrap(),
            json!({
                "type": "readings",
                "feed": feed,
                "readings": [{
                    "asset": "TWIN-03",
                    "kind": "temperature",
                    "value": 21.5,
                    "at": "2026-08-25T12:00:00Z"
                }]
            })
        );

        let assets = ServerMessage::Assets {
            assets: vec![AssetState {
                asset: "TWIN-03".to_string(),
                feed,
                online: true,
                values: vec![AssetValue {
                    kind: "temperature".to_string(),
                    value: 21.5,
                    at: "2026-08-25T12:00:00Z".to_string(),
                }],
            }],
        };
        assert_eq!(
            serde_json::from_str::<Value>(&assets.encode()).unwrap(),
            json!({
                "type": "assets",
                "assets": [{
                    "asset": "TWIN-03",
                    "feed": feed,
                    "online": true,
                    "values": [{
                        "kind": "temperature",
                        "value": 21.5,
                        "at": "2026-08-25T12:00:00Z"
                    }]
                }]
            })
        );

        let liveness = ServerMessage::Liveness {
            asset: "TWIN-03".to_string(),
            online: false,
            at: "2026-08-25T12:00:09Z".to_string(),
        };
        assert_eq!(
            serde_json::from_str::<Value>(&liveness.encode()).unwrap(),
            json!({
                "type": "liveness",
                "asset": "TWIN-03",
                "online": false,
                "at": "2026-08-25T12:00:09Z"
            })
        );

        assert_eq!(
            serde_json::from_str::<Value>(&FeedReply::Ack { count: 2 }.encode()).unwrap(),
            json!({"type": "ack", "count": 2})
        );
        assert_eq!(
            serde_json::from_str::<Value>(&FeedReply::error("malformed message").encode()).unwrap(),
            json!({"type": "error", "reason": "malformed message"})
        );
    }

    #[test]
    fn an_ingest_frame_parses_with_and_without_a_reading_time() {
        let parsed: FeedMessage = serde_json::from_str(
            r#"{"type":"readings","readings":[
                {"asset":"TWIN-03","kind":"temperature","value":21.5,"at":"2026-08-25T12:00:00Z"},
                {"asset":"TWIN-04","kind":"humidity","value":0.4}
            ]}"#,
        )
        .unwrap();
        let FeedMessage::Readings { readings } = parsed;
        assert_eq!(readings.len(), 2);
        assert_eq!(readings[0].asset, "TWIN-03");
        assert_eq!(readings[0].at.as_deref(), Some("2026-08-25T12:00:00Z"));
        assert_eq!(readings[1].value, 0.4);
        assert_eq!(readings[1].at, None);
    }

    /// The one wire format that stays tolerant. Devices we do not control send
    /// these, so a firmware that adds a field must not lose its readings.
    #[test]
    fn an_ingest_frame_keeps_its_readings_when_it_carries_an_unknown_key() {
        let parsed: FeedMessage = serde_json::from_str(
            r#"{"type":"readings","feed":"f1","readings":[
                {"asset":"TWIN-03","kind":"temperature","value":21.5,"unit":"C"}
            ]}"#,
        )
        .unwrap();
        let FeedMessage::Readings { readings } = parsed;
        assert_eq!(readings.len(), 1);
        assert_eq!(readings[0].asset, "TWIN-03");
        assert_eq!(readings[0].value, 21.5);
    }

    #[test]
    fn an_ingest_frame_missing_a_field_or_naming_another_type_is_refused() {
        for text in [
            r#"{"type":"readings"}"#,
            r#"{"type":"readings","readings":{}}"#,
            r#"{"type":"readings","readings":[{"kind":"temperature","value":1}]}"#,
            r#"{"type":"readings","readings":[{"asset":"a","value":1}]}"#,
            r#"{"type":"readings","readings":[{"asset":"a","kind":"b"}]}"#,
            r#"{"type":"readings","readings":[{"asset":"a","kind":"b","value":"warm"}]}"#,
            r#"{"type":"op","clientSeq":1,"key":"layers/a","value":null}"#,
            r#"{"type":"presence"}"#,
            "not json",
        ] {
            assert!(
                serde_json::from_str::<FeedMessage>(text).is_err(),
                "{text:?}"
            );
        }
    }
}
