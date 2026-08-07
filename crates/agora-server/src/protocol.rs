use std::sync::Arc;

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

use crate::role::DocumentRole;

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
pub struct BatchOp {
    pub key: String,
    pub value: OpValue,
}

/// A message a client may send.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
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

/// One op the server has ordered, as it appears inside a relayed batch. Each
/// carries its own seq, so a batch decomposes into exactly the `op` frames a
/// reconnect would replay.
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

    /// Encode once so the room can hand the same bytes to every peer. There is
    /// no unwrap here, so a client can never turn an encoding failure into a
    /// panic.
    pub fn encode(&self) -> Arc<str> {
        match serde_json::to_string(self) {
            Ok(text) => Arc::from(text),
            Err(_) => Arc::from(r#"{"type":"error","reason":"could not encode message"}"#),
        }
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
}
