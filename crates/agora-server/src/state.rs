use std::collections::BTreeMap;

use serde_json::{Map, Value};

use crate::limits::{MAX_DOCUMENT_NAME_BYTES, MAX_KEY_BYTES, MAX_OP_VALUE_BYTES};

/// The only namespaces an op key may address.
pub const NAMESPACES: [&str; 5] = ["meta", "layers", "annotations", "bookmarks", "comments"];

/// The one key the server reads rather than passes through.
pub const META_NAME_KEY: &str = "meta/name";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    TooLong,
    UnknownNamespace,
    InvalidId,
}

impl KeyError {
    pub fn reason(self) -> &'static str {
        match self {
            KeyError::TooLong => "key too long",
            KeyError::UnknownNamespace => "unknown key namespace",
            KeyError::InvalidId => "invalid key id",
        }
    }
}

fn is_id_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
}

/// Split a wire key into its namespace and id, refusing anything outside the
/// whitelist. Ids carry no slash, so a key always names exactly one value.
pub fn parse_key(key: &str) -> Result<(&str, &str), KeyError> {
    if key.len() > MAX_KEY_BYTES {
        return Err(KeyError::TooLong);
    }
    let Some((namespace, id)) = key.split_once('/') else {
        return Err(KeyError::UnknownNamespace);
    };
    if !NAMESPACES.contains(&namespace) {
        return Err(KeyError::UnknownNamespace);
    }
    if id.is_empty() || !id.chars().all(is_id_character) {
        return Err(KeyError::InvalidId);
    }
    Ok((namespace, id))
}

/// A document name a client may set, either at creation or through
/// `meta/name`.
pub fn valid_document_name(name: &str) -> bool {
    !name.trim().is_empty()
        && name.len() <= MAX_DOCUMENT_NAME_BYTES
        && !name.chars().any(char::is_control)
}

// serde_json cannot fail on a Value: keys are always strings and Number
// refuses NaN and infinity
fn value_bytes(value: &Value) -> usize {
    serde_json::to_string(value).map_or(0, |text| text.len())
}

pub fn op_value_within_cap(value: &Value) -> bool {
    value_bytes(value) <= MAX_OP_VALUE_BYTES
}

#[derive(Debug, Clone)]
struct Entry {
    value: Value,
    bytes: usize,
}

/// One document as a flat map from wire key to opaque json value.
///
/// The nested shape clients see is rendered on demand by [`Self::snapshot`],
/// which keeps last writer wins per key a single map insert and keeps the size
/// accounting exact.
#[derive(Debug, Clone, Default)]
pub struct DocumentState {
    entries: BTreeMap<String, Entry>,
    bytes: usize,
}

impl DocumentState {
    pub fn new(name: &str) -> Self {
        let mut state = Self::default();
        state.apply(META_NAME_KEY, Some(Value::String(name.to_string())));
        state
    }

    /// Rebuild from a stored checkpoint. Keys that no longer parse are
    /// dropped, so the whitelist holds even over a hand edited row.
    pub fn from_checkpoint(checkpoint: &Value) -> Self {
        let mut state = Self::default();
        for namespace in NAMESPACES {
            let Some(members) = checkpoint.get(namespace).and_then(Value::as_object) else {
                continue;
            };
            for (id, value) in members {
                let key = format!("{namespace}/{id}");
                if parse_key(&key).is_ok() {
                    state.apply(&key, Some(value.clone()));
                }
            }
        }
        state
    }

    pub fn snapshot(&self) -> Value {
        let mut namespaces: BTreeMap<&str, Map<String, Value>> =
            NAMESPACES.iter().map(|name| (*name, Map::new())).collect();
        for (key, entry) in &self.entries {
            let Ok((namespace, id)) = parse_key(key) else {
                continue;
            };
            if let Some(members) = namespaces.get_mut(namespace) {
                members.insert(id.to_string(), entry.value.clone());
            }
        }
        let rendered = namespaces
            .into_iter()
            .map(|(name, members)| (name.to_string(), Value::Object(members)))
            .collect();
        Value::Object(rendered)
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }

    fn entry_bytes(key: &str, value: &Value) -> usize {
        key.len() + value_bytes(value)
    }

    /// Size the state would have after these writes, so a cap can be enforced
    /// before any of them is persisted. Writes that are individually small can
    /// only be caught together, so a caller passes the whole group.
    ///
    /// A key written twice counts once, at its last write, which is where it
    /// will land. Collecting into a map is what drops the earlier ones.
    pub fn projected_bytes<'a>(
        &self,
        writes: impl IntoIterator<Item = (&'a str, Option<&'a Value>)>,
    ) -> usize {
        let last_writes: BTreeMap<&str, Option<&Value>> = writes.into_iter().collect();
        let mut total = self.bytes;
        for (key, value) in last_writes {
            let replaced = self
                .entries
                .get(key)
                .map_or(0, |entry| key.len() + entry.bytes);
            let added = value.map_or(0, |value| Self::entry_bytes(key, value));
            total = total.saturating_sub(replaced).saturating_add(added);
        }
        total
    }

    pub fn apply(&mut self, key: &str, value: Option<Value>) {
        if let Some(removed) = self.entries.remove(key) {
            self.bytes = self.bytes.saturating_sub(key.len() + removed.bytes);
        }
        if let Some(value) = value {
            let bytes = value_bytes(&value);
            self.bytes = self.bytes.saturating_add(key.len() + bytes);
            self.entries.insert(key.to_string(), Entry { value, bytes });
        }
    }

    pub fn value(&self, key: &str) -> Option<&Value> {
        self.entries.get(key).map(|entry| &entry.value)
    }

    pub fn name(&self) -> Option<&str> {
        self.entries
            .get(META_NAME_KEY)
            .and_then(|entry| entry.value.as_str())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use serde_json::json;

    #[test]
    fn key_namespaces_outside_the_whitelist_are_refused() {
        assert_eq!(parse_key("layers/a1"), Ok(("layers", "a1")));
        assert_eq!(parse_key("meta/name"), Ok(("meta", "name")));
        assert_eq!(
            parse_key("annotations/x-1_2.3"),
            Ok(("annotations", "x-1_2.3"))
        );
        assert_eq!(parse_key("bookmarks/b"), Ok(("bookmarks", "b")));
        assert_eq!(
            parse_key("comments/018f2c1a-6d3b-7e42-9c10-5a8b7d2e4f16"),
            Ok(("comments", "018f2c1a-6d3b-7e42-9c10-5a8b7d2e4f16"))
        );
        for key in ["", "layers", "secrets/a", "Layers/a", "/a", "../a"] {
            assert_eq!(parse_key(key), Err(KeyError::UnknownNamespace), "{key:?}");
        }
        for key in [
            "layers/",
            "layers/a/b",
            "layers/a b",
            "layers/a\u{0}",
            "meta/na me",
        ] {
            assert_eq!(parse_key(key), Err(KeyError::InvalidId), "{key:?}");
        }
    }

    #[test]
    fn keys_over_the_cap_are_refused_before_the_namespace_is_read() {
        let key = format!("layers/{}", "a".repeat(MAX_KEY_BYTES));
        assert_eq!(parse_key(&key), Err(KeyError::TooLong));
        let at_cap = format!("layers/{}", "a".repeat(MAX_KEY_BYTES - "layers/".len()));
        assert_eq!(at_cap.len(), MAX_KEY_BYTES);
        assert!(parse_key(&at_cap).is_ok());
    }

    #[test]
    fn document_names_are_bounded_and_printable() {
        assert!(valid_document_name("city plan"));
        assert!(!valid_document_name(""));
        assert!(!valid_document_name("   "));
        assert!(!valid_document_name("line\nbreak"));
        assert!(!valid_document_name(
            &"a".repeat(MAX_DOCUMENT_NAME_BYTES + 1)
        ));
        assert!(valid_document_name(&"a".repeat(MAX_DOCUMENT_NAME_BYTES)));
    }

    #[test]
    fn snapshot_always_carries_every_namespace() {
        let state = DocumentState::new("plan");
        let snapshot = state.snapshot();
        assert_eq!(snapshot["meta"]["name"], json!("plan"));
        for namespace in ["layers", "annotations", "bookmarks", "comments"] {
            assert!(snapshot[namespace].is_object(), "{namespace}");
            assert_eq!(snapshot[namespace].as_object().unwrap().len(), 0);
        }
    }

    #[test]
    fn last_write_wins_per_key_and_null_deletes() {
        let mut state = DocumentState::new("plan");
        state.apply("layers/a", Some(json!({"url": "one"})));
        state.apply("layers/a", Some(json!({"url": "two"})));
        state.apply("layers/b", Some(json!({"url": "three"})));
        assert_eq!(state.snapshot()["layers"]["a"], json!({"url": "two"}));
        state.apply("layers/a", None);
        assert!(state.snapshot()["layers"].get("a").is_none());
        assert_eq!(state.snapshot()["layers"]["b"], json!({"url": "three"}));
    }

    #[test]
    fn size_accounting_returns_to_zero_after_deletes() {
        let mut state = DocumentState::default();
        assert_eq!(state.bytes(), 0);
        state.apply("layers/a", Some(json!({"order": "a0"})));
        let with_one = state.bytes();
        assert!(with_one > 0);
        state.apply("layers/a", Some(json!({"order": "a0000000"})));
        assert!(state.bytes() > with_one);
        state.apply("layers/a", None);
        assert_eq!(state.bytes(), 0);
    }

    #[test]
    fn projected_bytes_matches_the_size_after_the_write() {
        let mut state = DocumentState::new("plan");
        let value = json!({"order": "a0", "url": "http://example.test/tiles"});
        let projected = state.projected_bytes([("layers/a", Some(&value))]);
        state.apply("layers/a", Some(value.clone()));
        assert_eq!(projected, state.bytes());

        let replacement = json!({"order": "a1"});
        let projected = state.projected_bytes([("layers/a", Some(&replacement))]);
        state.apply("layers/a", Some(replacement));
        assert_eq!(projected, state.bytes());

        let projected = state.projected_bytes([("layers/a", None)]);
        state.apply("layers/a", None);
        assert_eq!(projected, state.bytes());
    }

    #[test]
    fn projected_bytes_matches_the_size_after_a_whole_batch() {
        let mut state = DocumentState::new("plan");
        state.apply("layers/a", Some(json!({"order": "a0"})));

        let replacement = json!({"order": "a1", "url": "http://example.test/tiles"});
        let added = json!({"order": "a2"});
        let writes = [
            ("layers/a", Some(&replacement)),
            ("layers/b", Some(&added)),
            ("meta/name", None),
        ];
        let projected = state.projected_bytes(writes);
        for (key, value) in writes {
            state.apply(key, value.cloned());
        }
        assert_eq!(projected, state.bytes());
    }

    #[test]
    fn projected_bytes_counts_a_repeated_key_once() {
        let mut state = DocumentState::default();
        let first = json!({"order": "a0"});
        let last = json!({"order": "a1", "url": "http://example.test/tiles"});
        let projected =
            state.projected_bytes([("layers/a", Some(&first)), ("layers/a", Some(&last))]);
        state.apply("layers/a", Some(last.clone()));
        assert_eq!(projected, state.bytes());
        assert_eq!(
            projected,
            state.projected_bytes([("layers/a", Some(&last))]),
            "a repeated key was counted twice"
        );
    }

    #[test]
    fn checkpoint_round_trips_and_drops_keys_outside_the_whitelist() {
        let mut state = DocumentState::new("plan");
        state.apply("layers/a", Some(json!({"order": "a0"})));
        state.apply("bookmarks/home", Some(json!({"zoom": 4})));
        let reloaded = DocumentState::from_checkpoint(&state.snapshot());
        assert_eq!(reloaded.snapshot(), state.snapshot());
        assert_eq!(reloaded.bytes(), state.bytes());

        let hostile = json!({
            "meta": {"name": "plan"},
            "layers": {"ok": {"order": "a0"}, "bad/id": {"order": "a1"}},
            "secrets": {"root": true}
        });
        let filtered = DocumentState::from_checkpoint(&hostile);
        let snapshot = filtered.snapshot();
        assert!(snapshot["layers"].get("ok").is_some());
        assert!(snapshot["layers"].get("bad/id").is_none());
        assert!(snapshot.get("secrets").is_none());
    }

    #[test]
    fn op_values_over_the_cap_are_refused() {
        assert!(op_value_within_cap(&json!({"order": "a0"})));
        let oversized = json!("x".repeat(MAX_OP_VALUE_BYTES));
        assert!(!op_value_within_cap(&oversized));
    }

    #[test]
    fn name_reads_only_a_string_meta_name() {
        let mut state = DocumentState::new("plan");
        assert_eq!(state.name(), Some("plan"));
        state.apply(META_NAME_KEY, Some(json!(7)));
        assert_eq!(state.name(), None);
    }
}
