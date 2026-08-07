use serde::{Deserialize, Serialize};

/// What a connection may do to a document.
///
/// Read it through [`DocumentRole::parse`], never by comparing the stored
/// string, so an unknown role grants nothing instead of landing in a tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DocumentRole {
    View,
    Edit,
}

impl DocumentRole {
    pub fn parse(role: &str) -> Option<DocumentRole> {
        match role {
            "view" => Some(DocumentRole::View),
            "edit" => Some(DocumentRole::Edit),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            DocumentRole::View => "view",
            DocumentRole::Edit => "edit",
        }
    }

    pub fn can_edit(self) -> bool {
        matches!(self, DocumentRole::Edit)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn role_parse_is_exact() {
        assert_eq!(DocumentRole::parse("view"), Some(DocumentRole::View));
        assert_eq!(DocumentRole::parse("edit"), Some(DocumentRole::Edit));
        for role in ["", "View", "EDIT", " edit", "edit ", "owner", "admin", "*"] {
            assert_eq!(DocumentRole::parse(role), None, "{role:?}");
        }
    }

    #[test]
    fn only_edit_can_edit() {
        assert!(DocumentRole::Edit.can_edit());
        assert!(!DocumentRole::View.can_edit());
    }

    #[test]
    fn role_round_trips_through_its_string() {
        for role in [DocumentRole::View, DocumentRole::Edit] {
            assert_eq!(DocumentRole::parse(role.as_str()), Some(role));
        }
    }
}
