use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use reqwest::StatusCode;
use uuid::Uuid;

use crate::auth::PlatformToken;
use crate::role::DocumentRole;

/// Env var holding ptolemy's base url. Unset turns project role resolution off,
/// leaving agora's members table as the only authority on every document.
pub const PTOLEMY_URL_ENV: &str = "PTOLEMY_URL";

/// How long a resolved project role is reused before ptolemy is asked again. The
/// window a revoked project membership can still reach a document.
pub const PROJECT_ROLE_CACHE_TTL: Duration = Duration::from_secs(30);

/// Ceiling on one ptolemy call. Past it the caller keeps their members table
/// role alone, so a stalled ptolemy cannot hold agora's request open.
pub const PTOLEMY_REQUEST_TIMEOUT: Duration = Duration::from_secs(3);

/// Bytes of a single project's response read before it is refused. The body is a
/// handful of json fields, so anything larger is a wrong url rather than an
/// answer.
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// Bytes of the caller's project listing read before it is refused. One entry
/// runs a few hundred bytes and the list grows with how many projects one person
/// belongs to, so the cap is far above the single project one.
const MAX_PROJECT_LIST_BYTES: usize = 1024 * 1024;

/// Cached roles kept before expired ones are dropped. A bound, not a policy: the
/// map is only an optimisation, so emptying it costs one ptolemy call per caller.
const MAX_CACHED_ROLES: usize = 10_000;

/// What a caller may do on a ptolemy project.
///
/// Read it through [`ProjectRole::parse`], so a role ptolemy grows later grants
/// nothing here until it is mapped on purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectRole {
    Owner,
    Editor,
    Viewer,
}

impl ProjectRole {
    pub fn parse(role: &str) -> Option<ProjectRole> {
        match role {
            "owner" => Some(ProjectRole::Owner),
            "editor" => Some(ProjectRole::Editor),
            "viewer" => Some(ProjectRole::Viewer),
            _ => None,
        }
    }

    /// Owner and editor both land on edit: agora has no tier above it.
    pub fn document_role(self) -> DocumentRole {
        match self {
            ProjectRole::Owner | ProjectRole::Editor => DocumentRole::Edit,
            ProjectRole::Viewer => DocumentRole::View,
        }
    }

    /// Whether this role may point a document at the project. A viewer must not,
    /// or reading a project would be enough to widen who reaches a document.
    pub fn can_link_a_document(self) -> bool {
        matches!(self, ProjectRole::Owner | ProjectRole::Editor)
    }
}

/// The document role a caller's project membership grants, if any.
///
/// Its own type so every access check has to say out loud whether it resolved a
/// project role or deliberately did not: `ProjectGrant::none()` reads as a
/// decision where a bare `None` would not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProjectGrant(Option<DocumentRole>);

impl ProjectGrant {
    /// No project role. An unlinked document, no configured resolver, a caller
    /// whose credential is not a platform token, or a ptolemy call that did not
    /// answer all arrive here.
    pub fn none() -> Self {
        Self(None)
    }

    pub fn of(role: DocumentRole) -> Self {
        Self(Some(role))
    }

    pub fn role(self) -> Option<DocumentRole> {
        self.0
    }
}

/// The caller's role on a document: the wider of what the members table says and
/// what their project membership grants. `None` denies access.
pub fn widest_role(members: Option<DocumentRole>, grant: ProjectGrant) -> Option<DocumentRole> {
    match (members, grant.role()) {
        (Some(DocumentRole::Edit), _) | (_, Some(DocumentRole::Edit)) => Some(DocumentRole::Edit),
        (Some(DocumentRole::View), _) | (_, Some(DocumentRole::View)) => Some(DocumentRole::View),
        (None, None) => None,
    }
}

struct CachedRole {
    /// The project the answer was about. A document that moves to another
    /// project must not keep reading the old project's answer, and the cache key
    /// cannot tell the difference on its own.
    project_id: Uuid,
    role: Option<ProjectRole>,
    resolved_at: Instant,
}

/// Pull through resolver for a caller's role on the project a document belongs
/// to.
///
/// Every lookup carries the caller's own bearer token, so agora never holds a
/// credential that outranks the person asking and ptolemy stays the one place
/// project membership is decided.
pub struct ProjectAccess {
    client: reqwest::Client,
    /// No trailing slash, so joining a path is one format string.
    base_url: String,
    cache_ttl: Duration,
    cache: Mutex<HashMap<(Uuid, String), CachedRole>>,
}

impl std::fmt::Debug for ProjectAccess {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProjectAccess")
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

impl ProjectAccess {
    pub fn new(
        base_url: &str,
        cache_ttl: Duration,
        request_timeout: Duration,
    ) -> Result<Self, String> {
        let base_url = base_url.trim().trim_end_matches('/').to_string();
        // a url reqwest cannot use would make every call fail, which reads as
        // "nobody has a project role" rather than as the misconfiguration it is
        if !base_url.starts_with("http://") && !base_url.starts_with("https://") {
            return Err(format!(
                "{PTOLEMY_URL_ENV} must start with http:// or https://, got {base_url:?}"
            ));
        }
        let client = reqwest::Client::builder()
            .timeout(request_timeout)
            // the caller's own bearer token rides on this request, so it goes to
            // the one host the operator named and nowhere a redirect points. a
            // 3xx then reads as an answer agora could not get, which denies
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| format!("could not build the ptolemy client: {error}"))?;
        Ok(Self {
            client,
            base_url,
            cache_ttl,
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// `Ok(None)` when the env var is unset, which turns project role resolution
    /// off. An `Err` is a broken setting and should stop startup rather than
    /// quietly drop the project half of every access check.
    pub fn from_env() -> Result<Option<Self>, String> {
        let Some(url) = std::env::var(PTOLEMY_URL_ENV)
            .ok()
            .filter(|url| !url.trim().is_empty())
        else {
            return Ok(None);
        };
        Self::new(&url, PROJECT_ROLE_CACHE_TTL, PTOLEMY_REQUEST_TIMEOUT).map(Some)
    }

    /// The grant to apply to `document_id`, from the cache when it is fresh and
    /// from ptolemy otherwise.
    ///
    /// Keyed by document and user rather than by project so one document's
    /// answer cannot be reused for another under the same project.
    pub async fn document_grant(
        &self,
        document_id: Uuid,
        user_id: &str,
        project_id: Uuid,
        token: &PlatformToken,
    ) -> ProjectGrant {
        if let Some(cached) = self.cached_grant(document_id, user_id, project_id) {
            return cached;
        }
        match self.ask_ptolemy(project_id, token).await {
            Answer::Settled(role) => {
                self.remember(document_id, user_id, project_id, role);
                grant_of(role)
            }
            Answer::Unsettled => ProjectGrant::none(),
        }
    }

    /// Every project the caller belongs to, with the role each one grants.
    ///
    /// One call for the whole set rather than one per document: a listing that
    /// asked per document would let any signed in caller drive a ptolemy request
    /// for every project that holds a document, not just their own.
    ///
    /// An empty answer where ptolemy did not answer, so a listing falls back to
    /// the members table the way every other check does.
    pub async fn caller_projects(&self, token: &PlatformToken) -> Vec<(Uuid, ProjectRole)> {
        let url = format!("{}/api/v1/projects", self.base_url);
        let Ok(response) = self
            .client
            .get(&url)
            .bearer_auth(token.as_str())
            .send()
            .await
        else {
            return Vec::new();
        };
        if !response.status().is_success() {
            return Vec::new();
        }
        let Some(body) = read_capped_body(response, MAX_PROJECT_LIST_BYTES).await else {
            return Vec::new();
        };
        let Ok(body) = serde_json::from_slice::<serde_json::Value>(&body) else {
            return Vec::new();
        };
        let Some(entries) = body.as_array() else {
            return Vec::new();
        };
        entries.iter().filter_map(project_entry).collect()
    }

    /// The caller's role on a project, asked fresh every time.
    ///
    /// This is the check that authorizes pointing a document at a project, so it
    /// deliberately skips the cache: a membership dropped seconds ago must not
    /// still be able to link.
    pub async fn project_role(
        &self,
        project_id: Uuid,
        token: &PlatformToken,
    ) -> Option<ProjectRole> {
        match self.ask_ptolemy(project_id, token).await {
            Answer::Settled(role) => role,
            Answer::Unsettled => None,
        }
    }

    /// The remembered grant for this document and caller, or `None` when there
    /// is nothing fresh to reuse. A remembered refusal is a hit whose grant is
    /// none, so ptolemy is not asked again about it until the ttl runs out.
    fn cached_grant(
        &self,
        document_id: Uuid,
        user_id: &str,
        project_id: Uuid,
    ) -> Option<ProjectGrant> {
        let cache = self.cache.lock().ok()?;
        let entry = cache.get(&(document_id, user_id.to_string()))?;
        if entry.project_id != project_id || entry.resolved_at.elapsed() >= self.cache_ttl {
            return None;
        }
        Some(grant_of(entry.role))
    }

    fn remember(
        &self,
        document_id: Uuid,
        user_id: &str,
        project_id: Uuid,
        role: Option<ProjectRole>,
    ) {
        let Ok(mut cache) = self.cache.lock() else {
            return;
        };
        if cache.len() >= MAX_CACHED_ROLES {
            cache.retain(|_, entry| entry.resolved_at.elapsed() < self.cache_ttl);
            if cache.len() >= MAX_CACHED_ROLES {
                cache.clear();
            }
        }
        cache.insert(
            (document_id, user_id.to_string()),
            CachedRole {
                project_id,
                role,
                resolved_at: Instant::now(),
            },
        );
    }

    async fn ask_ptolemy(&self, project_id: Uuid, token: &PlatformToken) -> Answer {
        // project_id is a Uuid, so its Display is hex and dashes and there is
        // nothing here that could reshape the path
        let url = format!("{}/api/v1/projects/{project_id}", self.base_url);
        let Ok(response) = self
            .client
            .get(&url)
            .bearer_auth(token.as_str())
            .send()
            .await
        else {
            return Answer::Unsettled;
        };
        let status = response.status();
        if !status.is_success() {
            return if settles_membership(status) {
                Answer::Settled(None)
            } else {
                Answer::Unsettled
            };
        }
        let Some(body) = read_capped_body(response, MAX_RESPONSE_BYTES).await else {
            return Answer::Unsettled;
        };
        let Ok(body) = serde_json::from_slice::<serde_json::Value>(&body) else {
            return Answer::Unsettled;
        };
        // a body with no role, or a role agora does not map, is an answer: this
        // caller gets nothing from the project
        Answer::Settled(
            body.get("role")
                .and_then(|role| role.as_str())
                .and_then(ProjectRole::parse),
        )
    }
}

/// Whether a refusal settles the question of membership.
///
/// A 403 or a 404 is ptolemy saying there is no membership to have, which is
/// worth caching. Everything else, a 5xx or a rejected credential included, is
/// ptolemy having a bad time, so the next request asks again instead of holding
/// the caller out for the whole ttl.
fn settles_membership(status: StatusCode) -> bool {
    matches!(status, StatusCode::FORBIDDEN | StatusCode::NOT_FOUND)
}

/// What one ptolemy call produced: an answer about membership, or nothing at all.
///
/// Only a real answer is cached. Both land the caller on their members table
/// role alone, which is the fail closed direction, but a failure must not stick
/// around for the whole ttl.
enum Answer {
    Settled(Option<ProjectRole>),
    Unsettled,
}

fn grant_of(role: Option<ProjectRole>) -> ProjectGrant {
    match role {
        Some(role) => ProjectGrant::of(role.document_role()),
        None => ProjectGrant::none(),
    }
}

/// One entry of the project listing, dropped when it carries no readable id and
/// role. A project agora cannot read grants nothing rather than everything.
fn project_entry(entry: &serde_json::Value) -> Option<(Uuid, ProjectRole)> {
    let id = entry.get("id")?.as_str()?.parse().ok()?;
    let role = ProjectRole::parse(entry.get("role")?.as_str()?)?;
    Some((id, role))
}

/// The body, or `None` once it passes `cap`. Read chunk by chunk so a wrong url
/// streaming without end cannot be buffered whole.
async fn read_capped_body(mut response: reqwest::Response, cap: usize) -> Option<Vec<u8>> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.ok()? {
        if body.len() + chunk.len() > cap {
            return None;
        }
        body.extend_from_slice(&chunk);
    }
    Some(body)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn project_role_parse_is_exact() {
        assert_eq!(ProjectRole::parse("owner"), Some(ProjectRole::Owner));
        assert_eq!(ProjectRole::parse("editor"), Some(ProjectRole::Editor));
        assert_eq!(ProjectRole::parse("viewer"), Some(ProjectRole::Viewer));
        for role in [
            "", "Owner", "EDITOR", " viewer", "admin", "edit", "view", "*",
        ] {
            assert_eq!(ProjectRole::parse(role), None, "{role:?}");
        }
    }

    #[test]
    fn owner_and_editor_reach_edit_and_a_viewer_only_reads() {
        assert_eq!(ProjectRole::Owner.document_role(), DocumentRole::Edit);
        assert_eq!(ProjectRole::Editor.document_role(), DocumentRole::Edit);
        assert_eq!(ProjectRole::Viewer.document_role(), DocumentRole::View);

        assert!(ProjectRole::Owner.can_link_a_document());
        assert!(ProjectRole::Editor.can_link_a_document());
        assert!(!ProjectRole::Viewer.can_link_a_document());
    }

    #[test]
    fn the_wider_of_the_two_roles_wins() {
        let none = ProjectGrant::none();
        let view = ProjectGrant::of(DocumentRole::View);
        let edit = ProjectGrant::of(DocumentRole::Edit);

        assert_eq!(widest_role(None, none), None);
        assert_eq!(widest_role(None, view), Some(DocumentRole::View));
        assert_eq!(widest_role(None, edit), Some(DocumentRole::Edit));

        assert_eq!(
            widest_role(Some(DocumentRole::View), none),
            Some(DocumentRole::View)
        );
        assert_eq!(
            widest_role(Some(DocumentRole::View), view),
            Some(DocumentRole::View)
        );
        assert_eq!(
            widest_role(Some(DocumentRole::View), edit),
            Some(DocumentRole::Edit)
        );

        assert_eq!(
            widest_role(Some(DocumentRole::Edit), none),
            Some(DocumentRole::Edit)
        );
        assert_eq!(
            widest_role(Some(DocumentRole::Edit), view),
            Some(DocumentRole::Edit)
        );
        assert_eq!(
            widest_role(Some(DocumentRole::Edit), edit),
            Some(DocumentRole::Edit)
        );
    }

    #[test]
    fn a_grant_of_nothing_never_becomes_a_role() {
        assert_eq!(ProjectGrant::none().role(), None);
        assert_eq!(grant_of(None), ProjectGrant::none());
        assert_eq!(
            grant_of(Some(ProjectRole::Viewer)).role(),
            Some(DocumentRole::View)
        );
        assert_eq!(
            grant_of(Some(ProjectRole::Owner)).role(),
            Some(DocumentRole::Edit)
        );
    }

    #[test]
    fn only_a_definite_refusal_settles_membership() {
        assert!(settles_membership(StatusCode::FORBIDDEN));
        assert!(settles_membership(StatusCode::NOT_FOUND));
        for status in [
            StatusCode::UNAUTHORIZED,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::BAD_GATEWAY,
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::GATEWAY_TIMEOUT,
        ] {
            assert!(!settles_membership(status), "{status}");
        }
    }

    #[test]
    fn a_base_url_needs_a_scheme_and_keeps_no_trailing_slash() {
        let ttl = Duration::from_secs(1);
        let timeout = Duration::from_secs(1);
        let access = ProjectAccess::new("http://ptolemy:3000/", ttl, timeout).unwrap();
        assert_eq!(access.base_url, "http://ptolemy:3000");
        assert!(ProjectAccess::new("https://ptolemy.example", ttl, timeout).is_ok());

        for url in ["", "  ", "ptolemy:3000", "//ptolemy", "ftp://ptolemy"] {
            let error = ProjectAccess::new(url, ttl, timeout).unwrap_err();
            assert!(error.contains(PTOLEMY_URL_ENV), "{url:?}: {error}");
        }
    }

    #[test]
    fn a_debug_line_carries_no_cached_identity() {
        let access = ProjectAccess::new(
            "http://ptolemy:3000",
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .unwrap();
        let document = Uuid::new_v4();
        let project = Uuid::new_v4();
        access.remember(document, "ada", project, Some(ProjectRole::Owner));
        let printed = format!("{access:?}");
        assert!(printed.contains("http://ptolemy:3000"));
        assert!(!printed.contains("ada"));
    }

    #[test]
    fn a_cached_role_is_reused_only_for_the_same_document_user_and_project() {
        let access = ProjectAccess::new(
            "http://ptolemy:3000",
            Duration::from_secs(60),
            Duration::from_secs(1),
        )
        .unwrap();
        let document = Uuid::new_v4();
        let project = Uuid::new_v4();
        access.remember(document, "ada", project, Some(ProjectRole::Editor));

        assert_eq!(
            access.cached_grant(document, "ada", project),
            Some(ProjectGrant::of(DocumentRole::Edit))
        );
        assert_eq!(access.cached_grant(document, "grace", project), None);
        assert_eq!(access.cached_grant(Uuid::new_v4(), "ada", project), None);
        // the document moved to another project, so the old answer is no answer
        assert_eq!(access.cached_grant(document, "ada", Uuid::new_v4()), None);
    }

    #[test]
    fn a_cached_role_expires_with_the_ttl() {
        let access = ProjectAccess::new(
            "http://ptolemy:3000",
            Duration::from_millis(1),
            Duration::from_secs(1),
        )
        .unwrap();
        let document = Uuid::new_v4();
        let project = Uuid::new_v4();
        access.remember(document, "ada", project, Some(ProjectRole::Owner));
        std::thread::sleep(Duration::from_millis(10));
        assert_eq!(access.cached_grant(document, "ada", project), None);
    }

    #[test]
    fn a_cached_refusal_is_remembered_as_a_refusal() {
        let access = ProjectAccess::new(
            "http://ptolemy:3000",
            Duration::from_secs(60),
            Duration::from_secs(1),
        )
        .unwrap();
        let document = Uuid::new_v4();
        let project = Uuid::new_v4();
        access.remember(document, "ada", project, None);
        // a hit whose grant is none, which is what keeps a refusal from asking
        // ptolemy again on the next request
        assert_eq!(
            access.cached_grant(document, "ada", project),
            Some(ProjectGrant::none())
        );
    }

    #[test]
    fn the_cache_stays_bounded() {
        let access = ProjectAccess::new(
            "http://ptolemy:3000",
            Duration::from_secs(60),
            Duration::from_secs(1),
        )
        .unwrap();
        let project = Uuid::new_v4();
        for _ in 0..(MAX_CACHED_ROLES + 16) {
            access.remember(Uuid::new_v4(), "ada", project, Some(ProjectRole::Owner));
        }
        assert!(access.cache.lock().unwrap().len() <= MAX_CACHED_ROLES);
    }
}
