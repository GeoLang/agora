//! Signed outbound POSTs for the one agora event that has them, `watch.tripped`.
//!
//! Agora posts to a url a document editor typed, so the url is untrusted input
//! that agora dials from inside the platform network. Two things keep that from
//! being a way to reach the services around it: the host is checked against the
//! private ranges before every attempt, and the client is pinned to the address
//! that check passed, so the name cannot be moved between the check and the
//! connect.

use std::time::Duration;

use platform_webhook::{PrivateHosts, WebhookUrl, pinned_client, signature};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::assets::rfc3339;
use crate::limits::{WEBHOOK_ATTEMPTS, WEBHOOK_BACKOFF_SECONDS};

/// The event a tripped watch delivers, and the headers it carries. The same
/// scheme ptolemy and tiletopia send, so a receiver written for one reads all
/// three.
pub const WATCH_TRIPPED_EVENT: &str = "watch.tripped";
pub const EVENT_HEADER: &str = "X-Agora-Event";
pub const DELIVERY_HEADER: &str = "X-Agora-Delivery";
pub const SIGNATURE_HEADER: &str = "X-Agora-Signature";

/// How a watch's alerts are delivered: how long between attempts, and whether
/// the platform's own network is reachable.
#[derive(Debug, Clone, Copy)]
pub struct Webhooks {
    backoff: Duration,
    pub(crate) private_hosts: PrivateHosts,
}

impl Webhooks {
    pub fn new(backoff: Duration, private_hosts: PrivateHosts) -> Self {
        Self {
            backoff,
            private_hosts,
        }
    }

    /// What the binary runs with.
    pub fn refusing_private_hosts() -> Self {
        Self::new(
            Duration::from_secs(WEBHOOK_BACKOFF_SECONDS),
            PrivateHosts::Refused,
        )
    }

    /// Post one event, retrying with a doubling backoff. The `Err` is what the
    /// watch records as its `last_error`.
    pub async fn deliver(
        &self,
        url: &str,
        secret: Option<&str>,
        event: &str,
        occurred_at: OffsetDateTime,
        data: Value,
    ) -> Result<(), String> {
        let parsed = WebhookUrl::parse(url).map_err(|error| error.to_string())?;
        let body = serde_json::json!({
            "event": event,
            "occurredAt": rfc3339(occurred_at),
            "data": data,
        });
        let body = serde_json::to_vec(&body)
            .map_err(|_| "could not encode the webhook body".to_string())?;
        let delivery = Uuid::new_v4();

        let mut refused = String::new();
        for attempt in 1..=WEBHOOK_ATTEMPTS {
            match self.attempt(&parsed, secret, event, delivery, &body).await {
                Ok(()) => return Ok(()),
                Err(reason) => refused = reason,
            }
            if attempt < WEBHOOK_ATTEMPTS {
                tokio::time::sleep(self.backoff * 2u32.pow(attempt - 1)).await;
            }
        }
        Err(refused)
    }

    async fn attempt(
        &self,
        url: &WebhookUrl,
        secret: Option<&str>,
        event: &str,
        delivery: Uuid,
        body: &[u8],
    ) -> Result<(), String> {
        let client = pinned_client(url, self.private_hosts)
            .await
            .map_err(|error| error.to_string())?;
        let mut request = client
            .post(url.as_url().clone())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(EVENT_HEADER, event)
            .header(DELIVERY_HEADER, delivery.to_string());
        if let Some(secret) = secret {
            request = request.header(SIGNATURE_HEADER, signature(secret, body));
        }
        match request.body(body.to_vec()).send().await {
            Ok(response) if response.status().is_success() => Ok(()),
            Ok(response) => Err(format!("webhook answered {}", response.status())),
            Err(_) => Err("webhook did not answer".to_string()),
        }
    }
}
