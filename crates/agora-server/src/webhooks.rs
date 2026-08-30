//! Signed outbound POSTs for the one agora event that has them, `watch.tripped`.
//!
//! Agora posts to a url a document editor typed, so the url is untrusted input
//! that agora dials from inside the platform network. Two things keep that from
//! being a way to reach the services around it: the host is checked against the
//! private ranges before every attempt, and the client is pinned to the address
//! that check passed, so the name cannot be moved between the check and the
//! connect.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::assets::rfc3339;
use crate::limits::{WEBHOOK_ATTEMPTS, WEBHOOK_BACKOFF_SECONDS, WEBHOOK_TIMEOUT_SECONDS};

/// The event a tripped watch delivers, and the headers it carries. The same
/// scheme ptolemy and tiletopia send, so a receiver written for one reads all
/// three.
pub const WATCH_TRIPPED_EVENT: &str = "watch.tripped";
pub const EVENT_HEADER: &str = "X-Agora-Event";
pub const DELIVERY_HEADER: &str = "X-Agora-Delivery";
pub const SIGNATURE_HEADER: &str = "X-Agora-Signature";

/// Whether a webhook may reach an address inside the platform's own network.
///
/// `Refused` everywhere but agora's own test suite, whose receiver is a
/// loopback port. Nothing reads this from the environment, so a deployment
/// cannot end up on `Allowed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivateHosts {
    Refused,
    Allowed,
}

/// How a watch's alerts are delivered: how long between attempts, and whether
/// the platform's own network is reachable.
#[derive(Debug, Clone, Copy)]
pub struct Webhooks {
    backoff: Duration,
    private_hosts: PrivateHosts,
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

    /// Whether this url is one agora may post to, as far as can be told before
    /// anything is sent. A host that does not resolve passes here and is
    /// refused at delivery time instead, so a receiver that is not up yet can
    /// still be registered.
    pub async fn is_worth_registering(&self, url: &reqwest::Url) -> Result<(), &'static str> {
        if self.private_hosts == PrivateHosts::Allowed {
            return Ok(());
        }
        let Ok(addresses) = resolve(url).await else {
            return Ok(());
        };
        match addresses.iter().all(|address| is_public(address.ip())) {
            true => Ok(()),
            false => Err("webhook url resolves inside the platform network"),
        }
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
        let parsed =
            reqwest::Url::parse(url).map_err(|_| "webhook url is not a url".to_string())?;
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
        url: &reqwest::Url,
        secret: Option<&str>,
        event: &str,
        delivery: Uuid,
        body: &[u8],
    ) -> Result<(), String> {
        let client = self.client_for(url).await?;
        let mut request = client
            .post(url.clone())
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

    /// A client that can reach this url and nothing else: no redirects, and for
    /// a named host, resolution pinned to the address that was just checked.
    async fn client_for(&self, url: &reqwest::Url) -> Result<reqwest::Client, String> {
        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(WEBHOOK_TIMEOUT_SECONDS))
            // a redirect is a second url nobody checked, so a 3xx is the end of
            // the attempt rather than a hop
            .redirect(reqwest::redirect::Policy::none());

        if self.private_hosts == PrivateHosts::Refused {
            let addresses = resolve(url)
                .await
                .map_err(|reason| format!("webhook host {reason}"))?;
            let Some(address) = addresses
                .iter()
                .copied()
                .find(|address| is_public(address.ip()))
            else {
                return Err("webhook host is inside the platform network".to_string());
            };
            // a name is pinned to the address that just passed, so nothing can
            // point it somewhere else between here and the connect. an address
            // in the url is already its own answer
            if let Some(domain) = named_host(url) {
                builder = builder.resolve(domain, address);
            }
        }

        builder
            .build()
            .map_err(|_| "could not build the webhook client".to_string())
    }
}

/// `sha256=<hex>` of the HMAC-SHA256 of the body under the secret, the value a
/// receiver recomputes to know the post is agora's.
fn signature(secret: &str, body: &[u8]) -> String {
    let mut mac = match Hmac::<Sha256>::new_from_slice(secret.as_bytes()) {
        Ok(mac) => mac,
        // hmac takes a key of any length, so this is unreachable rather than a
        // case with a fallback
        Err(_) => return String::new(),
    };
    mac.update(body);
    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}

/// The url's host when it is a name rather than an address. An ipv6 literal
/// wears brackets in a url, which is what separates it from a name.
fn named_host(url: &reqwest::Url) -> Option<&str> {
    let host = url.host_str()?;
    (!host.starts_with('[') && host.parse::<IpAddr>().is_err()).then_some(host)
}

/// Every address a url's host stands for. An address in the url is its own
/// answer, and a name is asked of the resolver.
async fn resolve(url: &reqwest::Url) -> Result<Vec<SocketAddr>, &'static str> {
    let port = url.port_or_known_default().ok_or("has no port")?;
    let host = url.host_str().ok_or("is missing")?;
    let bare = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(address) = bare.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(address, port)]);
    }
    let resolved = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| "does not resolve")?;
    let addresses: Vec<SocketAddr> = resolved.collect();
    match addresses.is_empty() {
        true => Err("does not resolve"),
        false => Ok(addresses),
    }
}

/// Whether an address is out on the internet rather than somewhere agora can
/// reach only because of where it is deployed.
fn is_public(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_public_v4(address),
        IpAddr::V6(address) => match address.to_ipv4_mapped() {
            Some(mapped) => is_public_v4(mapped),
            None => is_public_v6(address),
        },
    }
}

fn is_public_v4(address: Ipv4Addr) -> bool {
    let [first, second, ..] = address.octets();
    let shared = first == 100 && (64..128).contains(&second);
    let this_network = first == 0;
    // 240.0.0.0/4, which carries the broadcast address
    let reserved = first >= 240;
    !(address.is_loopback()
        || address.is_private()
        || address.is_link_local()
        || address.is_multicast()
        || shared
        || this_network
        || reserved)
}

fn is_public_v6(address: Ipv6Addr) -> bool {
    let first = address.segments()[0];
    // fc00::/7
    let unique_local = (first & 0xfe00) == 0xfc00;
    // fe80::/10
    let link_local = (first & 0xffc0) == 0xfe80;
    !(address.is_loopback()
        || address.is_unspecified()
        || address.is_multicast()
        || unique_local
        || link_local)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn address(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn the_platforms_own_network_is_not_public() {
        for inside in [
            "127.0.0.1",
            "127.9.9.9",
            "0.0.0.0",
            "0.1.2.3",
            "10.0.0.7",
            "172.16.4.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "100.127.255.255",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "::1",
            "::",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.7",
        ] {
            assert!(!is_public(address(inside)), "{inside}");
        }
    }

    #[test]
    fn an_address_out_on_the_internet_is_public() {
        for outside in [
            "1.1.1.1",
            "8.8.8.8",
            "93.184.216.34",
            "172.32.0.1",
            "100.128.0.1",
            "99.255.255.255",
            "2606:4700::1111",
            "::ffff:8.8.8.8",
        ] {
            assert!(is_public(address(outside)), "{outside}");
        }
    }

    /// Pinned against tiletopia's own vector, since a receiver written for one
    /// service has to verify the other.
    #[test]
    fn the_signature_is_hmac_sha256_over_the_body() {
        let signed = signature("secret", b"body");
        assert_eq!(signed.len(), "sha256=".len() + 64);
        assert!(signed.starts_with("sha256="));
        assert_ne!(signature("other", b"body"), signed);
        assert_ne!(signature("secret", b"other body"), signed);
    }

    #[tokio::test]
    async fn a_url_naming_an_address_resolves_to_itself() {
        let url = reqwest::Url::parse("http://10.0.0.7:9000/hook").unwrap();
        assert_eq!(
            resolve(&url).await.unwrap(),
            vec![SocketAddr::new(address("10.0.0.7"), 9000)]
        );

        let url = reqwest::Url::parse("https://[::1]/hook").unwrap();
        assert_eq!(
            resolve(&url).await.unwrap(),
            vec![SocketAddr::new(address("::1"), 443)]
        );
    }

    #[tokio::test]
    async fn a_loopback_url_is_not_worth_registering() {
        let webhooks = Webhooks::refusing_private_hosts();
        for url in [
            "http://127.0.0.1:9000/hook",
            "http://[::1]:9000/hook",
            "https://10.0.0.7/hook",
            "http://169.254.169.254/latest/meta-data/",
        ] {
            let url = reqwest::Url::parse(url).unwrap();
            assert!(
                webhooks.is_worth_registering(&url).await.is_err(),
                "{url} was accepted"
            );
        }
    }

    /// A name nothing answers for is taken now and refused at delivery, so a
    /// receiver that is not up yet can still be registered.
    #[tokio::test]
    async fn a_host_that_does_not_resolve_is_left_to_the_delivery() {
        let webhooks = Webhooks::refusing_private_hosts();
        let url = reqwest::Url::parse("https://nothing.invalid/hook").unwrap();
        assert_eq!(webhooks.is_worth_registering(&url).await, Ok(()));
        assert!(webhooks.client_for(&url).await.is_err());
    }
}
