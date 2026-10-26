//! Local relay route policy. Not a listener, not room verification, and not
//! Genesis admission. Both origins absent selects Disabled. One side, a
//! malformed origin, or two different canonical origins is an error and must
//! not change the route. Matching strings are not approval of a manifest.
//!
//! `attach_verified_peer` only matches the configured expected peer and keeps
//! the direct sockets. The caller must already have checked signature, actor
//! and node pin, expiry, and revision or session.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

use iroh::{EndpointAddr, EndpointId, RelayConfig, RelayMap, RelayMode, RelayUrl, TransportAddr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyError {
    Incomplete,
    Url,
    Mismatch,
    Peer,
    Transport,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Incomplete => "relay policy selection is incomplete",
            Self::Url => "relay policy origin is malformed",
            Self::Mismatch => "relay policy origins do not match",
            Self::Peer => "relay route peer does not match the configured endpoint",
            Self::Transport => "relay route refused a relay or custom transport",
        })
    }
}

impl std::error::Error for PolicyError {}

/// What an endpoint address currently advertises. `OwnNotAdvertised` is not
/// home-relay readiness and is not permission to fall back to Disabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservedRelaySet {
    Disabled,
    OwnNotAdvertised,
    OwnUrlOnly,
}

#[derive(Clone, PartialEq, Eq)]
pub struct OwnRelayPolicy {
    url: RelayUrl,
}

#[derive(Clone, PartialEq, Eq)]
pub enum RelayPolicy {
    Disabled,
    Own(OwnRelayPolicy),
}

fn canonical_origin(raw: &str) -> Result<RelayUrl, PolicyError> {
    let authority = raw.strip_prefix("https://").ok_or(PolicyError::Url)?;
    let authority = authority.strip_suffix('/').unwrap_or(authority);
    if authority.is_empty()
        || authority.chars().any(|ch| {
            ch.is_whitespace()
                || ch.is_control()
                || matches!(ch, '/' | '\\' | '?' | '#' | '@' | '%')
        })
    {
        return Err(PolicyError::Url);
    }
    let parsed = RelayUrl::from_str(raw).map_err(|_| PolicyError::Url)?;
    if parsed.scheme() != "https"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || !(parsed.path() == "/" || parsed.path().is_empty())
    {
        return Err(PolicyError::Url);
    }
    match parsed.port() {
        None | Some(443) => {}
        Some(_) => return Err(PolicyError::Url),
    }
    let host = parsed
        .host_str()
        .ok_or(PolicyError::Url)?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let dns = !host.is_empty()
        && host.split('.').all(|label| {
            let mut bytes = label.bytes();
            let Some(first) = bytes.next() else {
                return false;
            };
            let last = label.bytes().last().unwrap_or(first);
            first.is_ascii_alphanumeric()
                && last.is_ascii_alphanumeric()
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        });
    if !dns
        || ["iroh.link", "iroh.network"].into_iter().any(|suffix| {
            host == suffix
                || host
                    .strip_suffix(suffix)
                    .is_some_and(|rest| rest.ends_with('.'))
        })
    {
        return Err(PolicyError::Url);
    }
    let canonical =
        RelayUrl::from_str(&format!("https://{host}/")).map_err(|_| PolicyError::Url)?;
    if canonical.scheme() != "https" || canonical.port().is_some() {
        return Err(PolicyError::Url);
    }
    Ok(canonical)
}

fn ip_only(addrs: &BTreeSet<TransportAddr>) -> Result<(), PolicyError> {
    for addr in addrs {
        match addr {
            TransportAddr::Ip(_) => {}
            TransportAddr::Relay(_) | TransportAddr::Custom(_) => {
                return Err(PolicyError::Transport);
            }
            _ => return Err(PolicyError::Transport),
        }
    }
    Ok(())
}

impl RelayPolicy {
    pub fn from_local_manifest(
        selected_origin: Option<&str>,
        approved_origin: Option<&str>,
    ) -> Result<Self, PolicyError> {
        match (selected_origin, approved_origin) {
            (None, None) => Ok(Self::Disabled),
            (None, Some(_)) | (Some(_), None) => Err(PolicyError::Incomplete),
            (Some(selected), Some(approved)) => {
                let selected = canonical_origin(selected)?;
                let approved = canonical_origin(approved)?;
                if selected != approved {
                    return Err(PolicyError::Mismatch);
                }
                Ok(Self::Own(OwnRelayPolicy { url: selected }))
            }
        }
    }

    pub fn relay_url(&self) -> Option<&RelayUrl> {
        match self {
            Self::Disabled => None,
            Self::Own(policy) => Some(&policy.url),
        }
    }

    pub fn relay_mode(&self) -> Result<RelayMode, PolicyError> {
        let Self::Own(policy) = self else {
            return Ok(RelayMode::Disabled);
        };
        let url = policy.url.clone();
        let config = RelayConfig::new(url.clone(), None);
        if config.quic.is_some() || config.auth_token.is_some() {
            return Err(PolicyError::Url);
        }
        let map = RelayMap::empty();
        map.insert(url.clone(), Arc::new(config));
        if map.len() != 1
            || map
                .get(&url)
                .is_none_or(|stored| stored.quic.is_some() || stored.auth_token.is_some())
        {
            return Err(PolicyError::Url);
        }
        Ok(RelayMode::Custom(map))
    }

    /// Classify advertised relay URLs. An empty Own set is `OwnNotAdvertised`.
    pub fn observe_relay_urls<'a>(
        &self,
        observed: impl IntoIterator<Item = &'a RelayUrl>,
    ) -> Result<ObservedRelaySet, PolicyError> {
        let mut observed = observed.into_iter();
        let first = observed.next();
        if observed.next().is_some() {
            return Err(PolicyError::Transport);
        }
        match (self, first) {
            (Self::Disabled, None) => Ok(ObservedRelaySet::Disabled),
            (Self::Disabled, Some(_)) => Err(PolicyError::Transport),
            (Self::Own(_), None) => Ok(ObservedRelaySet::OwnNotAdvertised),
            (Self::Own(policy), Some(url)) if url == &policy.url => {
                Ok(ObservedRelaySet::OwnUrlOnly)
            }
            (Self::Own(_), Some(_)) => Err(PolicyError::Transport),
        }
    }

    /// Precondition: the caller already checked signature, pins, expiry, and revision.
    /// `expected_peer` is that caller's configured peer, not a Genesis admission.
    pub fn attach_verified_peer(
        &self,
        peer: EndpointAddr,
        expected_peer: EndpointId,
    ) -> Result<EndpointAddr, PolicyError> {
        if peer.id != expected_peer {
            return Err(PolicyError::Peer);
        }
        ip_only(&peer.addrs)?;
        let Self::Own(policy) = self else {
            return Ok(peer);
        };
        let direct = peer.addrs.clone();
        let url = policy.url.clone();
        let attached = peer.with_relay_url(url.clone());
        let relays = attached
            .addrs
            .iter()
            .filter(|addr| matches!(addr, TransportAddr::Relay(_)))
            .count();
        if attached.id != expected_peer
            || relays != 1
            || !attached.addrs.contains(&TransportAddr::Relay(url))
            || !direct.iter().all(|addr| attached.addrs.contains(addr))
        {
            return Err(PolicyError::Transport);
        }
        Ok(attached)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;
    use std::net::SocketAddr;

    const ORIGIN: &str = "https://pair-relay.invalid";
    const EXPLICIT: &str = "https://pair-relay.invalid:443";

    fn synthetic(seed: u8) -> EndpointId {
        SecretKey::from_bytes(&[seed; 32]).public()
    }

    fn policy(selected: &str, approved: &str) -> RelayPolicy {
        RelayPolicy::from_local_manifest(Some(selected), Some(approved)).unwrap()
    }

    fn ip(raw: &str) -> SocketAddr {
        raw.parse().unwrap()
    }

    #[test]
    fn absence_is_disabled_and_bad_input_is_not() {
        assert!(matches!(
            RelayPolicy::from_local_manifest(None, None).unwrap(),
            RelayPolicy::Disabled
        ));
        assert_eq!(
            RelayPolicy::from_local_manifest(Some(ORIGIN), None)
                .err()
                .unwrap(),
            PolicyError::Incomplete
        );
        assert_eq!(
            RelayPolicy::from_local_manifest(None, Some(EXPLICIT))
                .err()
                .unwrap(),
            PolicyError::Incomplete
        );
        for bad in [
            "http://pair-relay.invalid",
            "wss://pair-relay.invalid",
            "https://pair-relay.invalid/relay",
            "https://pair-relay.invalid/../",
            "https://pair-relay.invalid/%2e/",
            "https://pair-relay.invalid\\relay",
            "https://user:secret@pair-relay.invalid",
            "https://pair-relay.invalid/?from=peer",
            "https://pair-relay.invalid/#frag",
            "https://pair-relay.invalid:8443",
            "https://dns.iroh.link",
            "https://relay.iroh.network",
            "https://EU.RELAY.IROH.NETWORK./",
        ] {
            assert_eq!(
                RelayPolicy::from_local_manifest(Some(bad), Some(bad))
                    .err()
                    .unwrap(),
                PolicyError::Url,
                "{bad}"
            );
        }
        assert_eq!(
            RelayPolicy::from_local_manifest(Some(ORIGIN), Some("https://other-relay.invalid"))
                .err()
                .unwrap(),
            PolicyError::Mismatch
        );
    }

    #[test]
    fn one_url_feeds_the_custom_map_and_the_configured_peer() {
        let selected = policy(ORIGIN, EXPLICIT);
        let explicit = policy("https://PAIR-RELAY.invalid:443/", ORIGIN);
        assert_eq!(selected.relay_url(), explicit.relay_url());
        let url = selected.relay_url().unwrap().clone();
        let RelayMode::Custom(map) = selected.relay_mode().unwrap() else {
            panic!("custom");
        };
        assert_eq!(map.len(), 1);
        let stored = map.get(&url).unwrap();
        assert!(stored.quic.is_none() && stored.auth_token.is_none());
        let expected = synthetic(0x11);
        let other = synthetic(0x22);
        let (left, right) = (ip("203.0.113.10:1"), ip("203.0.113.11:2"));
        let peer = EndpointAddr::from_parts(
            expected,
            [TransportAddr::Ip(left), TransportAddr::Ip(right)],
        );
        let attached = selected.attach_verified_peer(peer, expected).unwrap();
        assert_eq!(attached.id, expected);
        assert_eq!(attached.addrs.len(), 3);
        assert!(attached.addrs.contains(&TransportAddr::Ip(left)));
        assert!(attached.addrs.contains(&TransportAddr::Ip(right)));
        assert!(attached.addrs.contains(&TransportAddr::Relay(url)));
        let wrong = EndpointAddr::new(other).with_ip_addr(left);
        assert_eq!(
            selected
                .attach_verified_peer(wrong, expected)
                .err()
                .unwrap(),
            PolicyError::Peer
        );
        let preexisting = EndpointAddr::new(expected)
            .with_ip_addr(left)
            .with_relay_url(selected.relay_url().unwrap().clone());
        assert_eq!(
            selected
                .attach_verified_peer(preexisting, expected)
                .err()
                .unwrap(),
            PolicyError::Transport
        );
        let custom = EndpointAddr::from_parts(
            expected,
            [
                TransportAddr::Ip(left),
                TransportAddr::Custom("7_01".parse().unwrap()),
            ],
        );
        assert_eq!(
            selected
                .attach_verified_peer(custom, expected)
                .err()
                .unwrap(),
            PolicyError::Transport
        );
        let disabled = RelayPolicy::from_local_manifest(None, None).unwrap();
        assert!(matches!(
            disabled.relay_mode().unwrap(),
            RelayMode::Disabled
        ));
        let plain = EndpointAddr::from_parts(
            expected,
            [TransportAddr::Ip(left), TransportAddr::Ip(right)],
        );
        let kept = disabled
            .attach_verified_peer(
                EndpointAddr::from_parts(
                    expected,
                    [TransportAddr::Ip(left), TransportAddr::Ip(right)],
                ),
                expected,
            )
            .unwrap();
        assert_eq!((kept.id, kept.addrs.clone()), (plain.id, plain.addrs));
        assert!(
            kept.addrs
                .iter()
                .all(|addr| matches!(addr, TransportAddr::Ip(_)))
        );
    }

    #[test]
    fn observed_relay_set_is_exact_and_empty_own_is_not_ready() {
        let own = policy(ORIGIN, EXPLICIT);
        let url = own.relay_url().unwrap().clone();
        let other: RelayUrl = "https://other-relay.invalid/".parse().unwrap();
        assert_eq!(
            own.observe_relay_urls(std::iter::empty()).unwrap(),
            ObservedRelaySet::OwnNotAdvertised
        );
        assert_eq!(
            own.observe_relay_urls([&url]).unwrap(),
            ObservedRelaySet::OwnUrlOnly
        );
        assert_eq!(
            own.observe_relay_urls([&other]).err().unwrap(),
            PolicyError::Transport
        );
        assert_eq!(
            own.observe_relay_urls([&url, &url]).err().unwrap(),
            PolicyError::Transport
        );
        let disabled = RelayPolicy::from_local_manifest(None, None).unwrap();
        assert_eq!(
            disabled.observe_relay_urls(std::iter::empty()).unwrap(),
            ObservedRelaySet::Disabled
        );
        assert_eq!(
            disabled.observe_relay_urls([&url]).err().unwrap(),
            PolicyError::Transport
        );
    }
}
