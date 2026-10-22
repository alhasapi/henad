//! Zero-configuration discovery over mDNS.
//!
//! Discovery records are hints only. Trust comes from the pairing transcript, and
//! the SSH host key must match both the pinned key (when paired) and the advertised
//! fingerprint (when known).
use crate::net::{local_ipv4, SERVICE_TYPE};
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use serde::Serialize;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

// mDNS responders announce in a short burst (1 s, 2 s, 4 s, …) and then stay quiet until
// their records change or a TTL (120 s) lapses. Peers are therefore removed by the
// browser's own `ServiceRemoved` event — which fires on a goodbye packet or TTL expiry —
// rather than by a short staleness cutoff, which emptied the list seconds after launch.
const TTL_HINT_MS: i64 = 120_000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DiscoveredPeer {
    pub id: String,
    pub name: String,
    pub fingerprint: String,
    pub address: String,
    pub port: u16,
    pub fullname: String,
    /// Last time the peer was resolved, in epoch milliseconds (for display only).
    pub last_seen: i64,
}

pub struct Discovery {
    daemon: ServiceDaemon,
    fullname: String,
    peers: Arc<Mutex<HashMap<String, DiscoveredPeer>>>,
}

impl Discovery {
    /// Advertise this device and start listening for peers.
    ///
    /// `notify` is called whenever the peer set changes; it is expected to push a
    /// fresh snapshot to the UI.
    pub fn start(
        local_id: String,
        local_name: String,
        fingerprint: String,
        port: u16,
        notify: Arc<dyn Fn() + Send + Sync>,
    ) -> Result<Self, String> {
        let daemon = ServiceDaemon::new().map_err(|e| format!("mDNS unavailable: {e}"))?;

        let host = hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "henad".into());
        let host = sanitize_label(&host);
        let instance = format!("Henad on {host}");
        let ip = local_ipv4()
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "127.0.0.1".into());
        let props = [
            ("id", local_id.as_str()),
            ("name", local_name.as_str()),
            ("v", "2"),
            ("fp", fingerprint.as_str()),
        ];
        let info = ServiceInfo::new(
            SERVICE_TYPE,
            &instance,
            &format!("{host}.local."),
            ip,
            port,
            &props[..],
        )
        .map_err(|e| format!("could not build the mDNS record: {e}"))?;
        let fullname = info.get_fullname().to_string();
        daemon
            .register(info)
            .map_err(|e| format!("could not advertise over mDNS: {e}"))?;

        let receiver = daemon
            .browse(SERVICE_TYPE)
            .map_err(|e| format!("could not browse mDNS: {e}"))?;
        let peers: Arc<Mutex<HashMap<String, DiscoveredPeer>>> = Arc::default();

        {
            let peers = peers.clone();
            let notify = notify.clone();
            let local_id = local_id.clone();
            std::thread::spawn(move || {
                while let Ok(event) = receiver.recv() {
                    let changed = match event {
                        ServiceEvent::ServiceResolved(info) => {
                            let Some(id) = info.get_property_val_str("id") else {
                                continue;
                            };
                            if id == local_id {
                                continue;
                            }
                            let Some(address) = info
                                .get_addresses_v4()
                                .into_iter()
                                .next()
                                .map(|ip| ip.to_string())
                            else {
                                continue;
                            };
                            let name = info
                                .get_property_val_str("name")
                                .map(str::to_owned)
                                .unwrap_or_else(|| {
                                    info.get_fullname()
                                        .split('.')
                                        .next()
                                        .unwrap_or("Henad device")
                                        .to_owned()
                                });
                            let fingerprint = info
                                .get_property_val_str("fp")
                                .unwrap_or_default()
                                .to_owned();
                            let peer = DiscoveredPeer {
                                id: id.to_owned(),
                                name,
                                fingerprint,
                                address,
                                port: info.get_port(),
                                fullname: info.get_fullname().to_owned(),
                                last_seen: now_ms(),
                            };
                            if let Ok(mut peers) = peers.lock() {
                                let changed = match peers.get(id) {
                                    Some(old) => {
                                        old.address != peer.address
                                            || old.port != peer.port
                                            || old.name != peer.name
                                            || old.fingerprint != peer.fingerprint
                                    }
                                    None => true,
                                };
                                peers.insert(peer.id.clone(), peer);
                                changed
                            } else {
                                false
                            }
                        }
                        ServiceEvent::ServiceRemoved(_, fullname) => {
                            let mut changed = false;
                            if let Ok(mut peers) = peers.lock() {
                                let before = peers.len();
                                peers.retain(|_, p| p.fullname != fullname);
                                changed = peers.len() != before;
                            }
                            changed
                        }
                        _ => false,
                    };
                    if changed {
                        notify();
                    }
                }
            });
        }

        Ok(Self {
            daemon,
            fullname,
            peers,
        })
    }

    pub fn peers(&self) -> Vec<DiscoveredPeer> {
        let now = now_ms();
        let mut peers: Vec<_> = self
            .peers
            .lock()
            .map(|p| {
                p.values()
                    .filter(|peer| is_fresh(peer, now))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        peers.sort_by_key(|peer| peer.name.to_lowercase());
        peers
    }

    pub fn peer(&self, id: &str) -> Option<DiscoveredPeer> {
        self.peers
            .lock()
            .ok()
            .and_then(|p| p.get(id).cloned())
            .filter(|peer| is_fresh(peer, now_ms()))
    }

    pub fn shutdown(&self) {
        let _ = self.daemon.unregister(&self.fullname);
        let _ = self.daemon.shutdown();
    }
}

/// mDNS records expire after their 120 s TTL; treat an older resolution as gone even if the
/// goodbye packet never arrived (a peer that crashed rather than quit).
fn is_fresh(peer: &DiscoveredPeer, now: i64) -> bool {
    now - peer.last_seen <= TTL_HINT_MS
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or_default()
}

/// mDNS instance names cannot contain dots; keep hostnames readable but safe.
fn sanitize_label(value: &str) -> String {
    let cleaned: String = value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = cleaned.trim_matches('-');
    if trimmed.is_empty() {
        "henad".into()
    } else {
        trimmed.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::sanitize_label;

    #[test]
    fn host_labels_are_mdns_safe() {
        assert_eq!(sanitize_label("my-laptop"), "my-laptop");
        assert_eq!(sanitize_label("My Laptop.local"), "My-Laptop-local");
        assert_eq!(sanitize_label("***"), "henad");
    }
}
