//! Application state shared by commands, the SSH server, and background tasks.
use crate::{
    db::{self, TransferRow, TrustedPeer},
    discovery::{DiscoveredPeer, Discovery},
    identity::Identity,
    net::{self, PAIRING_WINDOW},
};
use rusqlite::Connection;
use serde::Serialize;
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio::sync::oneshot;

#[derive(Clone, Debug, Serialize)]
pub struct Device {
    pub id: String,
    pub name: String,
    pub state: String,
    pub trusted: bool,
    pub fingerprint: String,
    pub address: Option<String>,
    pub port: Option<u16>,
    pub last_seen: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Transfer {
    pub id: String,
    pub device_name: String,
    pub file_name: String,
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub speed_bps: u64,
    pub state: String,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct IdentityInfo {
    pub device_id: String,
    pub name: String,
    pub fingerprint: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct PairingPrompt {
    pub device_id: String,
    pub device_name: String,
    pub code: String,
    pub expires_in_secs: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct PairingResult {
    pub device_id: String,
    pub ok: bool,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct TransferResult {
    pub transfer_id: String,
    pub file_name: String,
    pub state: String,
    pub error: Option<String>,
}

/// All UI notifications funnel through this trait so the core can run headless in tests.
pub trait Events: Send + Sync + 'static {
    fn devices_changed(&self, devices: Vec<Device>);
    fn transfers_changed(&self, transfers: Vec<Transfer>);
    fn pairing_code(&self, prompt: PairingPrompt);
    fn pairing_incoming(&self, prompt: PairingPrompt);
    fn pairing_result(&self, result: PairingResult);
    fn transfer_finished(&self, result: TransferResult);
}

pub struct TauriEvents(pub tauri::AppHandle);

impl Events for TauriEvents {
    fn devices_changed(&self, devices: Vec<Device>) {
        let _ = tauri::Emitter::emit(&self.0, "devices://changed", devices);
    }
    fn transfers_changed(&self, transfers: Vec<Transfer>) {
        let _ = tauri::Emitter::emit(&self.0, "transfer://progress", transfers);
    }
    fn pairing_code(&self, prompt: PairingPrompt) {
        let _ = tauri::Emitter::emit(&self.0, "pairing://code", prompt);
    }
    fn pairing_incoming(&self, prompt: PairingPrompt) {
        let _ = tauri::Emitter::emit(&self.0, "pairing://incoming", prompt);
    }
    fn pairing_result(&self, result: PairingResult) {
        let _ = tauri::Emitter::emit(&self.0, "pairing://result", result);
    }
    fn transfer_finished(&self, result: TransferResult) {
        let _ = tauri::Emitter::emit(&self.0, "transfer://finished", result);
    }
}

pub struct NoEvents;

impl Events for NoEvents {
    fn devices_changed(&self, _devices: Vec<Device>) {}
    fn transfers_changed(&self, _transfers: Vec<Transfer>) {}
    fn pairing_code(&self, _prompt: PairingPrompt) {}
    fn pairing_incoming(&self, _prompt: PairingPrompt) {}
    fn pairing_result(&self, _result: PairingResult) {}
    fn transfer_finished(&self, _result: TransferResult) {}
}

pub struct PendingPairing {
    pub prompt: PairingPrompt,
    pub decision: Option<oneshot::Sender<bool>>,
    pub is_responder: bool,
    pub started: Instant,
}

pub struct LiveTransfer {
    pub done: u64,
    pub total: u64,
    pub speed_bps: u64,
    pub cancel: Arc<AtomicBool>,
    pub started: Instant,
    pub last_emit: Instant,
    pub last_persist: Instant,
}

/// A data channel plus any bytes already buffered from it.
pub type DataChannel = (
    russh::ChannelReadHalf,
    russh::ChannelWriteHalf<russh::server::Msg>,
    Vec<u8>,
);

/// A transfer the local side has accepted and is waiting to receive on a data channel.
pub struct IncomingSlot {
    pub device_name: String,
    pub file_name: String,
    pub total: u64,
    pub cancel: Arc<AtomicBool>,
    pub data_ready: Option<oneshot::Sender<DataChannel>>,
}

pub struct Shared {
    pub db: Mutex<Connection>,
    pub identity: Identity,
    pub events: Arc<dyn Events>,
    pub discovery: Mutex<Option<Arc<Discovery>>>,
    pub pairing: Mutex<HashMap<String, PendingPairing>>,
    pub live: Mutex<HashMap<String, LiveTransfer>>,
    pub incoming: Mutex<HashMap<String, IncomingSlot>>,
    pub server_config: Arc<russh::server::Config>,
    pub port: AtomicU16,
    pub connections: AtomicUsize,
    pub app_dir: PathBuf,
    pub discovery_error: Mutex<Option<String>>,
    /// Peers supplied out-of-band (tests, or a future manual "connect by address" flow).
    pub static_peers: Mutex<HashMap<String, DiscoveredPeer>>,
    pub downloads_override: Mutex<Option<PathBuf>>,
}

impl Shared {
    pub fn new(
        db: Connection,
        identity: Identity,
        events: Arc<dyn Events>,
        app_dir: PathBuf,
    ) -> Self {
        let server_config = Arc::new(russh::server::Config {
            keys: vec![(*identity.host).clone()],
            inactivity_timeout: Some(Duration::from_secs(300)),
            auth_rejection_time: Duration::from_millis(80),
            auth_rejection_time_initial: Some(Duration::from_millis(0)),
            max_auth_attempts: 3,
            nodelay: true,
            ..Default::default()
        });
        Self {
            db: Mutex::new(db),
            identity,
            events,
            discovery: Mutex::new(None),
            pairing: Mutex::new(HashMap::new()),
            live: Mutex::new(HashMap::new()),
            incoming: Mutex::new(HashMap::new()),
            server_config,
            port: AtomicU16::new(0),
            connections: AtomicUsize::new(0),
            app_dir,
            discovery_error: Mutex::new(None),
            static_peers: Mutex::new(HashMap::new()),
            downloads_override: Mutex::new(None),
        }
    }

    pub fn with_db<T>(&self, f: impl FnOnce(&Connection) -> T) -> Result<T, String> {
        let db = self.db.lock().map_err(|_| "database unavailable")?;
        Ok(f(&db))
    }

    pub fn identity_info(&self) -> IdentityInfo {
        IdentityInfo {
            device_id: self.identity.device_id.clone(),
            name: self.identity.name.clone(),
            fingerprint: self.identity.host_fingerprint(),
        }
    }

    pub fn trusted(&self, id: &str) -> Option<TrustedPeer> {
        self.with_db(|db| db::trusted_peer(db, id)).ok().flatten()
    }

    pub fn devices(&self) -> Vec<Device> {
        let trusted = self.with_db(db::list_trusted).unwrap_or_default();
        let mut discovered = self
            .discovery
            .lock()
            .ok()
            .and_then(|d| d.as_ref().map(|d| d.peers()))
            .unwrap_or_default();
        if let Ok(static_peers) = self.static_peers.lock() {
            for peer in static_peers.values() {
                if !discovered.iter().any(|p| p.id == peer.id) {
                    discovered.push(peer.clone());
                }
            }
        }

        let mut devices: Vec<Device> = Vec::new();
        let mut seen = HashSet::new();
        for peer in discovered {
            let known = trusted.iter().find(|t| t.id == peer.id);
            seen.insert(peer.id.clone());
            devices.push(Device {
                id: peer.id,
                name: known.map(|k| k.name.clone()).unwrap_or(peer.name),
                state: "online".into(),
                trusted: known.is_some(),
                fingerprint: known
                    .map(|k| k.fingerprint.clone())
                    .unwrap_or(peer.fingerprint),
                address: Some(peer.address),
                port: Some(peer.port),
                last_seen: None,
            });
        }
        for peer in trusted {
            if seen.contains(&peer.id) {
                continue;
            }
            devices.push(Device {
                id: peer.id,
                name: peer.name,
                state: "offline".into(),
                trusted: true,
                fingerprint: peer.fingerprint,
                address: None,
                port: None,
                last_seen: peer.last_seen,
            });
        }
        devices.sort_by(|a, b| {
            (a.state != "online", a.name.to_lowercase())
                .cmp(&(b.state != "online", b.name.to_lowercase()))
        });
        devices
    }

    pub fn emit_devices(&self) {
        self.events.devices_changed(self.devices());
    }

    pub fn transfers(&self) -> Vec<Transfer> {
        let rows = self
            .with_db(|db| db::list_transfers(db, 30))
            .unwrap_or_default();
        let live = self.live.lock().ok();
        rows.into_iter()
            .map(|row| {
                let runtime = live.as_ref().and_then(|l| l.get(&row.id));
                Transfer {
                    id: row.id,
                    device_name: row.device_name,
                    file_name: row.file_name,
                    bytes_done: runtime.map(|r| r.done).unwrap_or(row.bytes_done),
                    bytes_total: row.bytes_total,
                    speed_bps: runtime.map(|r| r.speed_bps).unwrap_or(0),
                    state: row.state,
                    error: row.error,
                }
            })
            .collect()
    }

    pub fn emit_transfers(&self) {
        self.events.transfers_changed(self.transfers());
    }

    pub fn discovered_peer(&self, id: &str) -> Option<DiscoveredPeer> {
        self.discovery
            .lock()
            .ok()
            .and_then(|d| d.as_ref().and_then(|d| d.peer(id)))
            .or_else(|| {
                self.static_peers
                    .lock()
                    .ok()
                    .and_then(|peers| peers.get(id).cloned())
            })
    }

    /// Register a peer without mDNS (tests).
    pub fn add_static_peer(&self, peer: DiscoveredPeer) {
        if let Ok(mut peers) = self.static_peers.lock() {
            peers.insert(peer.id.clone(), peer);
        }
    }

    pub fn set_downloads_dir(&self, path: PathBuf) {
        if let Ok(mut slot) = self.downloads_override.lock() {
            *slot = Some(path);
        }
    }

    pub fn discovery(&self) -> Option<Arc<Discovery>> {
        self.discovery.lock().ok().and_then(|d| d.clone())
    }

    pub fn register_pairing(&self, key: String, pending: PendingPairing) -> bool {
        match self.pairing.lock() {
            Ok(mut map) => {
                if map.contains_key(&key) {
                    return false;
                }
                map.insert(key, pending);
                true
            }
            Err(_) => false,
        }
    }

    /// Hand the local decision to the waiting pairing task. Returns false if no session is pending.
    pub fn decide_pairing(&self, device_id: &str, accepted: bool) -> bool {
        let sender = self
            .pairing
            .lock()
            .ok()
            .and_then(|mut map| map.get_mut(device_id).and_then(|p| p.decision.take()));
        match sender {
            Some(tx) => {
                let _ = tx.send(accepted);
                true
            }
            None => false,
        }
    }

    pub fn clear_pairing(&self, device_id: &str) {
        if let Ok(mut map) = self.pairing.lock() {
            map.remove(device_id);
        }
    }

    pub fn pairing_prompt(&self, device_id: &str) -> Option<PairingPrompt> {
        self.pairing
            .lock()
            .ok()
            .and_then(|map| map.get(device_id).map(|p| p.prompt.clone()))
    }

    pub fn start_live(&self, transfer_id: &str, total: u64) -> Arc<AtomicBool> {
        let cancel = Arc::new(AtomicBool::new(false));
        self.start_live_with(transfer_id, total, cancel)
    }

    /// Register live progress for a transfer whose cancellation flag is owned elsewhere.
    pub fn start_live_with(
        &self,
        transfer_id: &str,
        total: u64,
        cancel: Arc<AtomicBool>,
    ) -> Arc<AtomicBool> {
        if let Ok(mut live) = self.live.lock() {
            let now = Instant::now();
            live.insert(
                transfer_id.to_owned(),
                LiveTransfer {
                    done: 0,
                    total,
                    speed_bps: 0,
                    cancel: cancel.clone(),
                    started: now,
                    last_emit: now - Duration::from_secs(1),
                    last_persist: now,
                },
            );
        }
        cancel
    }

    /// Record progress and emit at most every 250 ms; persist at most every 2 s.
    pub fn record_progress(&self, transfer_id: &str, done: u64) {
        let mut should_emit = false;
        let mut should_persist = false;
        if let Ok(mut live) = self.live.lock() {
            if let Some(entry) = live.get_mut(transfer_id) {
                entry.done = done;
                let elapsed = entry.started.elapsed().as_secs_f64().max(0.001);
                entry.speed_bps = (done as f64 / elapsed) as u64;
                if entry.last_emit.elapsed() >= Duration::from_millis(250) {
                    entry.last_emit = Instant::now();
                    should_emit = true;
                }
                if entry.last_persist.elapsed() >= Duration::from_secs(2) {
                    entry.last_persist = Instant::now();
                    should_persist = true;
                }
            }
        }
        if should_emit {
            self.emit_transfers();
        }
        if should_persist {
            let _ = self.with_db(|db| db::update_transfer(db, transfer_id, done, "active", None));
        }
    }

    pub fn finish_transfer(&self, transfer_id: &str, state: &str, error: Option<&str>) {
        let done = self
            .live
            .lock()
            .ok()
            .and_then(|mut live| live.remove(transfer_id))
            .map(|entry| entry.done)
            .unwrap_or_else(|| {
                self.with_db(|db| {
                    db::list_transfers(db, 30)
                        .into_iter()
                        .find(|r| r.id == transfer_id)
                        .map(|r| r.bytes_done)
                        .unwrap_or(0)
                })
                .unwrap_or(0)
            });
        let _ = self.with_db(|db| db::update_transfer(db, transfer_id, done, state, error));
        let file_name = self
            .with_db(|db| {
                db::list_transfers(db, 30)
                    .into_iter()
                    .find(|r| r.id == transfer_id)
                    .map(|r| r.file_name)
            })
            .ok()
            .flatten()
            .unwrap_or_default();
        self.emit_transfers();
        self.events.transfer_finished(TransferResult {
            transfer_id: transfer_id.to_owned(),
            file_name,
            state: state.to_owned(),
            error: error.map(str::to_owned),
        });
    }

    pub fn with_db_write(
        &self,
        f: impl FnOnce(&Connection) -> rusqlite::Result<()>,
    ) -> Result<(), String> {
        let db = self.db.lock().map_err(|_| "database unavailable")?;
        f(&db).map_err(|e| e.to_string())
    }

    pub fn downloads_dir(&self) -> PathBuf {
        if let Some(path) = self.downloads_override.lock().ok().and_then(|p| p.clone()) {
            return path;
        }
        use directories::UserDirs;
        let base = UserDirs::new()
            .and_then(|u| u.download_dir().map(|p| p.to_path_buf()))
            .unwrap_or_else(|| self.app_dir.join("Downloads"));
        base.join("Henad")
    }

    pub fn pairing_window(&self) -> Duration {
        PAIRING_WINDOW
    }

    pub fn port(&self) -> u16 {
        self.port.load(Ordering::SeqCst)
    }

    pub fn set_discovery_error(&self, error: String) {
        if let Ok(mut slot) = self.discovery_error.lock() {
            *slot = Some(error);
        }
    }

    pub fn discovery_error(&self) -> Option<String> {
        self.discovery_error.lock().ok().and_then(|e| e.clone())
    }

    pub fn upsert_transfer(&self, row: &TransferRow) {
        let _ = self.with_db(|db| db::insert_transfer(db, row));
    }

    /// Reject and clean up expired pairing prompts.
    pub fn sweep_pairings(&self) -> Vec<String> {
        let expired: Vec<String> = match self.pairing.lock() {
            Ok(map) => map
                .iter()
                .filter(|(_, p)| p.started.elapsed() > PAIRING_WINDOW)
                .map(|(id, _)| id.clone())
                .collect(),
            Err(_) => Vec::new(),
        };
        for id in &expired {
            if let Some(pending) = self.pairing.lock().ok().and_then(|mut map| map.remove(id)) {
                if let Some(tx) = pending.decision {
                    let _ = tx.send(false);
                }
                self.events.pairing_result(PairingResult {
                    device_id: id.clone(),
                    ok: false,
                    error: Some("the pairing code expired".into()),
                });
            }
        }
        expired
    }

    pub fn net_timeouts(&self) -> (Duration, Duration) {
        (net::HANDSHAKE_TIMEOUT, net::PAIRING_WINDOW)
    }
}
