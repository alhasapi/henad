//! Shared harness for the loopback integration tests.
#![allow(dead_code)]

use henad_lib::db;
use henad_lib::discovery::DiscoveredPeer;
use henad_lib::identity::Identity;
use henad_lib::service;
use henad_lib::state::{
    Device, Events, IncomingResult, IncomingTransfer, PairingPrompt, PairingResult, Shared,
    Transfer, TransferResult,
};
use std::{
    fs,
    path::PathBuf,
    sync::{atomic::Ordering, Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::net::TcpListener;

#[derive(Default)]
pub struct Recorder {
    pub devices: Mutex<Vec<Device>>,
    pub transfers: Mutex<Vec<Transfer>>,
    pub codes: Mutex<Vec<PairingPrompt>>,
    pub incoming: Mutex<Vec<PairingPrompt>>,
    pub results: Mutex<Vec<PairingResult>>,
    pub finished: Mutex<Vec<TransferResult>>,
    pub offers: Mutex<Vec<IncomingTransfer>>,
    pub offers_closed: Mutex<Vec<IncomingResult>>,
}

impl Events for Recorder {
    fn devices_changed(&self, devices: Vec<Device>) {
        *self.devices.lock().unwrap() = devices;
    }
    fn transfers_changed(&self, transfers: Vec<Transfer>) {
        *self.transfers.lock().unwrap() = transfers;
    }
    fn pairing_code(&self, prompt: PairingPrompt) {
        self.codes.lock().unwrap().push(prompt);
    }
    fn pairing_incoming(&self, prompt: PairingPrompt) {
        self.incoming.lock().unwrap().push(prompt);
    }
    fn pairing_result(&self, result: PairingResult) {
        self.results.lock().unwrap().push(result);
    }
    fn transfer_finished(&self, result: TransferResult) {
        self.finished.lock().unwrap().push(result);
    }
    fn transfer_incoming(&self, prompt: IncomingTransfer) {
        self.offers.lock().unwrap().push(prompt);
    }
    fn transfer_incoming_closed(&self, result: IncomingResult) {
        self.offers_closed.lock().unwrap().push(result);
    }
}

pub struct Endpoint {
    pub shared: Arc<Shared>,
    pub events: Arc<Recorder>,
    pub dir: PathBuf,
}

pub async fn endpoint(id: &str, name: &str) -> Endpoint {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("henad-it-{id}-{stamp}"));
    fs::create_dir_all(&dir).unwrap();

    let db = db::open(&dir.join("henad.sqlite3")).unwrap();
    let identity = Identity::load_or_create(&dir, id.to_owned(), name.to_owned()).unwrap();
    let events = Arc::new(Recorder::default());
    let shared = Arc::new(Shared::new(db, identity, events.clone(), dir.clone()));

    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    shared.port.store(port, Ordering::SeqCst);
    tokio::spawn(service::serve(shared.clone(), listener));

    let downloads = dir.join("Downloads");
    fs::create_dir_all(&downloads).unwrap();
    shared.set_downloads_dir(downloads);

    Endpoint {
        shared,
        events,
        dir,
    }
}

pub fn peer_of(other: &Endpoint, name: &str) -> DiscoveredPeer {
    DiscoveredPeer {
        id: other.shared.identity.device_id.clone(),
        name: name.to_owned(),
        fingerprint: other.shared.identity.host_fingerprint(),
        address: "127.0.0.1".into(),
        port: other.shared.port(),
        fullname: "loopback._henad._tcp.local.".into(),
        last_seen: 1,
    }
}

pub async fn wait_until<F: FnMut() -> bool>(mut check: F, within: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + within;
    while tokio::time::Instant::now() < deadline {
        if check() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    check()
}

/// Pair two loopback endpoints, returning the two confirmation codes.
pub async fn pair(a: &Endpoint, b: &Endpoint) -> (String, String) {
    a.shared.add_static_peer(peer_of(b, "Henad on beta"));
    b.shared.add_static_peer(peer_of(a, "Henad on alpha"));

    let prompt_a = henad_lib::pairing::initiate(a.shared.clone(), &b.shared.identity.device_id)
        .await
        .expect("pairing should start");

    let b_id = b.shared.identity.device_id.clone();
    let prompt_b = loop {
        if let Some(prompt) = b.events.incoming.lock().unwrap().first().cloned() {
            break prompt;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    };
    assert_eq!(prompt_b.device_id, a.shared.identity.device_id);

    assert!(a.shared.decide_pairing(&b.shared.identity.device_id, true));
    assert!(b.shared.decide_pairing(&a.shared.identity.device_id, true));

    let a_id = a.shared.identity.device_id.clone();
    let paired = wait_until(
        || {
            a.shared.trusted(&b_id).is_some()
                && b.shared.trusted(&a_id).is_some()
                && !b.events.results.lock().unwrap().is_empty()
        },
        Duration::from_secs(10),
    )
    .await;
    assert!(paired, "both sides should pin the peer after confirming");

    // Tests that are not about consent accept automatically.
    a.shared
        .with_db(|db| henad_lib::db::set_auto_accept(db, &b_id, true))
        .expect("database")
        .expect("auto accept");
    b.shared
        .with_db(|db| henad_lib::db::set_auto_accept(db, &a_id, true))
        .expect("database")
        .expect("auto accept");

    (prompt_a.code, prompt_b.code)
}
