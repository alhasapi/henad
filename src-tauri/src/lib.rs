//! Henad: offline-first, peer-to-peer file transfer over SSH on the local network.
pub mod core;
pub mod db;
pub mod discovery;
pub mod identity;
pub mod net;
pub mod pairing;
pub mod protocol;
pub mod service;
pub mod state;
pub mod transfer;

use directories::ProjectDirs;
use discovery::Discovery;
use identity::Identity;
use serde::Serialize;
use state::{Device, IdentityInfo, PairingPrompt, Shared, TauriEvents, Transfer};
use std::{
    fs,
    path::PathBuf,
    sync::{atomic::Ordering, Arc},
    time::Duration,
};
use tauri::{Manager, State};
use tokio::net::TcpListener;
use uuid::Uuid;

#[derive(Serialize)]
pub struct AppStatus {
    pub discovery_error: Option<String>,
    pub port: u16,
    pub protocol_version: u16,
}

#[tauri::command]
fn list_devices(state: State<'_, Arc<Shared>>) -> Vec<Device> {
    state.devices()
}

#[tauri::command]
fn list_transfers(state: State<'_, Arc<Shared>>) -> Vec<Transfer> {
    state.transfers()
}

#[tauri::command]
fn local_identity(state: State<'_, Arc<Shared>>) -> IdentityInfo {
    state.identity_info()
}

#[tauri::command]
fn app_status(state: State<'_, Arc<Shared>>) -> AppStatus {
    AppStatus {
        discovery_error: state.discovery_error(),
        port: state.port(),
        protocol_version: core::PROTOCOL_VERSION,
    }
}

#[tauri::command]
async fn start_pairing(
    state: State<'_, Arc<Shared>>,
    device_id: String,
) -> Result<PairingPrompt, String> {
    pairing::initiate(state.inner().clone(), &device_id)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn confirm_pairing(
    state: State<'_, Arc<Shared>>,
    device_id: String,
    accepted: bool,
) -> Result<(), String> {
    if state.decide_pairing(&device_id, accepted) {
        Ok(())
    } else {
        Err("no pairing is waiting for confirmation".into())
    }
}

#[tauri::command]
async fn cancel_pairing(state: State<'_, Arc<Shared>>, device_id: String) -> Result<(), String> {
    state.decide_pairing(&device_id, false);
    Ok(())
}

#[tauri::command]
async fn unpair_device(state: State<'_, Arc<Shared>>, device_id: String) -> Result<(), String> {
    state.with_db_write(|db| db::unpair(db, &device_id))?;
    state.emit_devices();
    Ok(())
}

#[tauri::command]
async fn send_file(
    state: State<'_, Arc<Shared>>,
    device_id: String,
    path: String,
) -> Result<String, String> {
    transfer::queue(state.inner(), &device_id, &path)
}

#[tauri::command]
async fn resume_transfer(state: State<'_, Arc<Shared>>, transfer_id: String) -> Result<(), String> {
    transfer::resume(state.inner(), &transfer_id)
}

#[tauri::command]
async fn cancel_transfer(state: State<'_, Arc<Shared>>, transfer_id: String) -> Result<(), String> {
    transfer::cancel(state.inner(), &transfer_id);
    Ok(())
}

fn app_dir() -> PathBuf {
    ProjectDirs::from("org", "Henad", "Henad")
        .map(|dirs| dirs.data_local_dir().to_path_buf())
        .unwrap_or_else(|| std::env::temp_dir().join("henad"))
}

fn default_name() -> String {
    let host = hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "this computer".into());
    format!("Henad on {host}")
}

async fn bind_listener() -> std::io::Result<TcpListener> {
    match TcpListener::bind(("0.0.0.0", net::DEFAULT_PORT)).await {
        Ok(listener) => Ok(listener),
        Err(_) => TcpListener::bind(("0.0.0.0", 0)).await,
    }
}

async fn bootstrap(app: tauri::AppHandle) -> Result<Arc<Shared>, String> {
    let dir = app_dir();
    fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let connection = db::open(&dir.join("henad.sqlite3")).map_err(|e| e.to_string())?;

    let device_id = db::setting(&connection, "device_id").unwrap_or_else(|| {
        let id = Uuid::new_v4().to_string();
        let _ = db::set_setting(&connection, "device_id", &id);
        id
    });
    let name = db::setting(&connection, "local_name").unwrap_or_else(default_name);
    let identity = Identity::load_or_create(&dir, device_id, name.clone())
        .map_err(|e| format!("could not load this device's keys: {e}"))?;
    let _ = db::set_setting(&connection, "local_name", &identity.name);

    let shared = Arc::new(Shared::new(
        connection,
        identity,
        Arc::new(TauriEvents(app)),
        dir,
    ));

    let listener = bind_listener()
        .await
        .map_err(|e| format!("could not open the Henad port: {e}"))?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    shared.port.store(port, Ordering::SeqCst);
    tokio::spawn(service::serve(shared.clone(), listener));

    {
        let notifier = shared.clone();
        let notify = Arc::new(move || {
            notifier.sweep_pairings();
            notifier.emit_devices();
        });
        match Discovery::start(
            shared.identity.device_id.clone(),
            shared.identity.name.clone(),
            shared.identity.host_fingerprint(),
            port,
            notify,
        ) {
            Ok(discovery) => {
                if let Ok(mut slot) = shared.discovery.lock() {
                    *slot = Some(Arc::new(discovery));
                }
            }
            Err(error) => shared.set_discovery_error(error),
        }
    }

    {
        let shared = shared.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                shared.sweep_pairings();
            }
        });
    }

    shared.emit_devices();
    shared.emit_transfers();
    Ok(shared)
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            let handle = app.handle().clone();
            let shared = tauri::async_runtime::block_on(bootstrap(handle))?;
            app.manage(shared);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            list_devices,
            list_transfers,
            local_identity,
            app_status,
            start_pairing,
            confirm_pairing,
            cancel_pairing,
            unpair_device,
            send_file,
            resume_transfer,
            cancel_transfer
        ])
        .build(tauri::generate_context!())
        .expect("error while building Henad")
        .run(|app, event| {
            if let tauri::RunEvent::Exit = event {
                if let Some(shared) = app.try_state::<Arc<Shared>>() {
                    if let Some(discovery) = shared.discovery() {
                        discovery.shutdown();
                    }
                }
            }
        });
}
