mod core;
mod protocol;

use core::{confirmation_code, fingerprint, fresh_nonce, pairing_transcript};
use directories::ProjectDirs;
use rusqlite::{params, Connection};
use serde::Serialize;
use std::{fs, path::PathBuf, sync::Mutex};
use tauri::State;
use uuid::Uuid;

#[derive(Serialize)]
struct Device {
    id: String,
    name: String,
    state: String,
    fingerprint: String,
    last_seen: Option<String>,
}
#[derive(Serialize)]
struct Transfer {
    id: String,
    device_name: String,
    file_name: String,
    bytes_done: u64,
    bytes_total: u64,
    state: String,
    speed_bps: u64,
}
struct AppState {
    db: Mutex<Connection>,
    local_id: String,
    local_host: Vec<u8>,
    local_client: Vec<u8>,
}

fn app_data() -> PathBuf {
    ProjectDirs::from("org", "Henad", "Henad")
        .expect("supported platform")
        .data_local_dir()
        .to_path_buf()
}
fn open_db() -> Connection {
    let dir = app_data();
    fs::create_dir_all(&dir).expect("create app data");
    let db = Connection::open(dir.join("henad.sqlite3")).expect("open database");
    db.execute_batch("PRAGMA foreign_keys=ON;
      CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS devices (id TEXT PRIMARY KEY, name TEXT NOT NULL, fingerprint TEXT NOT NULL, trusted INTEGER NOT NULL DEFAULT 0, last_seen TEXT);
      CREATE TABLE IF NOT EXISTS transfers (id TEXT PRIMARY KEY, device_id TEXT NOT NULL, file_name TEXT NOT NULL, source_path TEXT NOT NULL, bytes_done INTEGER NOT NULL DEFAULT 0, bytes_total INTEGER NOT NULL DEFAULT 0, state TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);" ).expect("migrate database");
    db
}
fn saved_identity(db: &Connection, key: &str) -> Vec<u8> {
    if let Ok(value) = db.query_row("SELECT value FROM settings WHERE key=?", [key], |r| {
        r.get::<_, String>(0)
    }) {
        return hex::decode(value).expect("identity encoding");
    }
    let mut value = vec![0; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut value);
    db.execute(
        "INSERT INTO settings(key,value) VALUES (?,?)",
        params![key, hex::encode(&value)],
    )
    .expect("save identity");
    value
}
#[tauri::command]
fn list_devices(state: State<AppState>) -> Result<Vec<Device>, String> {
    let db = state.db.lock().map_err(|_| "database unavailable")?;
    let mut q=db.prepare("SELECT id,name,fingerprint,last_seen FROM devices ORDER BY COALESCE(last_seen,'') DESC").map_err(|e|e.to_string())?;
    let rows = q
        .query_map([], |r| {
            Ok(Device {
                id: r.get(0)?,
                name: r.get(1)?,
                fingerprint: r.get(2)?,
                state: "offline".into(),
                last_seen: r.get(3)?,
            })
        })
        .map_err(|e| e.to_string())?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())
}
#[tauri::command]
fn list_transfers(state: State<AppState>) -> Result<Vec<Transfer>, String> {
    let db = state.db.lock().map_err(|_| "database unavailable")?;
    let mut q=db.prepare("SELECT t.id,d.name,t.file_name,t.bytes_done,t.bytes_total,t.state FROM transfers t JOIN devices d ON d.id=t.device_id ORDER BY t.created_at DESC LIMIT 30").map_err(|e|e.to_string())?;
    let rows = q
        .query_map([], |r| {
            Ok(Transfer {
                id: r.get(0)?,
                device_name: r.get(1)?,
                file_name: r.get(2)?,
                bytes_done: r.get(3)?,
                bytes_total: r.get(4)?,
                state: r.get(5)?,
                speed_bps: 0,
            })
        })
        .map_err(|e| e.to_string())?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())
}
#[tauri::command]
fn start_pairing(state: State<AppState>, device_id: String) -> Result<String, String> {
    let remote = hex::decode(&device_id)
        .unwrap_or_else(|_| blake3::hash(device_id.as_bytes()).as_bytes().to_vec());
    let nonce = fresh_nonce();
    Ok(confirmation_code(&pairing_transcript(
        &state.local_id,
        &device_id,
        &state.local_host,
        &remote,
        &state.local_client,
        &remote,
        &nonce,
        &nonce,
    )))
}
#[tauri::command]
fn confirm_pairing(
    state: State<AppState>,
    device_id: String,
    accepted: bool,
) -> Result<(), String> {
    if !accepted {
        return Ok(());
    }
    let key = hex::decode(&device_id).unwrap_or_else(|_| device_id.as_bytes().to_vec());
    let db = state.db.lock().map_err(|_| "database unavailable")?;
    db.execute("INSERT INTO devices(id,name,fingerprint,trusted,last_seen) VALUES(?,?,?,1,CURRENT_TIMESTAMP) ON CONFLICT(id) DO UPDATE SET trusted=1,last_seen=CURRENT_TIMESTAMP", params![device_id, "Paired device", fingerprint(&key)]).map_err(|e|e.to_string())?;
    Ok(())
}
#[tauri::command]
fn queue_transfer(state: State<AppState>, device_id: String, path: String) -> Result<(), String> {
    let meta = fs::metadata(&path).map_err(|_| "The selected file is no longer available")?;
    if !meta.is_file() {
        return Err("Henad prototype transfers one regular file at a time.".into());
    }
    let name = PathBuf::from(&path)
        .file_name()
        .and_then(|x| x.to_str())
        .ok_or("Invalid filename")?
        .to_owned();
    let db = state.db.lock().map_err(|_| "database unavailable")?;
    let trusted: bool = db
        .query_row(
            "SELECT trusted FROM devices WHERE id=?",
            [&device_id],
            |r| r.get(0),
        )
        .unwrap_or(false);
    if !trusted {
        return Err("Pair with this device before sending files.".into());
    }
    db.execute("INSERT INTO transfers(id,device_id,file_name,source_path,bytes_total,state) VALUES(?,?,?,?,?,?)", params![Uuid::new_v4().to_string(),device_id,name,path,meta.len() as i64,"queued"]).map_err(|e|e.to_string())?;
    Ok(())
}
pub fn run() {
    let db = open_db();
    let local_id = db
        .query_row(
            "SELECT value FROM settings WHERE key='device_id'",
            [],
            |r| r.get::<_, String>(0),
        )
        .unwrap_or_else(|_| {
            let id = Uuid::new_v4().to_string();
            db.execute(
                "INSERT INTO settings(key,value) VALUES('device_id',?)",
                [&id],
            )
            .expect("save id");
            id
        });
    let local_host = saved_identity(&db, "host_identity");
    let local_client = saved_identity(&db, "client_identity");
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .manage(AppState {
            db: Mutex::new(db),
            local_id,
            local_host,
            local_client,
        })
        .invoke_handler(tauri::generate_handler![
            list_devices,
            list_transfers,
            start_pairing,
            confirm_pairing,
            queue_transfer
        ])
        .run(tauri::generate_context!())
        .expect("tauri application error");
}
