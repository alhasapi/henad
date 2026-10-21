//! SQLite persistence: trust store, transfer log, and settings.
//!
//! Trust is only ever written by the pairing flow, after both sides confirmed the code.
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;

pub const SCHEMA_VERSION: i64 = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedPeer {
    pub id: String,
    pub name: String,
    pub host_key: Vec<u8>,
    pub client_key: Vec<u8>,
    pub fingerprint: String,
    pub last_seen: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferRow {
    pub id: String,
    pub device_id: String,
    pub device_name: String,
    pub file_name: String,
    pub source_path: String,
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub state: String,
    pub error: Option<String>,
    pub created_at: String,
}

pub fn open(path: &Path) -> rusqlite::Result<Connection> {
    let db = Connection::open(path)?;
    db.execute_batch("PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL;")?;
    migrate(&db)?;
    Ok(db)
}

/// Idempotent migrations keyed by `PRAGMA user_version`.
///
/// Version 1 was the unversioned prototype schema, so a pre-existing database is
/// detected by table inspection rather than by the pragma alone.
fn migrate(db: &Connection) -> rusqlite::Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
         CREATE TABLE IF NOT EXISTS devices (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            fingerprint TEXT NOT NULL DEFAULT '',
            host_key BLOB,
            client_key BLOB,
            trusted INTEGER NOT NULL DEFAULT 0,
            last_seen TEXT
         );
         CREATE TABLE IF NOT EXISTS transfers (
            id TEXT PRIMARY KEY,
            device_id TEXT NOT NULL,
            device_name TEXT NOT NULL DEFAULT '',
            file_name TEXT NOT NULL,
            source_path TEXT NOT NULL DEFAULT '',
            bytes_done INTEGER NOT NULL DEFAULT 0,
            bytes_total INTEGER NOT NULL DEFAULT 0,
            state TEXT NOT NULL,
            error TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT
         );",
    )?;

    for (table, column, ddl) in [
        (
            "devices",
            "host_key",
            "ALTER TABLE devices ADD COLUMN host_key BLOB",
        ),
        (
            "devices",
            "client_key",
            "ALTER TABLE devices ADD COLUMN client_key BLOB",
        ),
        (
            "devices",
            "trusted",
            "ALTER TABLE devices ADD COLUMN trusted INTEGER NOT NULL DEFAULT 0",
        ),
        (
            "transfers",
            "device_name",
            "ALTER TABLE transfers ADD COLUMN device_name TEXT NOT NULL DEFAULT ''",
        ),
        (
            "transfers",
            "error",
            "ALTER TABLE transfers ADD COLUMN error TEXT",
        ),
        (
            "transfers",
            "updated_at",
            "ALTER TABLE transfers ADD COLUMN updated_at TEXT",
        ),
    ] {
        if !has_column(db, table, column)? {
            db.execute(ddl, [])?;
        }
    }

    // The prototype stored opaque random identity blobs; real SSH keys live in files now.
    db.execute(
        "DELETE FROM settings WHERE key IN ('host_identity', 'client_identity')",
        [],
    )?;
    db.execute(
        "UPDATE transfers SET device_name = COALESCE(
            (SELECT name FROM devices WHERE devices.id = transfers.device_id), device_name, '')",
        [],
    )?;
    db.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    Ok(())
}

fn has_column(db: &Connection, table: &str, column: &str) -> rusqlite::Result<bool> {
    let mut stmt = db.prepare(&format!("PRAGMA table_info({table})"))?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let name: String = row.get(1)?;
        if name == column {
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn setting(db: &Connection, key: &str) -> Option<String> {
    db.query_row("SELECT value FROM settings WHERE key=?", [key], |r| {
        r.get::<_, String>(0)
    })
    .optional()
    .ok()
    .flatten()
}

pub fn set_setting(db: &Connection, key: &str, value: &str) -> rusqlite::Result<()> {
    db.execute(
        "INSERT INTO settings(key,value) VALUES(?,?)
         ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![key, value],
    )?;
    Ok(())
}

pub fn list_trusted(db: &Connection) -> Vec<TrustedPeer> {
    let mut stmt = match db.prepare(
        "SELECT id,name,host_key,client_key,fingerprint,last_seen
         FROM devices WHERE trusted=1 ORDER BY COALESCE(last_seen,'') DESC",
    ) {
        Ok(stmt) => stmt,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |r| {
        Ok(TrustedPeer {
            id: r.get(0)?,
            name: r.get(1)?,
            host_key: r.get::<_, Option<Vec<u8>>>(2)?.unwrap_or_default(),
            client_key: r.get::<_, Option<Vec<u8>>>(3)?.unwrap_or_default(),
            fingerprint: r.get(4)?,
            last_seen: r.get(5)?,
        })
    });
    match rows {
        Ok(rows) => rows.filter_map(Result::ok).collect(),
        Err(_) => Vec::new(),
    }
}

pub fn trusted_peer(db: &Connection, id: &str) -> Option<TrustedPeer> {
    db.query_row(
        "SELECT id,name,host_key,client_key,fingerprint,last_seen
         FROM devices WHERE id=? AND trusted=1",
        [id],
        |r| {
            Ok(TrustedPeer {
                id: r.get(0)?,
                name: r.get(1)?,
                host_key: r.get::<_, Option<Vec<u8>>>(2)?.unwrap_or_default(),
                client_key: r.get::<_, Option<Vec<u8>>>(3)?.unwrap_or_default(),
                fingerprint: r.get(4)?,
                last_seen: r.get(5)?,
            })
        },
    )
    .optional()
    .ok()
    .flatten()
}

pub fn trusted_peer_by_client_key(db: &Connection, client_key: &[u8]) -> Option<TrustedPeer> {
    db.query_row(
        "SELECT id,name,host_key,client_key,fingerprint,last_seen
         FROM devices WHERE trusted=1 AND client_key=?",
        [client_key],
        |r| {
            Ok(TrustedPeer {
                id: r.get(0)?,
                name: r.get(1)?,
                host_key: r.get::<_, Option<Vec<u8>>>(2)?.unwrap_or_default(),
                client_key: r.get::<_, Option<Vec<u8>>>(3)?.unwrap_or_default(),
                fingerprint: r.get(4)?,
                last_seen: r.get(5)?,
            })
        },
    )
    .optional()
    .ok()
    .flatten()
}

/// Insert or refresh trust for a peer. Keys are pinned exactly once here.
pub fn trust_peer(db: &Connection, peer: &TrustedPeer) -> rusqlite::Result<()> {
    db.execute(
        "INSERT INTO devices(id,name,fingerprint,host_key,client_key,trusted,last_seen)
         VALUES(?,?,?,?,?,1,CURRENT_TIMESTAMP)
         ON CONFLICT(id) DO UPDATE SET
            name=excluded.name,
            fingerprint=excluded.fingerprint,
            host_key=excluded.host_key,
            client_key=excluded.client_key,
            trusted=1,
            last_seen=CURRENT_TIMESTAMP",
        params![
            peer.id,
            peer.name,
            peer.fingerprint,
            peer.host_key,
            peer.client_key
        ],
    )?;
    Ok(())
}

pub fn touch_peer(db: &Connection, id: &str) -> rusqlite::Result<()> {
    db.execute(
        "UPDATE devices SET last_seen=CURRENT_TIMESTAMP WHERE id=?",
        [id],
    )?;
    Ok(())
}

pub fn unpair(db: &Connection, id: &str) -> rusqlite::Result<()> {
    db.execute("DELETE FROM devices WHERE id=?", [id])?;
    Ok(())
}

pub fn insert_transfer(db: &Connection, row: &TransferRow) -> rusqlite::Result<()> {
    db.execute(
        "INSERT INTO transfers(id,device_id,device_name,file_name,source_path,bytes_done,bytes_total,state,created_at,updated_at)
         VALUES(?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)
         ON CONFLICT(id) DO UPDATE SET
            state=excluded.state, bytes_done=excluded.bytes_done, bytes_total=excluded.bytes_total,
            error=excluded.error, updated_at=CURRENT_TIMESTAMP",
        params![
            row.id,
            row.device_id,
            row.device_name,
            row.file_name,
            row.source_path,
            row.bytes_done as i64,
            row.bytes_total as i64,
            row.state,
        ],
    )?;
    Ok(())
}

pub fn update_transfer(
    db: &Connection,
    id: &str,
    bytes_done: u64,
    state: &str,
    error: Option<&str>,
) -> rusqlite::Result<()> {
    db.execute(
        "UPDATE transfers SET bytes_done=?, state=?, error=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
        params![bytes_done as i64, state, error, id],
    )?;
    Ok(())
}

/// Fetch a single transfer row by id.
pub fn transfer(db: &Connection, id: &str) -> Option<TransferRow> {
    db.query_row(
        "SELECT id,device_id,device_name,file_name,source_path,bytes_done,bytes_total,state,error,created_at
         FROM transfers WHERE id=?",
        [id],
        |r| {
            Ok(TransferRow {
                id: r.get(0)?,
                device_id: r.get(1)?,
                device_name: r.get(2)?,
                file_name: r.get(3)?,
                source_path: r.get(4)?,
                bytes_done: r.get::<_, i64>(5)? as u64,
                bytes_total: r.get::<_, i64>(6)? as u64,
                state: r.get(7)?,
                error: r.get(8)?,
                created_at: r.get(9)?,
            })
        },
    )
    .optional()
    .ok()
    .flatten()
}

pub fn list_transfers(db: &Connection, limit: usize) -> Vec<TransferRow> {
    let mut stmt = match db.prepare(
        "SELECT id,device_id,device_name,file_name,source_path,bytes_done,bytes_total,state,error,created_at
         FROM transfers ORDER BY created_at DESC, rowid DESC LIMIT ?1",
    ) {
        Ok(stmt) => stmt,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([limit as i64], |r| {
        Ok(TransferRow {
            id: r.get(0)?,
            device_id: r.get(1)?,
            device_name: r.get(2)?,
            file_name: r.get(3)?,
            source_path: r.get(4)?,
            bytes_done: r.get::<_, i64>(5)? as u64,
            bytes_total: r.get::<_, i64>(6)? as u64,
            state: r.get(7)?,
            error: r.get(8)?,
            created_at: r.get(9)?,
        })
    });
    match rows {
        Ok(rows) => rows.filter_map(Result::ok).collect(),
        Err(_) => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_db() -> Connection {
        Connection::open_in_memory().unwrap()
    }

    #[test]
    fn fresh_schema_is_version_two() {
        let db = temp_db();
        migrate(&db).unwrap();
        let version: i64 = db
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        assert!(has_column(&db, "devices", "host_key").unwrap());
        assert!(has_column(&db, "transfers", "error").unwrap());
    }

    #[test]
    fn migrates_a_legacy_prototype_database() {
        let db = temp_db();
        db.execute_batch(
            "CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             CREATE TABLE devices (id TEXT PRIMARY KEY, name TEXT NOT NULL, fingerprint TEXT NOT NULL, trusted INTEGER NOT NULL DEFAULT 0, last_seen TEXT);
             CREATE TABLE transfers (id TEXT PRIMARY KEY, device_id TEXT NOT NULL, file_name TEXT NOT NULL, source_path TEXT NOT NULL, bytes_done INTEGER NOT NULL DEFAULT 0, bytes_total INTEGER NOT NULL DEFAULT 0, state TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
             INSERT INTO settings VALUES ('device_id','dev-1'), ('host_identity','aabb'), ('client_identity','ccdd');
             INSERT INTO devices(id,name,fingerprint,trusted) VALUES ('peer-1','Laptop','abcd',1);
             INSERT INTO transfers(id,device_id,file_name,source_path,bytes_total,state) VALUES ('t-1','peer-1','a.txt','/tmp/a.txt',10,'queued');",
        )
        .unwrap();

        migrate(&db).unwrap();

        assert_eq!(setting(&db, "host_identity"), None);
        assert_eq!(setting(&db, "client_identity"), None);
        assert_eq!(setting(&db, "device_id").as_deref(), Some("dev-1"));
        assert!(has_column(&db, "devices", "client_key").unwrap());

        let transfers = list_transfers(&db, 10);
        assert_eq!(transfers.len(), 1);
        assert_eq!(transfers[0].device_name, "Laptop");

        // Idempotent: running again is a no-op.
        migrate(&db).unwrap();
    }

    #[test]
    fn trust_round_trip_and_unpair() {
        let db = temp_db();
        migrate(&db).unwrap();
        let peer = TrustedPeer {
            id: "peer".into(),
            name: "Laptop".into(),
            host_key: vec![1, 2, 3],
            client_key: vec![4, 5, 6],
            fingerprint: "abcd".into(),
            last_seen: None,
        };
        trust_peer(&db, &peer).unwrap();
        assert_eq!(trusted_peer(&db, "peer").unwrap().host_key, vec![1, 2, 3]);
        assert_eq!(
            trusted_peer_by_client_key(&db, &[4, 5, 6]).unwrap().id,
            "peer"
        );
        assert_eq!(list_trusted(&db).len(), 1);
        unpair(&db, "peer").unwrap();
        assert!(trusted_peer(&db, "peer").is_none());
        assert!(list_trusted(&db).is_empty());
    }

    #[test]
    fn transfer_rows_round_trip() {
        let db = temp_db();
        migrate(&db).unwrap();
        let row = TransferRow {
            id: "t-1".into(),
            device_id: "peer".into(),
            device_name: "Laptop".into(),
            file_name: "a.txt".into(),
            source_path: "/tmp/a.txt".into(),
            bytes_done: 0,
            bytes_total: 10,
            state: "queued".into(),
            error: None,
            created_at: String::new(),
        };
        insert_transfer(&db, &row).unwrap();
        update_transfer(&db, "t-1", 5, "active", None).unwrap();
        let rows = list_transfers(&db, 10);
        assert_eq!(rows[0].bytes_done, 5);
        assert_eq!(rows[0].state, "active");
        update_transfer(&db, "t-1", 5, "failed", Some("boom")).unwrap();
        assert_eq!(list_transfers(&db, 10)[0].error.as_deref(), Some("boom"));
    }
}
