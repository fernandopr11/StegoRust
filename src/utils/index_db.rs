use rusqlite::{params, Connection, Result};
use std::path::{Path};

pub struct MessageIndexDB {
    conn: Connection,
}

impl MessageIndexDB {
    pub fn new(db_path: &Path) -> Result<Self> {
        let conn = Connection::open(db_path)?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS message_index (
                message_id INTEGER PRIMARY KEY,
                image_path TEXT NOT NULL,
                offset_bytes INTEGER NOT NULL,
                message_hash BLOB NOT NULL
            )",
            [],
        )?;

        Ok(Self { conn })
    }

    pub fn register(&self, message_id: u32, image_path: &Path, offset_bytes: usize, message_hash: &[u8]) -> Result<()> {
        self.conn.execute(
            "INSERT INTO message_index (message_id, image_path, offset_bytes, message_hash)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                message_id,
                image_path.to_str().unwrap(),
                offset_bytes as i64,
                message_hash,
            ],
        )?;
        Ok(())
    }

    pub fn get_message_location(&self, message_id: u32) -> Result<Option<(String, usize)>> {
        let mut stmt = self.conn.prepare(
            "SELECT image_path, offset_bytes FROM message_index WHERE message_id = ?1"
        )?;

        let result = stmt.query_row(params![message_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)? as usize,
            ))
        });

        match result {
            Ok(data) => Ok(Some(data)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn get_all_messages(&self) -> Result<Vec<(u32, String, usize)>> {
        let mut stmt = self.conn.prepare(
            "SELECT message_id, image_path, offset_bytes FROM message_index"
        )?;

        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)? as u32,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)? as usize,
            ))
        })?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }

        Ok(results)
    }
}