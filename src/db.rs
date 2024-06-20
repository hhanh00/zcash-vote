use anyhow::Result;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::Connection;

pub fn create_tables(connection: &Connection) -> Result<()> {
    connection.execute(
        "CREATE TABLE IF NOT EXISTS nullifiers(
        id_nf INTEGER PRIMARY KEY NOT NULL,
        hash BLOB NOT NULL,
        revhash BLOB NOT NULL)",
        [],
    )?;
    connection.execute(
        "CREATE TABLE IF NOT EXISTS cmxs(
        id_cmx INTEGER PRIMARY KEY NOT NULL,
        hash BLOB NOT NULL)",
        [],
    )?;
    Ok(())
}

#[allow(dead_code)]
pub fn get_connection(pool: &Pool<SqliteConnectionManager>) -> crate::Connection {
    let connection = pool.get().unwrap();
    connection
}
