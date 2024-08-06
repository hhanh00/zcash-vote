use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::Connection;

use crate::errors::VoteError;

pub fn create_tables(connection: &Connection) -> Result<(), VoteError> {
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

pub fn drop_tables(connection: &Connection) -> Result<(), VoteError> {
    connection.execute("DROP TABLE IF EXISTS nullifiers", [])?;
    connection.execute("DROP TABLE IF EXISTS cmxs", [])?;
    Ok(())
}

pub fn get_connection(pool: &Pool<SqliteConnectionManager>) -> crate::Connection {
    let connection = pool.get().unwrap();
    connection
}
