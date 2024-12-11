use anyhow::Result;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, Connection};

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

pub fn drop_tables(connection: &Connection) -> Result<()> {
    connection.execute("DROP TABLE IF EXISTS nullifiers", [])?;
    connection.execute("DROP TABLE IF EXISTS cmxs", [])?;
    Ok(())
}

#[allow(dead_code)]
pub fn get_connection(pool: &Pool<SqliteConnectionManager>) -> crate::Connection {
    let connection = pool.get().unwrap();
    connection
}

pub fn store_refdata(connection: &Connection, nfs: &[Vec<u8>], cmxs: &[Vec<u8>]) -> Result<()> {
    let mut s_nf = connection.prepare(
        "INSERT INTO nullifiers(hash, revhash)
        VALUES (?1, ?2)",
    )?;
    let mut s_cmx = connection.prepare(
        "INSERT INTO cmxs(hash)
        VALUES (?1)",
    )?;
    for nf in nfs {
        let mut rev_nf = [0u8; 32];
        rev_nf.copy_from_slice(nf);
        rev_nf.reverse();
        s_nf.execute(params![nf, &rev_nf])?;
    }
    for cmx in cmxs {
        s_cmx.execute(params![cmx])?;
    }
    Ok(())
}
