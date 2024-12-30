use rusqlite::{params, Connection, OptionalExtension as _};
use crate::Result;

pub fn create_schema(connection: &Connection) -> Result<()> {
    connection.execute(
        "CREATE TABLE IF NOT EXISTS properties(
            id_property INTEGER PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            value TEXT NOT NULL
        )",
        [],
    )?;
    connection.execute(
        "CREATE TABLE IF NOT EXISTS ballots(
            id_ballot INTEGER PRIMARY KEY,
            hash BLOB NOT NULL UNIQUE,
            data BLOB NOT NULL
        )",
        [],
    )?;
    connection.execute(
        "CREATE TABLE IF NOT EXISTS nullifiers(
        id_nf INTEGER PRIMARY KEY NOT NULL,
        hash BLOB NOT NULL)",
        [],
    )?;
    connection.execute(
        "CREATE TABLE IF NOT EXISTS cmxs(
        id_cmx INTEGER PRIMARY KEY NOT NULL,
        hash BLOB NOT NULL)",
        [],
    )?;

    connection.execute(
        "CREATE TABLE IF NOT EXISTS notes(
        id_note INTEGER PRIMARY KEY,
        position INTEGER NOT NULL UNIQUE,
        height INTEGER NOT NULL,
        txid BLOB NOT NULL,
        value INTEGER NOT NULL,
        div BLOB NOT NULL,
        rseed BLOB NOT NULL,
        nf BLOB NOT NULL,
        dnf BLOB NOT NULL,
        rho BLOB NOT NULL,
        spent INTEGER)",
        [],
    )?;

    Ok(())
}

pub fn store_prop(connection: &Connection, name: &str, value: &str) -> Result<()> {
    connection.execute(
        "INSERT INTO properties(name, value) VALUES (?1, ?2)
        ON CONFLICT (name) DO UPDATE SET value = excluded.value",
        params![name, value],
    )?;
    Ok(())
}

pub fn load_prop(connection: &Connection, name: &str) -> Result<Option<String>> {
    let value = connection
        .query_row(
            "SELECT value FROM properties WHERE name = ?1",
            [name],
            |r| r.get::<_, String>(0),
        )
        .optional()?;
    Ok(value)
}
