use anyhow::Result;
use orchard::{
    keys::{Diversifier, FullViewingKey, Scope},
    note::{Nullifier, RandomSeed, Rho},
    value::NoteValue,
};
use pasta_curves::Fp;
use serde::{Deserialize, Serialize};
use sqlx::{sqlite::SqliteRow, Row, SqliteConnection, SqlitePool};

use crate::as_byte256;

pub async fn create_schema(connection: &SqlitePool) -> Result<()> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS properties(
        id_property INTEGER PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        value TEXT NOT NULL)",
    )
    .execute(connection)
    .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS ballots(
        id_ballot INTEGER PRIMARY KEY,
        election INTEGER NOT NULL,
        height INTEGER NOT NULL,
        hash BLOB NOT NULL UNIQUE,
        data BLOB NOT NULL)",
    )
    .execute(connection)
    .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS nfs(
        id_nf INTEGER PRIMARY KEY NOT NULL,
        election INTEGER NOT NULL,
        hash BLOB NOT NULL UNIQUE)",
    )
    .execute(connection)
    .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS dnfs(
        id_dnf INTEGER PRIMARY KEY NOT NULL,
        election INTEGER NOT NULL,
        hash BLOB NOT NULL UNIQUE)",
    )
    .execute(connection)
    .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS cmxs(
        id_cmx INTEGER PRIMARY KEY NOT NULL,
        election INTEGER NOT NULL,
        hash BLOB NOT NULL UNIQUE)",
    )
    .execute(connection)
    .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS cmx_roots(
        id_cmx_root INTEGER PRIMARY KEY,
        election INTEGER NOT NULL,
        height INTEGER NOT NULL,
        hash BLOB NOT NULL,
        CONSTRAINT u_cmx_roots UNIQUE (election, hash))",
    )
    .execute(connection)
    .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS cmx_frontiers(
        id_cmx_frontier INTEGER PRIMARY KEY,
        election INTEGER NOT NULL,
        height INTEGER NOT NULL,
        frontier TEXT NOT NULL,
        CONSTRAINT u_cmx_frontiers UNIQUE (election, height))",
    )
    .execute(connection)
    .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS notes(
        id_note INTEGER PRIMARY KEY,
        election INTEGER NOT NULL,
        scope INTEGER NOT NULL,
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
    )
    .execute(connection)
    .await?;

    Ok(())
}

pub async fn store_prop(connection: &mut SqliteConnection, name: &str, value: &str) -> Result<()> {
    sqlx::query(
        "INSERT INTO properties(name, value) VALUES (?, ?)
        ON CONFLICT (name) DO UPDATE SET value = excluded.value",
    )
    .bind(name)
    .bind(value)
    .execute(connection)
    .await?;
    Ok(())
}

pub async fn load_prop(connection: &mut SqliteConnection, name: &str) -> Result<Option<String>> {
    let value = sqlx::query("SELECT value FROM properties WHERE name = ?")
        .bind(name)
        .map(|row: SqliteRow| {
            let value: String = row.get(0);
            value
        })
        .fetch_optional(connection)
        .await?;
    Ok(value)
}

pub async fn store_dnf(connection: &mut SqliteConnection, id_election: u32, dnf: &[u8]) -> Result<()> {
    sqlx::query("INSERT INTO dnfs(election, hash) VALUES (?, ?)")
        .bind(id_election)
        .bind(dnf)
        .execute(connection)
        .await?;
    Ok(())
}

pub async fn store_note(
    connection: &mut SqliteConnection,
    id_election: u32,
    domain: Fp,
    fvk: &FullViewingKey,
    scope: u8,
    height: u32,
    position: u32,
    txid: &[u8],
    note: &orchard::Note,
) -> Result<u32> {
    let value = note.value().inner();
    let div = note.recipient().diversifier();
    let rseed = note.rseed().as_bytes();
    let nf = note.nullifier(fvk).to_bytes();
    let domain_nf = note.nullifier_domain(fvk, domain).to_bytes();
    let rho = note.rho().to_bytes();
    let r = sqlx::query(
        "INSERT INTO notes
        (election, scope, position, height, txid, value, div, rseed, nf, dnf, rho, spent)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)",
    )
    .bind(id_election)
    .bind(scope)
    .bind(position)
    .bind(height)
    .bind(txid)
    .bind(value as i64)
    .bind(div.as_array().as_slice())
    .bind(rseed.as_slice())
    .bind(nf.as_slice())
    .bind(domain_nf.as_slice())
    .bind(rho.as_slice())
    .execute(connection)
    .await?;
    let id = r.last_insert_rowid() as u32;
    Ok(id)
}

pub async fn mark_spent(connection: &mut SqliteConnection, id: u32, height: u32) -> Result<()> {
    sqlx::query("UPDATE notes SET spent = ? WHERE id_note = ?")
        .bind(height)
        .bind(id)
        .execute(connection)
        .await?;
    Ok(())
}

pub async fn list_notes(
    connection: &SqlitePool,
    id_election: u32,
    fvk: &FullViewingKey,
) -> Result<Vec<(orchard::Note, u32)>> {
    let notes = sqlx::query(
        "SELECT scope, position, height, txid, value, div, rseed, nf, dnf, rho
        FROM notes WHERE spent IS NULL AND election = ?",
    )
    .bind(id_election)
    .map(|row: SqliteRow| {
        let scope: u8 = row.get(0);
        let position: u32 = row.get(1);
        let height: u32 = row.get(2);
        let txid: Vec<u8> = row.get(3);
        let value: i64 = row.get(4);
        let div: Vec<u8> = row.get(5);
        let rseed: Vec<u8> = row.get(6);
        let nf: Vec<u8> = row.get(7);
        let dnf: Vec<u8> = row.get(8);
        let rho: Vec<u8> = row.get(9);

        let scope = if scope == 0 {
            Scope::External
        } else {
            Scope::Internal
        };

        let n = Note {
            position,
            height,
            txid,
            value: value as u64,
            div,
            rseed,
            nf,
            dnf,
            rho,
        };
        n.to_note(fvk, scope)
    })
    .fetch_all(connection)
    .await?;

    Ok(notes)
}

pub async fn store_cmx(connection: &mut SqliteConnection, id_election: u32, cmx: &[u8]) -> Result<()> {
    sqlx::query("INSERT INTO cmxs(election, hash) VALUES (?, ?)")
        .bind(id_election)
        .bind(cmx)
        .execute(connection)
        .await?;
    Ok(())
}

pub async fn store_cmx_root(
    connection: &mut SqliteConnection,
    id_election: u32,
    height: u32,
    cmx_root: &[u8],
) -> Result<()> {
    sqlx::query(
        "INSERT INTO cmx_roots
        (election, height, hash)
        VALUES (?, ?, ?)",
    )
    .bind(id_election)
    .bind(height)
    .bind(cmx_root)
    .execute(connection)
    .await?;
    Ok(())
}

#[derive(Clone, Serialize, Deserialize, Default, Debug)]
pub struct Note {
    pub position: u32,
    pub height: u32,
    pub txid: Vec<u8>,
    pub value: u64,
    pub div: Vec<u8>,
    pub rseed: Vec<u8>,
    pub nf: Vec<u8>,
    pub dnf: Vec<u8>,
    pub rho: Vec<u8>,
}

impl Note {
    fn to_note(&self, fvk: &FullViewingKey, scope: Scope) -> (orchard::Note, u32) {
        let d = Diversifier::from_bytes(self.div.clone().try_into().unwrap());
        let recipient = fvk.address(d, scope);
        let rho = Nullifier::from_bytes(&as_byte256(&self.rho)).unwrap();
        let rho = Rho::from_nf_old(rho);
        let note = orchard::Note::from_parts(
            recipient,
            NoteValue::from_raw(self.value),
            rho,
            RandomSeed::from_bytes(as_byte256(&self.rseed), &rho).unwrap(),
        )
        .unwrap();
        (note, self.position)
    }
}
