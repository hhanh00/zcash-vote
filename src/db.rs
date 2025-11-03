use anyhow::Result;
use orchard::{
    keys::{Diversifier, FullViewingKey, Scope},
    note::{Nullifier, RandomSeed},
    value::NoteValue,
};
use pasta_curves::Fp;
use serde::{Deserialize, Serialize};
use sqlx::{sqlite::SqliteRow, Row, SqliteConnection};

use crate::as_byte256;

pub async fn create_schema(connection: &mut SqliteConnection) -> Result<()> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS properties(
        id_property INTEGER PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        value TEXT NOT NULL)",
    )
    .execute(&mut *connection)
    .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS ballots(
        id_ballot INTEGER PRIMARY KEY,
        election INTEGER NOT NULL,
        height INTEGER NOT NULL,
        hash BLOB NOT NULL UNIQUE,
        data BLOB NOT NULL)",
    )
    .execute(&mut *connection)
    .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS nfs(
        id_nf INTEGER PRIMARY KEY NOT NULL,
        election INTEGER NOT NULL,
        hash BLOB NOT NULL UNIQUE)",
    )
    .execute(&mut *connection)
    .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS dnfs(
        id_dnf INTEGER PRIMARY KEY NOT NULL,
        election INTEGER NOT NULL,
        hash BLOB NOT NULL UNIQUE)",
    )
    .execute(&mut *connection)
    .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS cmxs(
        id_cmx INTEGER PRIMARY KEY NOT NULL,
        election INTEGER NOT NULL,
        hash BLOB NOT NULL UNIQUE)",
    )
    .execute(&mut *connection)
    .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS cmx_roots(
        id_cmx_root INTEGER PRIMARY KEY,
        election INTEGER NOT NULL,
        height INTEGER NOT NULL,
        hash BLOB NOT NULL,
        CONSTRAINT u_cmx_roots UNIQUE (election, hash))",
    )
    .execute(&mut *connection)
    .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS cmx_frontiers(
        id_cmx_frontier INTEGER PRIMARY KEY,
        election INTEGER NOT NULL,
        height INTEGER NOT NULL,
        frontier TEXT NOT NULL,
        CONSTRAINT u_cmx_frontiers UNIQUE (election, height))",
    )
    .execute(&mut *connection)
    .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS notes(
        id_note INTEGER PRIMARY KEY,
        election INTEGER NOT NULL,
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
    .execute(&mut *connection)
    .await?;
    Ok(())
}

pub async fn store_prop(connection: &mut SqliteConnection, name: &str, value: &str) -> Result<()> {
    sqlx::query(
        "INSERT INTO properties(name, value) VALUES (?1, ?2)
        ON CONFLICT (name) DO UPDATE SET value = excluded.value",
    )
    .bind(name)
    .bind(value)
    .execute(&mut *connection)
    .await?;
    Ok(())
}

pub async fn load_prop(connection: &mut SqliteConnection, name: &str) -> Result<Option<String>> {
    let value = sqlx::query("SELECT value FROM properties WHERE name = ?1")
        .bind(name)
        .map(|r: SqliteRow| r.get::<String, _>(0))
        .fetch_optional(&mut *connection)
        .await?;
    Ok(value)
}

pub async fn store_dnf(
    connection: &mut SqliteConnection,
    id_election: u32,
    dnf: &[u8],
) -> Result<()> {
    sqlx::query("INSERT INTO dnfs(election, hash) VALUES (?1, ?2)")
        .bind(id_election)
        .bind(dnf)
        .execute(&mut *connection)
        .await?;
    Ok(())
}

pub async fn store_note(
    connection: &mut SqliteConnection,
    id_election: u32,
    domain: Fp,
    fvk: &FullViewingKey,
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
        (election, position, height, txid, value, div, rseed, nf, dnf, rho, spent)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, NULL)",
    )
    .bind(id_election)
    .bind(position)
    .bind(height)
    .bind(txid)
    .bind(value as i64)
    .bind(&div.as_array()[..])
    .bind(&rseed[..])
    .bind(&nf[..])
    .bind(&domain_nf[..])
    .bind(&rho[..])
    .execute(&mut *connection)
    .await?;
    let id = r.last_insert_rowid() as u32;
    Ok(id)
}

pub async fn mark_spent(connection: &mut SqliteConnection, id: u32, height: u32) -> Result<()> {
    sqlx::query("UPDATE notes SET spent = ?2 WHERE id_note = ?1")
        .bind(id)
        .bind(height)
        .execute(&mut *connection)
        .await?;
    Ok(())
}

pub async fn list_notes(
    connection: &mut SqliteConnection,
    id_election: u32,
    fvk: &FullViewingKey,
) -> Result<Vec<(orchard::Note, u32)>> {
    let notes = sqlx::query(
        "SELECT position, height, txid, value, div, rseed, nf, dnf, rho
        FROM notes WHERE spent IS NULL AND election = ?1",
    )
    .bind(id_election)
    .map(|r: SqliteRow| {
        let position: u32 = r.get(0);
        let height: u32 = r.get(1);
        let txid: Vec<u8> = r.get(2);
        let value: u64 = r.get(3);
        let div: Vec<u8> = r.get(4);
        let rseed: Vec<u8> = r.get(5);
        let nf: Vec<u8> = r.get(6);
        let dnf: Vec<u8> = r.get(7);
        let rho: Vec<u8> = r.get(8);

        let n = Note {
            position,
            height,
            txid,
            value,
            div,
            rseed,
            nf,
            dnf,
            rho,
        };
        n.to_note(fvk)
    })
    .fetch_all(&mut *connection)
    .await?;
    Ok(notes)
}

pub async fn store_cmx(
    connection: &mut SqliteConnection,
    id_election: u32,
    cmx: &[u8],
) -> Result<()> {
    sqlx::query("INSERT INTO cmxs(election, hash) VALUES (?1, ?2)")
        .bind(id_election)
        .bind(cmx)
        .execute(&mut *connection)
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
        VALUES (?1, ?2, ?3)",
    )
    .bind(id_election)
    .bind(height)
    .bind(cmx_root)
    .execute(&mut *connection)
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
    fn to_note(&self, fvk: &FullViewingKey) -> (orchard::Note, u32) {
        let d = Diversifier::from_bytes(self.div.clone().try_into().unwrap());
        let recipient = fvk.address(d, Scope::External);
        let rho = Nullifier::from_bytes(&as_byte256(&self.rho)).unwrap();
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
