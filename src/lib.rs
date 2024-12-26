use serde::{Deserialize, Serialize};

pub type Hash = [u8; 32];
pub const DEPTH: usize = 32;

#[path = "./cash.z.wallet.sdk.rpc.rs"]
pub mod lwd_rpc;

pub mod errors;
mod vote_generated;
mod net;
pub mod db;
pub mod path;
mod prevhash;
pub mod proof;

use anyhow::Result;
pub use proof::{create_ballot, validate_proof};
pub use db::drop_tables;
pub use net::download_reference_data;
use vote_generated::fb::{BallotEnvelope, BallotEnvelopeT};
pub use vote_generated::fb as vote_data;

pub type Connection = r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager>;


#[derive(Clone, Serialize, Deserialize, Default, Debug)]
pub struct Election {
    pub id: u32,
    pub name: String,
    pub start_height: u32,
    pub end_height: u32,
    pub close_height: u32,
    pub submit_url: String,
    pub question: String,
    pub candidates: Vec<String>,
    pub cmx: Option<String>,
    pub nf: Option<String>,
    pub status: String,
}

pub fn parse_ballot(bytes: &[u8]) -> Result<BallotEnvelopeT> {
    let envelope = flatbuffers::root::<BallotEnvelope>(bytes)?;
    Ok(envelope.unpack())
}
