use errors::VoteError;
use orchard::{note::Nullifier, tree::MerklePath, Address, Note};
use r2d2::PooledConnection;
use r2d2_sqlite::SqliteConnectionManager;
use serde::{Deserialize, Serialize};

pub type Hash = [u8; 32];
pub const DEPTH: usize = 32;

#[path = "./cash.z.wallet.sdk.rpc.rs"]
pub mod rpc;

pub mod errors;

pub type Result<T> = std::result::Result<T, VoteError>;
pub type PoolConnection = PooledConnection<SqliteConnectionManager>;

pub mod db;
mod election;
pub mod download;
pub mod decrypt;
pub mod ballot;
mod net;
mod prevhash;
mod refs;

pub use election::{CandidateChoice, Election};
pub use net::download_reference_data;
pub use refs::{get_candidate_address, get_cmx_count, list_cmxs, list_nfs, list_notes};

pub type Connection = r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager>;

#[derive(Clone, Debug)]
pub struct VoteNote {
    pub note: Note,
    pub idx: usize,
    pub nf: Nullifier,
    pub nf_start: Nullifier,
    pub nf_path: MerklePath,
    pub cmx_path: MerklePath,
}

pub fn as_byte256(h: &[u8]) -> [u8; 32] {
    let mut hh = [0u8; 32];
    hh.copy_from_slice(h);
    hh
}
