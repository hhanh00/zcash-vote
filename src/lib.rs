use orchard::{note::Nullifier, tree::MerklePath, Address, Note};
use serde::{Deserialize, Serialize};

pub type Hash = [u8; 32];
pub const DEPTH: usize = 32;

#[path = "./cash.z.wallet.sdk.rpc.rs"]
pub mod lwd_rpc;

mod db;
mod election;
pub mod ballot;
pub mod errors;
mod net;
mod prevhash;
mod refs;

pub use db::{drop_tables, get_connection};
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
