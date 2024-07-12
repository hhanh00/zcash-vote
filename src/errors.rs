use http::uri::InvalidUri;
use tonic::transport::Error as TonicTransportError;
use rusqlite::Error as SqlError;
use halo2_proofs::plonk::Error as PlonkError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum VoteError {
    #[error(transparent)]
    Other(#[from] anyhow::Error),
    #[error(transparent)]
    InvalidUri(#[from] InvalidUri),
    #[error(transparent)]
    TonicTransportError(#[from] TonicTransportError),
    #[error(transparent)]
    SqlError(#[from] SqlError),
    #[error(transparent)]
    PlonkError(#[from] PlonkError),

    #[error("Note at position {0} is out of range")]
    OutOfRange(usize),
    #[error("Nullifier {0} already used")]
    DoubleNullifier(String),
}
