use orchard::{
    vote::{Circuit, Frontier, OrchardHash, ProvingKey, VerifyingKey},
    Address,
};
use pasta_curves::Fp;
use serde::{Deserialize, Serialize};

use crate::{address::VoteAddress, errors::VoteError};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct CandidateChoice {
    pub address: String,
    pub choice: String,
}

impl CandidateChoice {
    pub fn new(address: Address, choice: &str) -> Self {
        CandidateChoice {
            address: VoteAddress(address).to_string(),
            choice: choice.to_string(),
        }
    }
}

/// Details of an election, including metadata, candidates, and election parameters.
#[derive(Clone, Serialize, Deserialize, Default, Debug)]
pub struct Election {
    pub id: String,
    pub name: String,
    pub start_height: u32,
    pub end_height: u32,
    pub question: String,
    pub candidates: Vec<CandidateChoice>,
    pub signature_required: bool,
    pub cmx: OrchardHash,
    pub nf: OrchardHash,
    pub cmx_frontier: Option<Frontier>,
}

impl Election {
    pub fn from_json(json: &str) -> Result<Election, VoteError> {
        let election: Election =
            serde_json::from_str(json).map_err(|e| VoteError::InvalidJson(e.to_string()))?;
        Ok(election)
    }

    pub fn domain(&self) -> Fp {
        orchard::vote::calculate_domain(self.name.as_bytes())
    }
}

lazy_static::lazy_static! {
    pub static ref BALLOT_PK: ProvingKey<Circuit> = ProvingKey::build();
    pub static ref BALLOT_VK: VerifyingKey<Circuit> = VerifyingKey::build();
}
