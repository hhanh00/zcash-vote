use orchard::{
    vote::{domain, BallotCircuit, CountCircuit, ElectionDomain, ProvingKey, VerifyingKey},
    Address,
};
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

///
#[derive(Clone, Serialize, Deserialize, Default, Debug)]
pub struct Election {
    pub id: u32,
    pub name: String,
    pub start_height: u32,
    pub end_height: u32,
    pub question: String,
    pub candidates: Vec<CandidateChoice>,
    pub signature_required: bool,
    #[serde(with = "hex")]
    pub cmx: [u8; 32],
    #[serde(with = "hex")]
    pub nf: [u8; 32],
}

impl Election {
    pub fn from_json(json: &str) -> Result<Election, VoteError> {
        let election: Election =
            serde_json::from_str(json).map_err(|e| VoteError::InvalidJson(e.to_string()))?;
        Ok(election)
    }

    pub fn domain(&self) -> ElectionDomain {
        ElectionDomain(domain(self.name.as_bytes()))
    }
}

lazy_static::lazy_static! {
    pub static ref BALLOT_PK: ProvingKey<BallotCircuit> = ProvingKey::build();
    pub static ref BALLOT_VK: VerifyingKey<BallotCircuit> = VerifyingKey::build();

    pub static ref COUNT_PK: ProvingKey<CountCircuit> = ProvingKey::build();
    pub static ref COUNT_VK: VerifyingKey<CountCircuit> = VerifyingKey::build();
}
