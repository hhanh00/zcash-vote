use ff::PrimeField;
use orchard::{
    note::ExtractedNoteCommitment, tree::{MerkleHashOrchard, MerklePath}, vote::{domain, BallotCircuit, CountCircuit, ElectionDomain, ProvingKey, VerifyingKey}, Address
};
use pasta_curves::Fp;
use serde::{Deserialize, Serialize};

use crate::{address::VoteAddress, errors::VoteError, trees::cmx_hash};

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

#[derive(Clone, Copy, Serialize, Deserialize, Default, Debug)]
pub struct OrchardHash(#[serde(with = "hex")] pub [u8; 32]);

#[derive(Clone, Serialize, Deserialize, Default, Debug)]
pub struct Frontier {
    pub position: u32,
    pub leaf: OrchardHash,
    pub ommers: Vec<OrchardHash>,
}

impl Frontier {
    pub fn append(&mut self, cmx: OrchardHash) {
        let mut c = Fp::from_repr(self.leaf.0).unwrap();
        let mut p = self.position;
        assert!(p > 0);
        p -= 1;
        
        let mut i = 0u8;
        while p > 0 {
            if p % 2 == 0 {
                self.ommers[i as usize] = OrchardHash(c.to_repr());
                break;
            }
            else {
                c = cmx_hash(i, 
                    Fp::from_repr(self.ommers[i as usize].0).unwrap(), 
                    c);
            }
            p /= 2;
            i += 1;
        }
        self.leaf = cmx;
        self.position += 1;
    }

    pub fn root(&self) -> [u8; 32] {
        let ommers = self.ommers.iter().map(|o| MerkleHashOrchard::from_bytes(&o.0).unwrap()).collect::<Vec<_>>();
        let mp = MerklePath::from_parts(self.position, ommers.try_into().unwrap());
        let root = mp.root(ExtractedNoteCommitment::from_bytes(&self.leaf.0).unwrap());
        root.to_bytes()
    }
}

///
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
