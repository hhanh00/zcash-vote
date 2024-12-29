use orchard::{
    keys::SpendingKey,
    note::Nullifier,
    vote::{domain, BallotBuilder, BallotCircuit, BallotEnvelope, CandidateCount, CandidateCountEnvelope, CountBuilder, CountCircuit, ElectionDomain, ProvingKey, VerifyingKey},
    Address, Anchor,
};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::{errors::VoteError, get_candidate_address, refs::get_candidate_fvk, Hash, VoteNote};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct CandidateChoice {
    #[serde(with = "hex")]
    pub address: [u8; 43],
    pub choice: String,
}

impl CandidateChoice {
    pub fn new(address: Address, choice: &str) -> Self {
        CandidateChoice {
            address: address.to_raw_address_bytes(),
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

    pub fn create_ballot<R: RngCore + CryptoRng>(
        &self,
        sk: SpendingKey,
        notes: &[VoteNote],
        candidates: &[u64],
        cmxs: &[Hash],
        nfs: &[Nullifier],
        mut rng: R,
    ) -> Result<BallotEnvelope, VoteError> {
        let total_input = notes.iter().map(|vn| vn.note.value().inner()).sum::<u64>();
        let total_output = candidates.iter().sum::<u64>();
        if total_input != total_output {
            return Err(VoteError::InvalidBallot("Notes do not match Votes".into()));
        }
        if candidates.len() != self.candidates.len() {
            return Err(VoteError::InvalidBallot(
                "Number of candidates must match election definition".into(),
            ));
        }
        let mut bb = BallotBuilder::new(&self.name, cmxs, nfs, &BALLOT_PK, &BALLOT_VK);
        for vn in notes.iter() {
            bb.add_note(vn.idx as u32, sk, vn.note)?;
        }
        for (weight, choice) in candidates.iter().zip(self.candidates.iter()) {
            bb.add_candidate(
                Address::from_raw_address_bytes(&choice.address).unwrap(),
                *weight,
            )?;
        }
        let ballot = bb.build(&mut rng)?;
        Ok(ballot)
    }
}

pub struct ElectionCounter {
    seed: Hash,
    election: Election,
    domain: ElectionDomain,
    counters: Vec<CountBuilder<'static>>,
}

impl ElectionCounter {
    pub fn new(seed: Hash, election: &Election) -> Self {
        ElectionCounter {
            seed,
            election: election.clone(),
            domain: election.domain(),
            counters: election.candidates.iter().map(|c| 
                CountBuilder::new(Address::from_raw_address_bytes(&c.address).unwrap(), 
            &COUNT_PK, &COUNT_VK)).collect::<Vec<_>>(),
        }
    }

    pub fn add_ballot(&mut self, ballot: BallotEnvelope) -> Result<(), VoteError> {
        let (ballot, _dnf) = ballot.verify(&BALLOT_VK, self.domain.clone(), 
            Anchor::from_bytes(self.election.cmx.clone()).unwrap(),
            Anchor::from_bytes(self.election.nf.clone()).unwrap())?;
        for i in 0..self.election.candidates.len() {
            let fvk = get_candidate_fvk(self.seed, i as u32)?;
            ballot.count_candidate(i, &fvk)?;
        }
        Ok(())
    }

    pub fn finalize_into_proofs<R: RngCore + CryptoRng>(self, mut rng: R) -> Result<Vec<CandidateCountEnvelope>, VoteError> {
        let counts: Vec<_> = self.counters.into_iter().map(|c| c.build(&mut rng)).collect();
        Ok(counts)
    }

    pub fn finalize<R: RngCore + CryptoRng>(self, mut rng: R) -> Result<Vec<CandidateCount>, VoteError> {
        let counts: Result<Vec<_>, orchard::vote::VoteError> = self.counters.into_iter().map(|c| c.build(&mut rng).verify(&COUNT_VK)).collect();
        let counts = counts?;
        Ok(counts)
    }

}

lazy_static::lazy_static! {
    pub static ref BALLOT_PK: ProvingKey<BallotCircuit> = ProvingKey::build();
    pub static ref BALLOT_VK: VerifyingKey<BallotCircuit> = VerifyingKey::build();

    pub static ref COUNT_PK: ProvingKey<CountCircuit> = ProvingKey::build();
    pub static ref COUNT_VK: VerifyingKey<CountCircuit> = VerifyingKey::build();
}
