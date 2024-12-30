use std::io::Write;

use blake2b_simd::Params;
use orchard::{keys::FullViewingKey, note::Nullifier, primitives::redpallas::{SigningKey, SpendAuth, VerificationKey}, value::{ValueCommitTrapdoor, ValueCommitment}, Note};
use pasta_curves::Fq;
use serde::{Serialize, Deserialize};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct BallotAnchors {
    #[serde(with = "hex")]
    pub nf: Vec<u8>,
    #[serde(with = "hex")]
    pub cmx: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct BallotAction {
    #[serde(with = "hex")]
    pub cv_net: Vec<u8>,
    #[serde(with = "hex")]
    pub rk: Vec<u8>,
    #[serde(with = "hex")]
    pub nf: Vec<u8>,
    #[serde(with = "hex")]
    pub cmx: Vec<u8>,
    #[serde(with = "hex")]
    pub epk: Vec<u8>,
    #[serde(with = "hex")]
    pub enc: Vec<u8>,
}

impl BallotAction {
    pub fn write<W: Write>(&self, mut w: W) -> std::io::Result<()> {
        w.write_all(&self.cv_net)?;
        w.write_all(&self.rk)?;
        w.write_all(&self.nf)?;
        w.write_all(&self.cmx)?;
        w.write_all(&self.epk)?;
        w.write_all(&self.enc)?;
        Ok(())
    }
}

pub struct BallotActionSecret {
    pub fvk: FullViewingKey,
    pub rcv: ValueCommitTrapdoor,
    pub spend_note: Note,
    pub output_note: Note,
    pub alpha: Fq,
    pub sp_signkey: Option<SigningKey<SpendAuth>>,
    pub nf: Nullifier,
    pub nf_start: Nullifier,
    pub nf_position: u32,
    pub cmx_position: u32,
    pub cv_net: ValueCommitment,
    pub rk: VerificationKey<SpendAuth>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct BallotData {
    pub version: u32,
    #[serde(with = "hex")]
    pub domain: Vec<u8>,
    pub actions: Vec<BallotAction>,
    pub anchors: BallotAnchors,
}

impl BallotData {
    pub fn sighash(&self) -> std::io::Result<Vec<u8>> {
        let mut buffer: Vec<u8> = vec![];
        self.write(&mut buffer)?;
        let sighash = Params::new()
            .hash_length(32)
            .personal(b"Zcash_VoteBallot")
            .hash(&buffer)
            .as_bytes()
            .to_vec();
        Ok(sighash)
    }

    pub fn write<W: Write>(&self, mut w: W) -> std::io::Result<()> {
        w.write_all(&self.version.to_le_bytes())?;
        let n_actions = self.actions.len() as u32;
        w.write_all(&n_actions.to_le_bytes())?;
        for a in self.actions.iter() {
            a.write(&mut w)?;
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct VoteProof(#[serde(with = "hex")] pub Vec<u8>);

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct VoteSignature(#[serde(with = "hex")] pub Vec<u8>);

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct BallotWitnesses {
    pub proofs: Vec<VoteProof>,
    pub sp_signatures: Option<Vec<VoteSignature>>,
    #[serde(with = "hex")]
    pub binding_signature: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Ballot {
    pub data: BallotData,
    pub witnesses: BallotWitnesses,
}
