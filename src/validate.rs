use anyhow::{anyhow, Result};
use ff::PrimeField;
use orchard::{
    note::{ExtractedNoteCommitment, Nullifier},
    primitives::redpallas::{Binding, Signature, SpendAuth, VerificationKey},
    value::ValueCommitment,
    vote::{
        circuit::Instance, proof::Proof, BallotCircuit as Circuit, ElectionDomain, ProvingKey,
        VerifyingKey,
    },
    Anchor,
};
use pasta_curves::Fp;

use crate::{
    ballot::{Ballot, BallotWitnesses},
    CtOpt, Election,
};
use bip0039::Mnemonic;
use zcash_address::unified::Encoding;

use crate::as_byte256;

pub fn validate_key(key: String) -> Result<bool, ()> {
    if Mnemonic::from_phrase(&key).is_ok() {
        return Ok(true);
    }
    if zcash_address::unified::Ufvk::decode(&key).is_ok() {
        return Ok(true);
    }
    Ok(false)
}

pub fn validate_ballot(ballot: Ballot, signature_check: bool) -> Result<()> {
    let Ballot { data, witnesses } = ballot;
    let sighash = data.sighash()?;
    let domain = Fp::from_repr(as_byte256(&data.domain)).unwrap();

    log::info!("Verify spending signatures if needed");
    if let Some(sp_signatures) = witnesses.sp_signatures {
        for (signature, action) in sp_signatures.into_iter().zip(data.actions.iter()) {
            let signature: [u8; 64] = signature
                .0
                .try_into()
                .map_err(|_| anyhow!("Signature must be 64 byte long"))?;
            let signature: Signature<SpendAuth> = signature.into();
            let rk = as_byte256(&action.rk);
            let rk: VerificationKey<SpendAuth> =
                rk.try_into().map_err(|_| anyhow!("Invalid public key"))?;
            rk.verify(&sighash, &signature)?;
        }
    } else if signature_check {
        anyhow::bail!("Signatures missing");
    }

    log::info!("Verify binding signature");
    let mut total_cv = ValueCommitment::derive_from_value(0);
    for action in data.actions.iter() {
        let cv_net = as_byte256(&action.cv_net);
        let cv_net = CtOpt(ValueCommitment::from_bytes(&cv_net)).to_result()?;
        total_cv = total_cv + &cv_net;
    }
    let cv: VerificationKey<Binding> = total_cv.to_bytes().try_into()?;
    let binding_signature: [u8; 64] = witnesses
        .binding_signature
        .try_into()
        .map_err(|_| anyhow!("Invalid binding signature"))?;
    let binding_signature: Signature<Binding> = binding_signature.into();
    cv.verify(&sighash, &binding_signature)?;

    let BallotWitnesses { proofs, .. } = witnesses;

    log::info!("Verify ZKP");
    for (proof, action) in proofs.into_iter().zip(data.actions.iter()) {
        let proof: Proof<Circuit> = Proof::new(proof.0);
        let cmx_root = as_byte256(&data.anchors.cmx);
        let nf_root = as_byte256(&data.anchors.nf);
        let cv_net = as_byte256(&action.cv_net);
        let dnf = as_byte256(&action.nf);
        let rk = as_byte256(&action.rk);
        let cmx = as_byte256(&action.cmx);

        let instance = Instance::from_parts(
            CtOpt(Anchor::from_bytes(cmx_root)).to_result()?,
            CtOpt(ValueCommitment::from_bytes(&cv_net)).to_result()?,
            CtOpt(Nullifier::from_bytes(&dnf)).to_result()?,
            rk.try_into()?,
            CtOpt(ExtractedNoteCommitment::from_bytes(&cmx)).to_result()?,
            ElectionDomain(domain.clone()),
            CtOpt(Anchor::from_bytes(nf_root)).to_result()?,
        );

        proof.verify(&VK, &[instance])?;
    }

    // TODO: Verify anchors

    Ok(())
}

lazy_static::lazy_static! {
    pub static ref PK: ProvingKey<Circuit> = ProvingKey::build();
    pub static ref VK: VerifyingKey<Circuit> = VerifyingKey::build();
}
