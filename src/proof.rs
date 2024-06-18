use anyhow::Result;
use blake2b_simd::Params;
use ff::{Field, PrimeField};
use orchard::{
    keys::{Diversifier, FullViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
    note::{Nullifier, RandomSeed},
    pob::{create_proof, verify_proof, Proof, ProofBalancePublic},
    primitives::redpallas::{Binding, Signature, SigningKey, SpendAuth, VerificationKey},
    tree::{MerkleHashOrchard, MerklePath as OrchardMerklePath},
    value::{NoteValue, ValueCommitTrapdoor, ValueCommitment},
    Anchor, Note,
};
use pasta_curves::{Fp, Fq};
use rand::{CryptoRng, RngCore};
use rusqlite::params;

use crate::{
    Hash,
    net::connect_lightwalletd,
    parse_ballot,
    path::calculate_merkle_paths,
    prevhash::{fetch_tree_state, PreviousHashes},
    vote_generated::fb::{
        BallotEnvelopeT, BallotT, BallotWitnessT, HeaderT, InputT, ProofT, SignatureT,
    },
    Connection, Election,
};

pub struct NotePosition {
    pub note: Note,
    pub position: u32,
    pub nf_start_range: Fp,
    pub nf_position: u32,
}

pub async fn create_ballot<R: RngCore + CryptoRng>(
    connection: &Connection,
    lwd_url: &str,
    account: u32,
    e: &Election,
    id_notes: &[u32],
    candidate: u32,
    mut rng: R,
) -> Result<BallotEnvelopeT> {
    let mut client = connect_lightwalletd(lwd_url).await?;
    let ph = fetch_tree_state(&mut client, e.start_height - 1).await?;

    log::info!("Creating proof...");
    let (sk, fvk) = connection.query_row(
        "SELECT sk, fvk FROM orchard_addrs WHERE account = ?1",
        [account],
        |r| {
            let sk = r.get::<_, Vec<u8>>(0)?;
            let fvk = r.get::<_, Vec<u8>>(1)?;
            Ok((sk, fvk))
        },
    )?;
    let fvk = FullViewingKey::from_bytes(&fvk.try_into().unwrap()).unwrap();

    println!("Scanning notes...");
    let mut notes = vec![];
    let mut s = connection.prepare("SELECT id_note, position, diversifier, value, rcm, nf, rho FROM received_notes WHERE account = ?1 AND height >= ?2 AND height <= ?3 AND orchard = 1 AND spent IS NULL")?;
    let rows = s.query_map(params![account, e.start_height, e.end_height], |r| {
        let id_note = r.get::<_, u32>(0)?;
        let position = r.get::<_, u32>(1)?;
        let diversifier = r.get::<_, Vec<u8>>(2)?;
        let value = r.get::<_, u64>(3)?;
        let rcm = r.get::<_, Vec<u8>>(4)?;
        let nf = r.get::<_, Vec<u8>>(5)?;
        let rho = r.get::<_, Vec<u8>>(6)?;
        Ok((id_note, position, diversifier, value, rcm, nf, rho))
    })?;
    for r in rows {
        let (id_note, position, diversifier, value, rcm, _nf, rho) = r?;
        let d = Diversifier::from_bytes(diversifier.try_into().unwrap());
        let recipient = fvk.address(d, Scope::External);
        let value = NoteValue::from_raw(value);
        let rho = Nullifier::from_bytes(&rho.try_into().unwrap()).unwrap();
        let rseed = RandomSeed::from_bytes(rcm.try_into().unwrap(), &rho).unwrap();

        if id_notes.contains(&id_note) {
            let note = Note::from_parts(recipient, value, rho, rseed).unwrap();
            notes.push(NotePosition {
                note,
                position,
                nf_start_range: Fp::zero(),
                nf_position: 0,
            });
        }
    }

    log::info!("Building cmx tree...");
    s = connection.prepare("SELECT hash FROM cmxs")?;
    let rows = s.query_map([], |r| r.get::<_, [u8; 32]>(0))?;
    let hashes = rows.collect::<Result<Vec<_>, _>>()?;

    let positions = notes.iter().map(|n| n.position).collect::<Vec<_>>();
    let cmx_paths = calculate_merkle_paths(&ph, &positions, &hashes)?;

    log::info!("Building nf tree...");
    s = connection.prepare("SELECT hash FROM nullifiers ORDER BY revhash")?;
    let rows = s.query_map([], |r| {
        let h = r.get::<_, [u8; 32]>(0)?;
        Ok(Fp::from_repr(h).unwrap())
    })?;
    let mut nfs = vec![];
    nfs.push(Fp::zero());
    for r in rows {
        let r = r?;
        nfs.push(r - Fp::one());
        nfs.push(r + Fp::one());
    }
    nfs.push(Fp::one().neg());
    for n in notes.iter_mut() {
        let NotePosition { note, .. } = n;
        let nf: Nullifier = note.nullifier(&fvk);
        let nf = Fp::from_repr(nf.to_bytes()).unwrap();
        match nfs.binary_search(&nf) {
            Ok(_) => anyhow::bail!("Duplicate nullifier"),
            Err(idx) => {
                n.nf_start_range = nfs[idx - 1];
                n.nf_position = (idx - 1) as u32;
            }
        }
    }

    let positions = notes.iter().map(|n| n.nf_position).collect::<Vec<_>>();
    let nfs = nfs.iter().map(|nf| nf.to_repr()).collect::<Vec<_>>();
    let nf_paths = calculate_merkle_paths(&PreviousHashes::default(), &positions, &nfs)?;

    let domain = orchard::pob::domain(e.name.as_bytes());
    // let sk = Fp::one().to_repr();
    let sk = SpendingKey::from_bytes(sk.try_into().unwrap()).unwrap();
    let spauth = SpendAuthorizingKey::from(&sk);

    let mut inputs = vec![];
    let mut proofs = vec![];
    let mut amount = 0u64;
    let mut rcv_total = ValueCommitTrapdoor::zero();
    for (n, (cmx_path, nf_path)) in notes.iter().zip(cmx_paths.iter().zip(nf_paths.iter())) {
        let NotePosition {
            note,
            position,
            nf_start_range,
            nf_position,
        } = n;

        let cmx_path = OrchardMerklePath::from_parts(
            *position,
            cmx_path
                .path
                .map(|h| MerkleHashOrchard::from_bytes(&h).unwrap()),
        );
        let nf_path = OrchardMerklePath::from_parts(
            *nf_position,
            nf_path
                .path
                .map(|h| MerkleHashOrchard::from_bytes(&h).unwrap()),
        );

        // let cmx = ExtractedNoteCommitment::from_bytes(&p.value).unwrap();
        // let root = path.root(cmx);

        let alpha = Fq::random(&mut rng);

        let cmx_root = e.cmx.as_ref().map(|root| {
            Anchor::from_bytes(hex::decode(&root).unwrap().try_into().unwrap()).unwrap()
        });
        let nf_root = e.nf.as_ref().map(|root| {
            Anchor::from_bytes(hex::decode(&root).unwrap().try_into().unwrap()).unwrap()
        });
        let proof = create_proof(
            domain,
            spauth.clone(),
            &fvk,
            note,
            cmx_path,
            nf_path,
            nf_start_range.clone(),
            alpha,
            cmx_root,
            nf_root,
            &mut rng,
        )?;

        let proof_public = proof.public;
        proofs.push(ProofT {
            data: Some(proof_public.proof.as_ref().to_vec()),
        });

        let input = InputT {
            cv: proof_public.cv.to_bytes(),
            nf: proof_public.domain_nf.to_bytes(),
            rk: proof_public.rk.into(),
        };
        inputs.push(input);

        let rcv = proof.private.rcv;
        rcv_total = rcv_total + &rcv;
        amount += note.value().inner();
    }

    let header = HeaderT {
        version: 1,
        domain: domain.to_repr(),
    };
    let ballot = BallotT {
        header: Some(header),
        inputs: Some(inputs),
        amount,
        payload: Some(candidate.to_le_bytes().to_vec()),
    };
    let mut fbb = flatbuffers::FlatBufferBuilder::new();
    let root = ballot.pack(&mut fbb);
    fbb.finish_minimal(root);
    let ballot_data = fbb.finished_data();

    let sig_hash = Params::new()
        .personal(b"ZcashVoteSighash")
        .hash_length(32)
        .hash(ballot_data);

    let bsk = rcv_total.to_bytes();
    let bsk: SigningKey<Binding> = bsk.try_into().unwrap();

    let binding_signature = bsk.sign(&mut rng, sig_hash.as_ref());
    let binding_signature: [u8; 64] = (&binding_signature).into();
    let binding_signature = SignatureT {
        r_part: binding_signature[0..32].try_into().unwrap(),
        s_part: binding_signature[32..64].try_into().unwrap(),
    };

    let witness = BallotWitnessT {
        proofs: Some(proofs),
        binding_signature: Some(binding_signature),
    };

    let ballot_envelope = BallotEnvelopeT {
        ballot: Some(Box::new(ballot)),
        witness: Some(Box::new(witness)),
    };

    println!("Ballot created");
    Ok(ballot_envelope)
}

pub fn validate_proof(proof_bytes: &[u8], domain: Fp, election: &Election) -> Result<ValidationResult> {
    let envelope = parse_ballot(proof_bytes)?;
    let ballot = envelope.ballot.unwrap();
    let witness = envelope.witness.unwrap();

    let mut fbb = flatbuffers::FlatBufferBuilder::new();
    let root = ballot.pack(&mut fbb);
    fbb.finish_minimal(root);

    let sig_hash: [u8; 32] = Params::new()
        .personal(b"ZcashVoteSighash")
        .hash_length(32)
        .hash(fbb.finished_data())
        .as_bytes()
        .try_into()
        .unwrap();

    let inputs = ballot.inputs.unwrap();
    let proofs = witness.proofs.unwrap();
    let cmx_root = election.cmx.as_ref().unwrap();
    let nf_root = election.nf.as_ref().unwrap();
    for (i, p) in inputs.iter().zip(proofs.iter()) {
        let data = p.data.as_ref().unwrap();
        let zkproof = Proof::new(data.clone());
        let rk: VerificationKey<SpendAuth> = i.rk.try_into().unwrap();
        let proof_public = ProofBalancePublic {
            cv: ValueCommitment::from_bytes(&i.cv).unwrap(),
            domain_nf: Nullifier::from_bytes(&i.nf).unwrap(),
            rk,
            proof: zkproof,
            cmx_root: Anchor::from_bytes(hex::decode(&cmx_root).unwrap().try_into().unwrap())
                .unwrap(),
            nf_root: Anchor::from_bytes(hex::decode(&nf_root).unwrap().try_into().unwrap())
                .unwrap(),
        };

        verify_proof(domain, &proof_public)?;
    }

    let valuebalance = ValueCommitment::derive_from_value(ballot.amount as i64);
    let total_cv = inputs
        .iter()
        .map(|i| ValueCommitment::from_bytes(&i.cv).unwrap())
        .sum::<ValueCommitment>()
        - valuebalance;
    let bvk = total_cv.to_bytes();
    let bvk: VerificationKey<Binding> = bvk.try_into().unwrap();

    let signature = witness.binding_signature.as_ref().unwrap();
    let mut binding_signature = [0u8; 64];
    binding_signature[0..32].copy_from_slice(&signature.r_part);
    binding_signature[32..64].copy_from_slice(&signature.s_part);
    let binding_signature: Signature<Binding> = binding_signature.into();
    bvk.verify(&sig_hash, &binding_signature)?;

    let nfs = inputs.iter().map(|i| {
        i.nf.clone()
    }).collect::<Vec<_>>();
    let validation_result = ValidationResult {
        sig_hash,
        amount: ballot.amount,
        candidate: ballot.payload.as_ref().unwrap().clone(),
        nfs,
    };
    Ok(validation_result)
}

#[derive(Debug)]
pub struct ValidationResult {
    pub sig_hash: Hash,
    pub amount: u64,
    pub candidate: Vec<u8>,
    pub nfs: Vec<Hash>,
}
