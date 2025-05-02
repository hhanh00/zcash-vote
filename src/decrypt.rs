use anyhow::{anyhow, Result};
use bip0039::{English, Mnemonic};
use orchard::{
    keys::{FullViewingKey, PreparedIncomingViewingKey, SpendingKey},
    note::{ExtractedNoteCommitment, Nullifier, Rho},
    note_encryption::{CompactAction, OrchardDomain},
    Note,
};
use zcash_address::unified::{self, Container, Encoding, Fvk};
use zcash_note_encryption::{try_compact_note_decryption, EphemeralKeyBytes};
use zcash_primitives::zip32::AccountId;

use crate::{as_byte256, rpc::CompactOrchardAction};

pub fn to_sk(key: &str) -> Result<Option<SpendingKey>> {
    if let Ok(m) = Mnemonic::<English>::from_phrase(key) {
        let seed = m.to_seed("");
        let spk =
            SpendingKey::from_zip32_seed(&seed, zcash_primitives::constants::mainnet::COIN_TYPE, AccountId::ZERO)
                .map_err(|_| anyhow!("Failed to derive zip-32"))?;
        return Ok(Some(spk));
    }
    Ok(None)
}

pub fn to_fvk(key: &str) -> Result<FullViewingKey> {
    if let Some(spk) = to_sk(key)? {
        return Ok(FullViewingKey::from(&spk));
    } else {
        let (_, ufvk) = unified::Ufvk::decode(key)?;
        for fvk in ufvk.items() {
            if let Fvk::Orchard(fvk) = fvk {
                let fvk = FullViewingKey::from_bytes(&fvk).unwrap();
                return Ok(fvk);
            }
        }
    }
    anyhow::bail!("UFVK does not have an Orchard receiver");
}

pub fn try_decrypt(
    ivk: &PreparedIncomingViewingKey,
    action: &CompactOrchardAction,
) -> Result<Option<Note>> {
    let CompactOrchardAction {
        nullifier,
        cmx,
        ephemeral_key,
        ciphertext,
    } = action;

    let nf = Nullifier::from_bytes(&as_byte256(nullifier)).unwrap();
    let rho = Rho::from_nf_old(nf);
    let domain = OrchardDomain::for_rho(rho);
    let action = CompactAction::from_parts(
        nf,
        ExtractedNoteCommitment::from_bytes(&as_byte256(cmx)).unwrap(),
        EphemeralKeyBytes(as_byte256(ephemeral_key)),
        ciphertext.clone().try_into().unwrap(),
    );
    let note = try_compact_note_decryption(&domain, ivk, &action).map(|na| na.0);
    Ok(note)
}
