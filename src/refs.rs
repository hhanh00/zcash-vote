use orchard::{
    keys::{Diversifier, FullViewingKey, Scope, SpendingKey},
    note::{Nullifier, RandomSeed},
    tree::MerklePath,
    value::NoteValue,
    Address, Note,
};
use rusqlite::params;
use zcash_primitives::constants::mainnet::COIN_TYPE;

use crate::{
    errors::VoteError, net::connect_lightwalletd, prevhash::fetch_tree_state, Connection, Hash,
    VoteNote,
};

pub fn list_cmxs(connection: &Connection) -> Result<Vec<Hash>, VoteError> {
    let mut s = connection.prepare("SELECT hash FROM cmxs ORDER BY id_cmx")?;
    let rows = s.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
    let mut cmxs = vec![];
    for r in rows {
        let hash = r?;
        let hash: Hash = hash.try_into().unwrap();
        cmxs.push(hash);
    }
    Ok(cmxs)
}

pub fn list_nfs(connection: &Connection) -> Result<Vec<Nullifier>, VoteError> {
    let mut s = connection.prepare("SELECT hash FROM nullifiers ORDER BY revhash")?;
    let rows = s.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
    let mut nfs = vec![];
    for r in rows {
        let hash = r?;
        let hash: Hash = hash.try_into().unwrap();
        nfs.push(Nullifier::from_bytes(&hash).unwrap());
    }
    let nfs = orchard::vote::build_nf_ranges(nfs.into_iter());
    Ok(nfs)
}

pub async fn get_cmx_count(lwd_url: &str, height: u32) -> Result<usize, VoteError> {
    let mut client = connect_lightwalletd(lwd_url).await?;
    let ph = fetch_tree_state(&mut client, height - 1).await?;
    Ok(ph.position())
}

pub fn list_notes(
    connection: &Connection,
    account: u32,
    cmx_offset: usize,
    start_height: u32,
    end_height: u32,
    id_notes: &[u32],
    all_notes: bool,
) -> Result<(SpendingKey, Vec<VoteNote>), VoteError> {
    let (sk, fvk) = connection.query_row(
        "SELECT sk, fvk FROM orchard_addrs WHERE account = ?1",
        [account],
        |r| {
            let sk = r.get::<_, Vec<u8>>(0)?;
            let fvk = r.get::<_, Vec<u8>>(1)?;
            Ok((sk, fvk))
        },
    )?;
    let sk = SpendingKey::from_bytes(sk.try_into().unwrap()).unwrap();
    let fvk = FullViewingKey::from_bytes(&fvk.try_into().unwrap()).unwrap();

    let mut notes = vec![];
    let mut s = connection.prepare("SELECT id_note, position, diversifier, value, rcm, nf, rho FROM received_notes WHERE account = ?1 AND height >= ?2 AND height <= ?3 AND orchard = 1 AND (spent IS NULL OR spent > ?3)")?;
    let rows = s.query_map(params![account, start_height, end_height], |r| {
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

        if all_notes || id_notes.contains(&id_note) {
            let note = Note::from_parts(recipient, value, rho, rseed).unwrap();
            let note = VoteNote {
                note,
                idx: position as usize - cmx_offset,
                nf: note.nullifier(&fvk),
                nf_start: Nullifier::empty(),
                nf_path: MerklePath::empty(),
                cmx_path: MerklePath::empty(),
            };
            notes.push(note);
        }
    }

    Ok((sk, notes))
}

pub fn get_candidate_fvk(seed: Hash, candidate: u32) -> Result<FullViewingKey, VoteError> {
    let sk = SpendingKey::from_zip32_seed(&seed, COIN_TYPE, candidate).unwrap();
    let fvk = FullViewingKey::from(&sk);
    Ok(fvk)
}

pub fn get_candidate_address(seed: Hash, candidate: u32) -> Result<Address, VoteError> {
    let fvk = get_candidate_fvk(seed, candidate)?;
    let address = fvk.address_at(0u64, Scope::External);
    Ok(address)
}

#[cfg(test)]
mod tests {
    use crate::{download_reference_data, drop_tables};

    use super::*;
    use orchard::vote::BallotBuilder;
    use r2d2::Pool;
    use r2d2_sqlite::SqliteConnectionManager;
    use rand::rngs::OsRng;
    use std::str::FromStr;

    #[tokio::test]
    async fn f() {
        dotenv::dotenv().unwrap();
        let lwd_url = dotenv::var("LWD_URL").unwrap();
        let db_path = dotenv::var("DB_PATH").unwrap();
        let start_height = u32::from_str(&dotenv::var("START").unwrap()).unwrap();
        let end_height = u32::from_str(&dotenv::var("END").unwrap()).unwrap();
        let idx_offset = get_cmx_count(&lwd_url, start_height - 1).await.unwrap();
        let pool = Pool::new(SqliteConnectionManager::file(db_path)).unwrap();
        let connection = crate::db::get_connection(&pool);

        // drop_tables(&connection).unwrap();
        // download_reference_data(&connection, &lwd_url, start_height, end_height).await.unwrap();

        let cmxs = list_cmxs(&connection).unwrap();
        let nfs = list_nfs(&connection).unwrap();
        let (sk, notes) = list_notes(
            &connection,
            1,
            idx_offset,
            start_height,
            end_height,
            &[],
            true,
        )
        .unwrap();

        let fvk = FullViewingKey::from(&sk);
        for n in nfs.iter() {
            println!("{:?}", n);
        }
        for vn in notes.iter() {
            println!("{:?}", vn.note.nullifier(&fvk));
        }

        // let seed = [42u8; 32];
        // let mut builder = BallotBuilder::new("test-election", seed, cmxs, nfs);
        // let total_value = notes.iter().map(|n| n.note.value().inner()).sum::<u64>();
        // for vn in notes.iter() {
        //     builder.add_note(vn.idx as u32, sk, vn.note.clone()).unwrap();
        // }
        // let address = get_candidate_address(seed, 1).unwrap();
        // builder.add_candidate(address, total_value).unwrap();
        // let (ballot, rcv) = builder.build(OsRng).unwrap();

        // let a = &ballot.actions[0];
    }
}
