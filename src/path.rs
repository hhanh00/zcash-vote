use std::mem::swap;

use anyhow::Result;

use crate::{Hash, DEPTH};

#[derive(Clone, Default)]
pub struct MerklePath {
    pub value: Hash,
    pub position: u32,
    pub path: [Hash; DEPTH],
    p: usize,
}

pub fn calculate_merkle_paths(
    position_offset: usize,
    positions: &[u32],
    hashes: &[Hash],
) -> Result<Vec<MerklePath>> {
    let mut paths = positions
        .iter()
        .map(|p| {
            let rel_p = *p as usize - position_offset;
            MerklePath {
                value: hashes[rel_p],
                position: rel_p as u32,
                path: [Hash::default(); DEPTH],
                p: rel_p,
            }
        })
        .collect::<Vec<_>>();
    let mut er = orchard::pob::empty_hash();
    let mut layer = Vec::with_capacity(positions.len() + 2);
    for i in 0..32 {
        if i == 0 {
            layer.extend(hashes);
            if layer.len() & 1 == 1 {
                layer.push(er);
            }
        }

        for path in paths.iter_mut() {
            let idx = path.p;
            if idx & 1 == 1 {
                path.path[i] = layer[idx as usize - 1];
            } else {
                path.path[i] = layer[idx as usize + 1];
            }
            path.p /= 2;
        }

        let pairs = layer.len() / 2;
        let mut next_layer = Vec::with_capacity(pairs + 2);

        for j in 0..pairs {
            let h = orchard::pob::cmx_hash(i as u8, &layer[j * 2], &layer[j * 2 + 1]);
            next_layer.push(h);
        }

        er = orchard::pob::cmx_hash(i as u8, &er, &er);
        if next_layer.len() & 1 == 1 {
            next_layer.push(er);
        }

        swap(&mut layer, &mut next_layer);
    }

    Ok(paths)
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use crate::{db::get_connection, net::download_reference_data, Election};

    #[tokio::test]
    async fn test() -> Result<()> {
        const DB_FILE: &str = "/Users/hanhhuynhhuu/Library/Containers/me.hanh.ywallet/Data/Library/Application Support/me.hanh.ywallet/databases/zec.db";
        const LWD_URL: &str = "https://lwd5.zcash-infra.com:9067";

        let e = Election {
            name: "Devfund Poll".to_string(),
            start_height: 2540000,
            end_height: 2541500,
            cmx: None,
            nf: None,
        };
        let manager = r2d2_sqlite::SqliteConnectionManager::file(DB_FILE);
        let pool = r2d2::Pool::new(manager)?;
        let connection = get_connection(&pool);

        download_reference_data(&connection, LWD_URL, &e).await?;
        Ok(())
    }
}
