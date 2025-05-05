use std::collections::HashMap;

use orchard::keys::{FullViewingKey, PreparedIncomingViewingKey, Scope};
use pasta_curves::Fp;
use sqlx::{SqliteConnection, SqlitePool};
use tonic::{transport::Endpoint, Request};

use crate::as_byte256;
use crate::db::{mark_spent, store_prop};
use crate::errors::VoteError;
use crate::{
    db::store_note,
    decrypt::try_decrypt,
    election::Election,
    rpc::{compact_tx_streamer_client::CompactTxStreamerClient, BlockId, BlockRange, CompactBlock},
    Result,
};

pub async fn download_reference_data(
    connection: &SqlitePool,
    id_election: u32,
    election: &Election,
    fvk: Option<FullViewingKey>,
    lwd_url: &str,
    progress: impl Fn(u32) + Send + 'static,
) -> Result<u32> {
    let pivks = fvk.clone().map(|fvk| {
        let ivk = fvk.to_ivk(Scope::External);
        let pivk1 = PreparedIncomingViewingKey::new(&ivk);
        let ivk = fvk.to_ivk(Scope::Internal);
        let pivk2 = PreparedIncomingViewingKey::new(&ivk);
        (pivk1, pivk2)
    });
    let domain = election.domain();
    let start = election.start_height as u64;
    let end = election.end_height as u64;
    let lwd_url = lwd_url.to_string();

    let connection2 = connection.clone();
    let task = tokio::spawn(async move {
        let mut connection2 = connection2.acquire().await?;
        let ep = Endpoint::from_shared(lwd_url)?;
        let mut client = CompactTxStreamerClient::connect(ep).await?;
        let mut blocks = client
            .get_block_range(Request::new(BlockRange {
                start: Some(BlockId {
                    height: start + 1,
                    hash: vec![],
                }),
                end: Some(BlockId {
                    height: end,
                    hash: vec![],
                }),
                spam_filter_threshold: 0,
            }))
            .await?
            .into_inner();
        let mut position = 0usize;
        let mut nfs_cache = HashMap::new();
        while let Some(block) = blocks.message().await? {
            let height = block.height as u32;
            if height % 1000 == 0 || height == end as u32 {
                progress(block.height as u32);
            }
            let inc_position = handle_block(
                &mut connection2,
                id_election,
                domain,
                fvk.as_ref(),
                pivks.as_ref(),
                position,
                block,
                &mut nfs_cache,
            ).await?;
            position += inc_position;
        }

        Ok::<_, VoteError>(())
    });

    tokio::spawn(async move {
        match task.await {
            Ok(Err(err)) => {
                eprintln!("Task returned an error: {}", err);
                Err(err)
            }
            Err(err) => {
                eprintln!("Task panicked: {:?}", err);
                let e: anyhow::Error = err.into();
                Err(e.into())
            }
            Ok(_) => Ok(()),
        }
    })
    .await
    .unwrap()?;

    Ok(end as u32)
}

async fn handle_block(
    connection: &mut SqliteConnection,
    id_election: u32,
    domain: Fp,
    fvk: Option<&FullViewingKey>,
    pivks: Option<&(PreparedIncomingViewingKey, PreparedIncomingViewingKey)>,
    start_position: usize,
    block: CompactBlock,
    nfs_cache: &mut HashMap<[u8; 32], u32>,
) -> Result<usize> {
    let mut position = 0usize;
    for tx in block.vtx {
        let height = block.height;
        for a in tx.actions {
            if let Some((pivk1, pivk2)) = pivks {
                let fvk = fvk.unwrap(); // if we have pivk, we have fvk
                let p = start_position + position;
                let txid = &tx.hash;

                if let Some(note) = try_decrypt(pivk1, &a)? {
                    let id = store_note(
                        connection,
                        0,
                        domain,
                        fvk,
                        0,
                        height as u32,
                        p as u32,
                        txid,
                        &note,
                    ).await?;
                    nfs_cache.insert(note.nullifier(fvk).to_bytes(), id);
                }
                if let Some(note) = try_decrypt(pivk2, &a)? {
                    let id = store_note(
                        connection,
                        0,
                        domain,
                        fvk,
                        1,
                        height as u32,
                        p as u32,
                        txid,
                        &note,
                    ).await?;
                    nfs_cache.insert(note.nullifier(fvk).to_bytes(), id);
                }
            }
            let nf = &a.nullifier;
            let cmx = &a.cmx;

            sqlx::query("INSERT INTO nfs(election, hash) VALUES (?1, ?2)")
                .bind(id_election)
                .bind(nf)
                .execute(&mut *connection)
                .await?;

            sqlx::query("INSERT INTO cmxs(election, hash) VALUES (?, ?)")
                .bind(id_election)
                .bind(cmx)
                .execute(&mut *connection)
                .await?;
            if let Some(id) = nfs_cache.get(&as_byte256(nf)) {
                mark_spent(connection, *id, block.height as u32).await?;
            }
            position += 1;
        }
    }
    store_prop(connection, "height", &block.height.to_string()).await?;

    Ok(position)
}
