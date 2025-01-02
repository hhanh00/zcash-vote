use orchard::{keys::{FullViewingKey, PreparedIncomingViewingKey, Scope}, vote::ElectionDomain};
use rusqlite::{params, Connection};
use tonic::{transport::Endpoint, Request};

use crate::{decrypt::try_decrypt, rpc::{compact_tx_streamer_client::CompactTxStreamerClient, BlockId, BlockRange, CompactBlock}, Election, PoolConnection, Result};
use crate::errors::VoteError;

pub async fn download_reference_data(
    connection: PoolConnection,
    id_election: u32,
    election: &Election,
    fvk: Option<FullViewingKey>,
    lwd_url: &str,
    progress: impl Fn(u32) + Send + 'static,
) -> Result<(PoolConnection, u32)> {
    let pivk = fvk.clone().map(|fvk| {
        let ivk = fvk.to_ivk(Scope::External);
        PreparedIncomingViewingKey::new(&ivk)
    });
    let domain = election.domain();
    let start = election.start_height as u64;
    let end = election.end_height as u64;
    let lwd_url = lwd_url.to_string();

    let task = tokio::spawn(async move {
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
        while let Some(block) = blocks.message().await? {
            let height = block.height as u32;
            if height % 1000 == 0 || height == end as u32 {
                progress(block.height as u32);
            }
            let inc_position = handle_block(&connection, id_election, &domain, fvk.as_ref(), pivk.as_ref(), position, block)?;
            position += inc_position;
        }

        Ok::<_, VoteError>(connection)
    });

    let connection = tokio::spawn(async move {
        match task.await {
            Ok(Ok(connection)) => Ok(connection),
            Ok(Err(err)) => {
                eprintln!("Task returned an error: {}", err);
                Err(err)
            }
            Err(err) => {
                eprintln!("Task panicked: {:?}", err);
                let e: anyhow::Error = err.into();
                Err(e.into())
            }
        }
    }).await.unwrap()?;

    Ok((connection, end as u32))
}

fn handle_block(
    connection: &Connection,
    id_election: u32,
    domain: &ElectionDomain,
    fvk: Option<&FullViewingKey>,
    pivk: Option<&PreparedIncomingViewingKey>,
    start_position: usize,
    block: CompactBlock,
) -> Result<usize> {
    let mut s_cmx = connection.prepare_cached("INSERT INTO cmxs(hash) VALUES (?1)")?;
    let mut s_nf = connection.prepare_cached("INSERT INTO nullifiers(hash) VALUES (?1)")?;
    let mut position = 0usize;
    for tx in block.vtx {
        for a in tx.actions {
            if let Some(pivk) = pivk {
            if let Some(note) = try_decrypt(pivk, &a)? {
                    let p = start_position + position;
                    let height = block.height;
                    let txid = &tx.hash;
                    let value = note.value().inner();
                    let div = note.recipient().diversifier();
                    let rseed = note.rseed().as_bytes();
                    let nf = note.nullifier(fvk.unwrap()).to_bytes();
                    let domain_nf = note
                        .nullifier_domain(fvk.unwrap(), domain.0)
                        .to_bytes();
                    let rho = note.rho().to_bytes();
                    connection.execute(
                        "INSERT INTO notes
                        (election, position, height, txid, value, div, rseed, nf, dnf, rho, spent)
                        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, NULL)",
                        params![id_election, p, height, txid, value, div.as_array(), rseed, nf, domain_nf, rho],
                    )?;

                    println!("{:?}", note);
                }
            }
            let nf = &a.nullifier;
            let cmx = &a.cmx;
            s_nf.execute([nf])?;
            s_cmx.execute([cmx])?;
            position += 1;
        }
    }

    Ok(position)
}
