use crate::{
    db::create_tables, lwd_rpc::{compact_tx_streamer_client::CompactTxStreamerClient, BlockId, BlockRange}, Connection, Election
};
use anyhow::Result;
use rusqlite::params;
use tonic::{transport::{Certificate, Channel, ClientTlsConfig}, Request};

/// Connect to a lightwalletd server
pub async fn connect_lightwalletd(url: &str) -> anyhow::Result<CompactTxStreamerClient<Channel>> {
    let mut channel = tonic::transport::Channel::from_shared(url.to_owned())?;
    if url.starts_with("https") {
        let pem = include_bytes!("ca.pem");
        let ca = Certificate::from_pem(pem);
        let tls = ClientTlsConfig::new().ca_certificate(ca);
        channel = channel.tls_config(tls)?;
    }
    let client = CompactTxStreamerClient::connect(channel).await?;
    Ok(client)
}

pub async fn download_reference_data(
    connection: &Connection,
    lwd_url: &str,
    election: &Election,
) -> Result<()> {
    create_tables(connection)?;
    let c = connection.query_row("SELECT COUNT(*) FROM cmxs", [], |r| r.get::<_, u32>(0))?;
    if c != 0 {
        return Ok(())
    }

    let mut client = connect_lightwalletd(lwd_url).await?;
    let mut block_stream = client
        .get_block_range(Request::new(BlockRange {
            start: Some(BlockId {
                height: election.start_height as u64,
                hash: vec![],
            }),
            end: Some(BlockId {
                height: election.end_height as u64,
                hash: vec![],
            }),
            spam_filter_threshold: 0,
        }))
        .await?
        .into_inner();

    let mut s_nf = connection.prepare(
        "INSERT INTO nullifiers(hash, revhash)
        VALUES (?1, ?2)",
    )?;
    let mut s_cmx = connection.prepare(
        "INSERT INTO cmxs(hash)
        VALUES (?1)",
    )?;
    let mut pos = 0;
    while let Some(block) = block_stream.message().await? {
        for tx in block.vtx.iter() {
            for a in tx.actions.iter() {
                let nf = &*a.nullifier;
                let mut rev_nf = [0u8; 32];
                rev_nf.copy_from_slice(nf);
                rev_nf.reverse();
                s_nf.execute(params![nf, &rev_nf])?;
                let cmx = &*a.cmx;
                s_cmx.execute(params![cmx])?;
                pos += 1;
            }
        }
    }
    if pos & 1 == 1 {
        let er = orchard::pob::empty_hash();
        s_cmx.execute(params![&er])?;
    }
    Ok(())
}
