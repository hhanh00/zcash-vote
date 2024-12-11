use crate::{
    errors::VoteError, lwd_rpc::{compact_tx_streamer_client::CompactTxStreamerClient, BlockId, BlockRange}, Election
};
use anyhow::Result;
use tonic::{transport::{Certificate, Channel, ClientTlsConfig}, Request};

/// Connect to a lightwalletd server
pub async fn connect_lightwalletd(url: &str) -> Result<CompactTxStreamerClient<Channel>, VoteError> {
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
    lwd_url: &str,
    election: &Election,
) -> Result<(Vec<Vec<u8>>, Vec<Vec<u8>>)> {
    // let c = connection.query_row("SELECT COUNT(*) FROM cmxs", [], |r| r.get::<_, u32>(0))?;
    // if c != 0 {
    //     return Ok(())
    // }

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

    let mut pos = 0;
    let mut nfs = vec![];
    let mut cmxs = vec![];
    while let Some(block) = block_stream.message().await? {
        for tx in block.vtx.iter() {
            for a in tx.actions.iter() {
                nfs.push(a.nullifier.to_vec());
                cmxs.push(a.cmx.clone());
                pos += 1;
            }
        }
    }

    // cmxs are padded to an even # of nodes
    // nfs is not padded because the nullifier tree
    // has 2x len(nfs) which is always even
    if pos & 1 == 1 {
        let er = orchard::pob::empty_hash();
        cmxs.push(er.to_vec());
    }
    Ok((nfs, cmxs))
}
