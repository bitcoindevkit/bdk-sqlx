#![no_main]

use bdk_sqlx_fuzz::{load, new_store, persist, Reader};
use bdk_wallet::bitcoin::hashes::Hash;
use bdk_wallet::bitcoin::{BlockHash, Txid};
use bdk_wallet::chain::{BlockId, ConfirmationBlockTime};
use bdk_wallet::ChangeSet;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut reader = Reader::new(data);
    let wallet_name = reader.wallet_name();
    let hash = BlockHash::from_byte_array(reader.array32());
    let txid = Txid::from_byte_array(reader.array32());
    let height = reader.u32() % 1_000_000;
    let height_other = (height + 1) % 1_000_000;
    let early = reader.u64() >> 1;
    let late = early ^ 1;

    let anchor = |height, confirmation_time| ConfirmationBlockTime {
        block_id: BlockId { height, hash },
        confirmation_time,
    };
    let same_block_early = anchor(height, early);
    let same_block_late = anchor(height, late);
    let other_height = anchor(height_other, early);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    runtime.block_on(async move {
        let mut store = new_store(wallet_name).await;

        let mut first = ChangeSet::default();
        first.tx_graph.anchors.insert((same_block_late, txid));
        persist(&mut store, &first)
            .await
            .expect("anchor without block or tx must persist");

        // A stale observation of the same block, plus the same hash at another
        // height, must each get their own row rather than replace the newer one.
        let mut stale = ChangeSet::default();
        stale.tx_graph.anchors.insert((same_block_early, txid));
        stale.tx_graph.anchors.insert((other_height, txid));
        persist(&mut store, &stale)
            .await
            .expect("distinct anchors must persist independently");

        let loaded = load(&mut store).await.expect("load anchors");
        assert_eq!(loaded.tx_graph.anchors.len(), 3);
        assert!(loaded.tx_graph.anchors.contains(&(same_block_late, txid)));
        assert!(loaded.tx_graph.anchors.contains(&(same_block_early, txid)));
        assert!(loaded.tx_graph.anchors.contains(&(other_height, txid)));
        assert!(loaded.tx_graph.txs.is_empty());
        assert!(loaded.local_chain.blocks.is_empty());
    });
});
