#![no_main]

use bdk_sqlx::BdkSqlxError;
use bdk_sqlx_fuzz::{load, new_store, persist, random_changeset, Reader};
use bdk_wallet::chain::Merge;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut reader = Reader::new(data);
    let wallet_name = reader.wallet_name();
    let changeset = random_changeset(&mut reader);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    runtime.block_on(async move {
        let mut store = new_store(wallet_name).await;

        match persist(&mut store, &changeset).await {
            Ok(()) => {
                let first = load(&mut store)
                    .await
                    .expect("loading after a successful persist must succeed");
                persist(&mut store, &first)
                    .await
                    .expect("re-persisting a loaded snapshot must succeed");
                let second = load(&mut store)
                    .await
                    .expect("loading after re-persisting must succeed");
                assert_eq!(first, second, "persist/load must be idempotent");
            }
            // These are the only structurally invalid changesets the generator
            // can produce: one hash at multiple heights, or a value outside the
            // schema's representable range.
            Err(BdkSqlxError::IntOutOfRange { .. })
            | Err(BdkSqlxError::DuplicateBlockHash { .. }) => {
                let loaded = load(&mut store)
                    .await
                    .expect("loading after a rejected changeset must succeed");
                assert!(loaded.is_empty(), "a rejected changeset must roll back");
            }
            Err(error) => panic!("unexpected persist error: {error:?}"),
        }
    });
});
