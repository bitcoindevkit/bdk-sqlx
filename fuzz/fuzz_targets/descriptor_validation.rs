#![no_main]

use bdk_sqlx::sqlx;
use bdk_sqlx::BdkSqlxError;
use bdk_sqlx_fuzz::{
    descriptor_changeset, load, new_store_with_pool, persist, unsupported_descriptors, Reader,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut reader = Reader::new(data);
    let wallet_name = reader.wallet_name();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    runtime.block_on(async move {
        let (mut store, pool) = new_store_with_pool(wallet_name.clone()).await;
        persist(&mut store, &descriptor_changeset())
            .await
            .expect("descriptor changeset must persist");

        for descriptor in unsupported_descriptors() {
            sqlx::query(
                "UPDATE keychain SET descriptor=$2 WHERE wallet_name=$1 AND keychainkind='External'",
            )
            .bind(&wallet_name)
            .bind(descriptor)
            .execute(&pool)
            .await
            .expect("update descriptor");

            match load(&mut store).await {
                Err(BdkSqlxError::UnsupportedDescriptor) => {}
                other => panic!("expected UnsupportedDescriptor, got {other:?}"),
            }
        }

        // Arbitrary bytes must also fail cleanly (or parse as a valid descriptor).
        sqlx::query(
            "UPDATE keychain SET descriptor=$2 WHERE wallet_name=$1 AND keychainkind='External'",
        )
        .bind(&wallet_name)
        .bind(reader.text(256))
        .execute(&pool)
        .await
        .expect("update descriptor");

        let _ = load(&mut store).await;
    });
});
