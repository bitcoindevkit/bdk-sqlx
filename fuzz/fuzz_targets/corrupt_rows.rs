#![no_main]

use bdk_sqlx::sqlx;
use bdk_sqlx::sqlx::{Pool, Sqlite};
use bdk_sqlx_fuzz::{baseline_changeset, load, new_store_with_pool, persist, Reader};
use bdk_wallet::bitcoin::hashes::Hash;
use libfuzzer_sys::fuzz_target;

async fn apply_mutation(pool: &Pool<Sqlite>, wallet_name: &str, reader: &mut Reader<'_>) {
    match reader.u8() % 16 {
        0 => {
            let _ = sqlx::query("UPDATE tx SET txid=$2 WHERE wallet_name=$1")
                .bind(wallet_name)
                .bind(reader.bytes(32).to_vec())
                .execute(pool)
                .await;
        }
        1 => {
            let _ = sqlx::query("UPDATE tx SET whole_tx=$2 WHERE wallet_name=$1")
                .bind(wallet_name)
                .bind(reader.bytes(128).to_vec())
                .execute(pool)
                .await;
        }
        2 => {
            let _ = sqlx::query("UPDATE tx SET last_seen=$2 WHERE wallet_name=$1")
                .bind(wallet_name)
                .bind(reader.text(24))
                .execute(pool)
                .await;
        }
        3 => {
            let _ = sqlx::query("UPDATE txout SET txid=$2 WHERE wallet_name=$1")
                .bind(wallet_name)
                .bind(reader.bytes(32).to_vec())
                .execute(pool)
                .await;
        }
        4 => {
            let _ = sqlx::query("UPDATE txout SET vout=$2 WHERE wallet_name=$1")
                .bind(wallet_name)
                .bind(reader.i64())
                .execute(pool)
                .await;
        }
        5 => {
            let _ = sqlx::query("UPDATE txout SET value=$2 WHERE wallet_name=$1")
                .bind(wallet_name)
                .bind(reader.i64())
                .execute(pool)
                .await;
        }
        6 => {
            let _ = sqlx::query("UPDATE txout SET script=$2 WHERE wallet_name=$1")
                .bind(wallet_name)
                .bind(reader.bytes(128).to_vec())
                .execute(pool)
                .await;
        }
        7 => {
            let anchor = if reader.bool() {
                serde_json::json!({
                    "block_id": {
                        "height": reader.u32(),
                        "hash": bdk_wallet::bitcoin::BlockHash::from_byte_array(
                            reader.array32(),
                        )
                        .to_string(),
                    },
                    "confirmation_time": reader.u64(),
                })
                .to_string()
            } else {
                reader.text(48)
            };
            let _ = sqlx::query("UPDATE anchor_tx SET anchor=jsonb($2) WHERE wallet_name=$1")
                .bind(wallet_name)
                .bind(anchor)
                .execute(pool)
                .await;
        }
        8 => {
            let _ = sqlx::query("UPDATE anchor_tx SET block_height=$2 WHERE wallet_name=$1")
                .bind(wallet_name)
                .bind(reader.i64())
                .execute(pool)
                .await;
        }
        9 => {
            let _ = sqlx::query("UPDATE anchor_tx SET confirmation_time=$2 WHERE wallet_name=$1")
                .bind(wallet_name)
                .bind(reader.i64())
                .execute(pool)
                .await;
        }
        10 => {
            let _ = sqlx::query("UPDATE anchor_tx SET txid=$2 WHERE wallet_name=$1")
                .bind(wallet_name)
                .bind(reader.bytes(32).to_vec())
                .execute(pool)
                .await;
        }
        11 => {
            let _ = sqlx::query("UPDATE block SET height=$2 WHERE wallet_name=$1")
                .bind(wallet_name)
                .bind(reader.i64())
                .execute(pool)
                .await;
        }
        12 => {
            let _ = sqlx::query("UPDATE block SET hash=$2 WHERE wallet_name=$1")
                .bind(wallet_name)
                .bind(reader.bytes(32).to_vec())
                .execute(pool)
                .await;
        }
        13 => {
            let _ = sqlx::query("UPDATE keychain SET last_revealed=$2 WHERE wallet_name=$1")
                .bind(wallet_name)
                .bind(reader.i64())
                .execute(pool)
                .await;
        }
        14 => {
            let _ = sqlx::query("UPDATE keychain SET descriptor=$2 WHERE wallet_name=$1")
                .bind(wallet_name)
                .bind(reader.text(256))
                .execute(pool)
                .await;
        }
        _ => {
            let _ = sqlx::query("UPDATE network SET name=$2 WHERE wallet_name=$1")
                .bind(wallet_name)
                .bind(reader.text(24))
                .execute(pool)
                .await;
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut reader = Reader::new(data);
    let wallet_name = reader.wallet_name();
    let baseline = baseline_changeset(&mut reader);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    runtime.block_on(async move {
        let (mut store, pool) = new_store_with_pool(wallet_name.clone()).await;
        persist(&mut store, &baseline)
            .await
            .expect("baseline changeset must persist");

        for _ in 0..(1 + reader.u8() % 8) {
            apply_mutation(&pool, &wallet_name, &mut reader).await;
        }

        // The only invariant is that corrupt rows never panic the load. If the
        // corrupted state happens to be valid, exercise a write round trip too.
        if let Ok(loaded) = load(&mut store).await {
            let _ = persist(&mut store, &loaded).await;
            let _ = load(&mut store).await;
        }
    });
});
