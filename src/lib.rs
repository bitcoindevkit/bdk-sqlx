use bdk_wallet::bitcoin::consensus::Decodable;
use bdk_wallet::bitcoin::hashes::Hash;
use bdk_wallet::bitcoin::secp256k1::Secp256k1;
use bdk_wallet::chain::{
    keychain_txout, local_chain, tx_graph, Anchor, ConfirmationBlockTime, DescriptorExt, Merge,
};
use bdk_wallet::descriptor::ExtendedDescriptor;
use bdk_wallet::{bitcoin, AsyncWalletPersister, ChangeSet};
use bitcoin::Network;
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;

// ... (keeping other imports and struct definitions)
/// Error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("sqlx error: {0}")]
    Sqlx(#[from] sqlx::Error),
}

/// Store.
#[derive(Debug)]
pub struct Store {
    pool: PgPool,
    network: Network,
}

impl Store {
    /// Construct a new [`Store`].
    pub async fn new(url: &str, network: Network) -> Result<Self, Error> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(url)
            .await
            .unwrap();

        Ok(Self { pool, network })
    }
}
impl AsyncWalletPersister for Store {
    type Error = Error;

    fn initialize<'a>(
        store: &'a mut Self,
        wallet_name: String,
    ) -> FutureResult<'a, ChangeSet, Self::Error>
    where
        Self: 'a,
    {
        Box::pin(store.migrate_and_read(wallet_name))
    }

    fn persist<'a>(
        store: &'a mut Self,
        changeset: &'a ChangeSet,
        wallet_name: String,
    ) -> FutureResult<'a, (), Self::Error>
    where
        Self: 'a,
    {
        Box::pin(store.write(changeset, wallet_name))
    }
}

type FutureResult<'a, T, E> = Pin<Box<dyn Future<Output = Result<T, E>> + Send + 'a>>;

/// Represents a row in the wallet table.
#[derive(Debug, sqlx::FromRow)]
struct WalletRow {
    network: String,
    descriptor: String,
    last_revealed: i32,
}
impl Store {
    async fn migrate_and_read(&self, wallet_name: String) -> Result<ChangeSet, Error> {
        let pool = &self.pool;
        // migrate(pool).await?;

        sqlx::migrate!("db/migrations").run(pool).await.unwrap();

        let mut changeset = ChangeSet::default();

        let mut tx = pool.begin().await.unwrap();

        // Fetch wallet data
        let row = sqlx::query_as::<_, WalletRow>(
            "SELECT n.name as network, k.descriptor, k.last_revealed 
             FROM network n 
             JOIN keychain k ON n.wallet_name = k.wallet_name 
             LIMIT 1",
        )
        .fetch_optional(&mut *tx)
        // .fetch_optional(&pool)
        .await
        .unwrap();

        if let Some(WalletRow {
            network,
            descriptor,
            last_revealed,
        }) = row
        {
            let (descriptor, _) =
                ExtendedDescriptor::parse_descriptor(&Secp256k1::new(), &descriptor).unwrap();
            let did = descriptor.descriptor_id();
            changeset.descriptor = Some(descriptor);
            changeset.network = Some(Network::from_str(&network).expect("must parse"));
            changeset.indexer = keychain_txout::ChangeSet {
                last_revealed: [(did, last_revealed as u32)].into(),
            };
        }

        changeset.tx_graph = tx_graph_changeset_from_postgres(&mut tx).await.unwrap();
        changeset.local_chain = local_chain_changeset_from_postgres(&mut tx).await.unwrap();
        // Note: keychain_txout ChangeSet is already set above

        tx.commit().await.unwrap();

        Ok(changeset)
    }

    async fn write(&self, changeset: &ChangeSet, wallet_name: String) -> Result<(), Error> {
        if changeset.is_empty() {
            return Ok(());
        }

        let pool = &self.pool;
        let mut tx = pool.begin().await.unwrap();

        // let network = self.network;

        // let descriptor = changeset.clone().descriptor.unwrap();
        // let change_descriptor = changeset.clone().change_descriptor;
        //
        // let wallet_name = bdk_wallet::wallet_name_from_descriptor(descriptor,change_descriptor , network,&Secp256k1::new()).unwrap();

        if let Some(ref descriptor) = changeset.descriptor {
            insert_descriptor(&mut tx, &wallet_name, descriptor)
                .await
                .unwrap();
        }
        if let Some(network) = changeset.network {
            insert_network(&mut tx, &wallet_name, network)
                .await
                .unwrap();
        }
        if let Some(last_revealed) = changeset.indexer.last_revealed.values().next() {
            update_last_revealed(&mut tx, &wallet_name, *last_revealed)
                .await
                .unwrap();
        }

        tx_graph_changeset_persist_to_postgres(&mut tx, &wallet_name, &changeset.tx_graph)
            .await
            .unwrap();
        local_chain_changeset_persist_to_postgres(&mut tx, &wallet_name, &changeset.local_chain)
            .await
            .unwrap();
        // Note: keychain_txout ChangeSet is already handled above

        tx.commit().await.unwrap();

        Ok(())
    }
}

async fn insert_descriptor(
    tx: &mut Transaction<'_, Postgres>,
    wallet_name: &str,
    descriptor: &ExtendedDescriptor,
) -> Result<(), Error> {
    let descriptor_str = descriptor.to_string();
    let descriptor_id = descriptor.descriptor_id().to_byte_array();
    let keychain = serde_json::to_value(descriptor).expect("Serialization should not fail");

    sqlx::query(
        "INSERT INTO keychain (wallet_name, keychain, descriptor, descriptor_id)
                    VALUES ($1, to_jsonb($2), $3, $4)",
    )
    .bind(wallet_name)
    .bind(keychain)
    .bind(descriptor_str)
    .bind(descriptor_id.as_slice())
    .execute(&mut **tx)
    .await
    .unwrap();

    Ok(())
}

async fn insert_network(
    tx: &mut Transaction<'_, Postgres>,
    wallet_name: &str,
    network: Network,
) -> Result<(), Error> {
    sqlx::query("INSERT INTO network (wallet_name, name) VALUES ($1, $2)")
        .bind(wallet_name)
        .bind(network.to_string())
        .execute(&mut **tx)
        .await
        .unwrap();

    Ok(())
}

async fn update_last_revealed(
    tx: &mut Transaction<'_, Postgres>,
    wallet_name: &str,
    last_revealed: u32,
) -> Result<(), Error> {
    sqlx::query("UPDATE keychain SET last_revealed = $1 WHERE wallet_name = $2")
        .bind(last_revealed as i32)
        .bind(wallet_name)
        .execute(&mut **tx)
        .await
        .unwrap();

    Ok(())
}

pub async fn tx_graph_changeset_from_postgres(
    db_tx: &mut Transaction<'_, Postgres>,
) -> sqlx::Result<tx_graph::ChangeSet<ConfirmationBlockTime>> {
    let mut changeset = tx_graph::ChangeSet::default();

    // Fetch transactions
    let rows = sqlx::query("SELECT txid, whole_tx, last_seen FROM tx")
        .fetch_all(&mut **db_tx)
        .await
        .unwrap();

    for row in rows {
        let txid: String = row.get("txid");
        let txid = bitcoin::Txid::from_str(&txid).expect("Invalid txid");
        let whole_tx: Option<Vec<u8>> = row.get("whole_tx");
        let last_seen: Option<i64> = row.get("last_seen");

        if let Some(tx_bytes) = whole_tx {
            if let Ok(tx) = bitcoin::Transaction::consensus_decode(&mut tx_bytes.as_slice()) {
                changeset.txs.insert(Arc::new(tx));
            }
        }
        if let Some(last_seen) = last_seen {
            changeset.last_seen.insert(txid, last_seen as u64);
        }
    }

    // Fetch txouts
    let rows = sqlx::query("SELECT txid, vout, value, script FROM txout")
        .fetch_all(&mut **db_tx)
        .await
        .unwrap();

    for row in rows {
        let txid: String = row.get("txid");
        let txid = bitcoin::Txid::from_str(&txid).expect("Invalid txid");
        let vout: i32 = row.get("vout");
        let value: i64 = row.get("value");
        let script: Vec<u8> = row.get("script");

        changeset.txouts.insert(
            bitcoin::OutPoint {
                txid,
                vout: vout as u32,
            },
            bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(value as u64),
                script_pubkey: bitcoin::ScriptBuf::from(script),
            },
        );
    }

    // Fetch anchors
    let rows = sqlx::query("SELECT anchor, txid FROM anchor_tx")
        .fetch_all(&mut **db_tx)
        .await
        .unwrap();

    for row in rows {
        let anchor: serde_json::Value = row.get("anchor");
        let txid: String = row.get("txid");
        let txid = bitcoin::Txid::from_str(&txid).expect("Invalid txid");

        if let Ok(anchor) = serde_json::from_value::<ConfirmationBlockTime>(anchor) {
            changeset.anchors.insert((anchor, txid));
        }
    }

    Ok(changeset)
}

pub async fn tx_graph_changeset_persist_to_postgres(
    db_tx: &mut Transaction<'_, Postgres>,
    wallet_name: &str,
    changeset: &tx_graph::ChangeSet<ConfirmationBlockTime>,
) -> sqlx::Result<()> {
    for tx in &changeset.txs {
        sqlx::query(
            "INSERT INTO tx (wallet_name, txid, whole_tx) VALUES ($1, $2, $3)
             ON CONFLICT (wallet_name, txid) DO UPDATE SET whole_tx = $3",
        )
        .bind(wallet_name)
        .bind(tx.compute_txid().to_string())
        .bind(bitcoin::consensus::serialize(tx.as_ref()))
        .execute(&mut **db_tx)
        .await
        .unwrap();
    }

    for (&txid, &last_seen) in &changeset.last_seen {
        sqlx::query("UPDATE tx SET last_seen = $1 WHERE wallet_name = $2 AND txid = $3")
            .bind(last_seen as i64)
            .bind(wallet_name)
            .bind(txid.to_string())
            .execute(&mut **db_tx)
            .await
            .unwrap();
    }

    for (op, txo) in &changeset.txouts {
        sqlx::query(
            "INSERT INTO txout (wallet_name, txid, vout, value, script) VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (wallet_name, txid, vout) DO UPDATE SET value = $4, script = $5",
        )
        .bind(wallet_name)
        .bind(op.txid.to_string())
        .bind(op.vout as i32)
        .bind(txo.value.to_sat() as i64)
        .bind(txo.script_pubkey.as_bytes())
        .execute(&mut **db_tx)
        .await
        .unwrap();
    }

    for (anchor, txid) in &changeset.anchors {
        let anchor_block = anchor.anchor_block();
        sqlx::query(
            "INSERT INTO anchor_tx (wallet_name, block_hash, anchor, txid) VALUES ($1, $2, $3, $4)
             ON CONFLICT (wallet_name, anchor, txid) DO UPDATE SET block_hash = $2",
        )
        .bind(wallet_name)
        .bind(anchor_block.hash.to_string())
        .bind(serde_json::to_value(anchor).unwrap())
        .bind(txid.to_string())
        .execute(&mut **db_tx)
        .await
        .unwrap();
    }

    Ok(())
}

pub async fn local_chain_changeset_from_postgres(
    db_tx: &mut Transaction<'_, Postgres>,
) -> sqlx::Result<local_chain::ChangeSet> {
    let mut changeset = local_chain::ChangeSet::default();

    let rows = sqlx::query("SELECT hash, height FROM block")
        .fetch_all(&mut **db_tx)
        .await
        .unwrap();

    for row in rows {
        let hash: String = row.get("hash");
        let height: i32 = row.get("height");
        if let Ok(block_hash) = bitcoin::BlockHash::from_str(&hash) {
            changeset.blocks.insert(height as u32, Some(block_hash));
        }
    }

    Ok(changeset)
}

pub async fn local_chain_changeset_persist_to_postgres(
    db_tx: &mut Transaction<'_, Postgres>,
    wallet_name: &str,
    changeset: &local_chain::ChangeSet,
) -> sqlx::Result<()> {
    for (&height, &hash) in &changeset.blocks {
        match hash {
            Some(hash) => {
                sqlx::query(
                    "INSERT INTO block (wallet_name, hash, height) VALUES ($1, $2, $3)
                     ON CONFLICT (wallet_name, hash) DO UPDATE SET height = $3",
                )
                .bind(wallet_name)
                .bind(hash.to_string())
                .bind(height as i32)
                .execute(&mut **db_tx)
                .await
                .unwrap();
            }
            None => {
                sqlx::query("DELETE FROM block WHERE wallet_name = $1 AND height = $2")
                    .bind(wallet_name)
                    .bind(height as i32)
                    .execute(&mut **db_tx)
                    .await
                    .unwrap();
            }
        }
    }

    Ok(())
}
