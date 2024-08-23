use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;

use bdk_wallet::bitcoin::{
    self, consensus::Decodable, hashes::Hash, secp256k1::Secp256k1, Network,
};
use bdk_wallet::chain::{
    keychain_txout, local_chain, miniscript, tx_graph, Anchor, ConfirmationBlockTime,
    DescriptorExt, Merge,
};
use bdk_wallet::descriptor::ExtendedDescriptor;
use bdk_wallet::{AsyncWalletPersister, ChangeSet, KeychainKind};
use sqlx::{
    postgres::{PgPool, PgPoolOptions, Postgres},
    Row, Transaction,
};

/// Error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("migrate error: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    #[error("miniscript error: {0}")]
    Miniscript(#[from] miniscript::Error),
    #[error("serde_json error: {0}")]
    SerdeJson(#[from] serde_json::error::Error),
    #[error("sqlx error: {0}")]
    Sqlx(#[from] sqlx::Error),
}

/// Store.
#[derive(Debug)]
pub struct Store {
    pool: PgPool,
    wallet_name: String,
}

impl Store {
    /// Construct a new [`Store`].
    pub async fn new(url: &str, wallet_name: &str) -> Result<Self, Error> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(url)
            .await?;

        Ok(Self {
            pool,
            wallet_name: wallet_name.to_string(),
        })
    }
}
impl AsyncWalletPersister for Store {
    type Error = Error;

    fn initialize<'a>(store: &'a mut Self) -> FutureResult<'a, ChangeSet, Self::Error>
    where
        Self: 'a,
    {
        Box::pin(store.migrate_and_read())
    }

    fn persist<'a>(
        store: &'a mut Self,
        changeset: &'a ChangeSet,
    ) -> FutureResult<'a, (), Self::Error>
    where
        Self: 'a,
    {
        Box::pin(store.write(changeset))
    }
}

type FutureResult<'a, T, E> = Pin<Box<dyn Future<Output = Result<T, E>> + Send + 'a>>;

impl Store {
    async fn migrate_and_read(&self) -> Result<ChangeSet, Error> {
        sqlx::migrate!("db/migrations").run(&self.pool).await?;

        let mut tx = self.pool.begin().await?;

        let mut changeset = ChangeSet::default();

        // Fetch wallet data
        let row = sqlx::query(
            "SELECT n.name as network, k.descriptor, k.last_revealed \
             FROM network n \
             JOIN keychain k ON n.wallet_name = k.wallet_name \
             WHERE n.wallet_name = $1 \
             LIMIT 1",
        )
        .bind(&self.wallet_name)
        .fetch_optional(&mut *tx)
        .await?;

        if let Some(row) = row {
            let desc_str: String = row.get("descriptor");
            let network: String = row.get("network");
            let last_revealed: i32 = row.get("last_revealed");
            let (descriptor, _) =
                ExtendedDescriptor::parse_descriptor(&Secp256k1::new(), &desc_str)?;
            let did = descriptor.descriptor_id();
            changeset.descriptor = Some(descriptor);
            changeset.network = Some(Network::from_str(&network).expect("must parse"));
            changeset.indexer = keychain_txout::ChangeSet {
                last_revealed: [(did, last_revealed as u32)].into(),
            };
            changeset.tx_graph = tx_graph_changeset_from_postgres(&mut tx).await?;
            changeset.local_chain = local_chain_changeset_from_postgres(&mut tx).await?;
        }

        tx.commit().await?;

        Ok(changeset)
    }

    async fn write(&self, changeset: &ChangeSet) -> Result<(), Error> {
        if changeset.is_empty() {
            return Ok(());
        }

        let wallet_name = &self.wallet_name;
        let mut tx = self.pool.begin().await?;

        if let Some(ref descriptor) = changeset.descriptor {
            insert_descriptor(&mut tx, wallet_name, descriptor).await?;
        }
        if let Some(network) = changeset.network {
            insert_network(&mut tx, wallet_name, network).await?;
        }
        if let Some(last_revealed) = changeset.indexer.last_revealed.values().next() {
            update_last_revealed(&mut tx, wallet_name, *last_revealed).await?;
        }

        local_chain_changeset_persist_to_postgres(&mut tx, wallet_name, &changeset.local_chain)
            .await?;
        tx_graph_changeset_persist_to_postgres(&mut tx, wallet_name, &changeset.tx_graph).await?;

        tx.commit().await?;

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
    let keychain =
        serde_json::to_value(KeychainKind::External).expect("Serialization should not fail");

    sqlx::query(
        "INSERT INTO keychain (wallet_name, keychain, descriptor, descriptor_id)
                    VALUES ($1, to_jsonb($2), $3, $4)",
    )
    .bind(wallet_name)
    .bind(keychain)
    .bind(descriptor_str)
    .bind(descriptor_id.as_slice())
    .execute(&mut **tx)
    .await?;

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
        .await?;

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
        .await?;

    Ok(())
}

pub async fn tx_graph_changeset_from_postgres(
    db_tx: &mut Transaction<'_, Postgres>,
) -> Result<tx_graph::ChangeSet<ConfirmationBlockTime>, Error> {
    let mut changeset = tx_graph::ChangeSet::default();

    // Fetch transactions
    let rows = sqlx::query("SELECT txid, whole_tx, last_seen FROM tx")
        .fetch_all(&mut **db_tx)
        .await?;

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
        .await?;

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
        .await?;

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
) -> Result<(), Error> {
    for tx in &changeset.txs {
        sqlx::query(
            "INSERT INTO tx (wallet_name, txid, whole_tx) VALUES ($1, $2, $3)
             ON CONFLICT (wallet_name, txid) DO UPDATE SET whole_tx = $3",
        )
        .bind(wallet_name)
        .bind(tx.compute_txid().to_string())
        .bind(bitcoin::consensus::serialize(tx.as_ref()))
        .execute(&mut **db_tx)
        .await?;
    }

    for (&txid, &last_seen) in &changeset.last_seen {
        sqlx::query("UPDATE tx SET last_seen = $1 WHERE wallet_name = $2 AND txid = $3")
            .bind(last_seen as i64)
            .bind(wallet_name)
            .bind(txid.to_string())
            .execute(&mut **db_tx)
            .await?;
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
        .await?;
    }

    for (anchor, txid) in &changeset.anchors {
        let block_hash = anchor.anchor_block().hash;
        let anchor = serde_json::to_value(anchor)?;
        sqlx::query(
            "INSERT INTO anchor_tx (wallet_name, block_hash, anchor, txid) VALUES ($1, $2, $3, $4)
             ON CONFLICT (wallet_name, anchor, txid) DO UPDATE SET block_hash = $2",
        )
        .bind(wallet_name)
        .bind(block_hash.to_string())
        .bind(anchor)
        .bind(txid.to_string())
        .execute(&mut **db_tx)
        .await?;
    }

    Ok(())
}

pub async fn local_chain_changeset_from_postgres(
    db_tx: &mut Transaction<'_, Postgres>,
) -> Result<local_chain::ChangeSet, Error> {
    let mut changeset = local_chain::ChangeSet::default();

    let rows = sqlx::query("SELECT hash, height FROM block")
        .fetch_all(&mut **db_tx)
        .await?;

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
) -> Result<(), Error> {
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
                .await?;
            }
            None => {
                sqlx::query("DELETE FROM block WHERE wallet_name = $1 AND height = $2")
                    .bind(wallet_name)
                    .bind(height as i32)
                    .execute(&mut **db_tx)
                    .await?;
            }
        }
    }

    Ok(())
}