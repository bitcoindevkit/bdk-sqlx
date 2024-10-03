//! bdk-sqlx sqlite store

#![warn(missing_docs)]

use std::str::FromStr;
use std::sync::Arc;

use super::{BdkSqlxError, FutureResult, Store};
use bdk_chain::{
    local_chain, tx_graph, Anchor, ConfirmationBlockTime, DescriptorExt, DescriptorId, Merge,
};
use bdk_wallet::bitcoin::{
    self,
    consensus::{self, Decodable},
    hashes::Hash,
    Amount, BlockHash, Network, OutPoint, ScriptBuf, TxOut, Txid,
};
use bdk_wallet::chain as bdk_chain;
use bdk_wallet::descriptor::{Descriptor, DescriptorPublicKey, ExtendedDescriptor};
use bdk_wallet::KeychainKind::{External, Internal};
use bdk_wallet::{AsyncWalletPersister, ChangeSet, KeychainKind};
use serde_json::json;
use sqlx::sqlite::SqliteRow;
use sqlx::{
    migrate::Migrator,
    sqlite::{SqlitePool, SqlitePoolOptions},
};
use sqlx::{sqlite::Sqlite, FromRow, Pool, Row, Transaction};
use tokio::sync::Mutex;
use tracing::info;

impl AsyncWalletPersister for Store<Sqlite> {
    type Error = BdkSqlxError;

    #[tracing::instrument]
    fn initialize<'a>(store: &'a mut Self) -> FutureResult<'a, ChangeSet, Self::Error>
    where
        Self: 'a,
    {
        info!("initialize store");
        Box::pin(store.migrate_and_read())
    }

    #[tracing::instrument]
    fn persist<'a>(
        store: &'a mut Self,
        changeset: &'a ChangeSet,
    ) -> FutureResult<'a, (), Self::Error>
    where
        Self: 'a,
    {
        info!("persist store");
        Box::pin(store.write(changeset))
    }
}

impl Store<Sqlite> {
    /// Construct a new [`Store`] with an existing sqlite connection.
    #[tracing::instrument]
    pub async fn new(
        pool: Arc<Mutex<Pool<Sqlite>>>,
        wallet_name: Option<String>,
        migration: bool,
    ) -> Result<Self, BdkSqlxError> {
        info!("new store");

        let wallet_name = wallet_name.unwrap_or_else(|| "bdk_sqlites_wallet".to_string());

        Ok(Self {
            pool,
            wallet_name,
            migration,
        })
    }

    /// Construct a new [`Store`] without an existing sqlite connection.
    ///
    /// The SQLite DB URL should look like "sqlite://bdk_wallet.sqlite?mode=rwc".
    ///
    /// If no URL is given a memory DB (non-persisted) will be used. A memory DB
    /// is useful for testing.
    #[tracing::instrument]
    pub async fn new_with_url(
        url: Option<String>,
        wallet_name: Option<String>,
    ) -> Result<Store<Sqlite>, BdkSqlxError> {
        info!("new store with url");

        let pool = if let Some(url) = url {
            SqlitePool::connect(url.as_str()).await?
        } else {
            // must limit to one connection and no timeout if using memory DB
            SqlitePoolOptions::new()
                .max_connections(1)
                .min_connections(1)
                .idle_timeout(None)
                .max_lifetime(None)
                .connect(":memory:")
                .await?
        };
        let pool = Arc::new(Mutex::new(pool));
        let wallet_name = wallet_name.unwrap_or_else(|| "bdk_sqlite_wallet".to_string());

        Ok(Self {
            pool,
            wallet_name,
            migration: true,
        })
    }
}

impl Store<Sqlite> {
    #[tracing::instrument]
    pub(crate) async fn migrate_and_read(&self) -> Result<ChangeSet, BdkSqlxError> {
        info!("migrate and read");
        let pool = self.pool.lock().await;
        if self.migration {
            let migrator = Migrator::new(std::path::Path::new("./migrations/sqlite/"))
                .await
                .unwrap();
            migrator.run(&*pool).await.unwrap();
        }

        let mut tx = pool.begin().await?;

        let mut changeset = ChangeSet::default();

        let sql =
            "SELECT n.name as network,
            k_int.descriptor as internal_descriptor, k_int.last_revealed as internal_last_revealed,
            k_ext.descriptor as external_descriptor, k_ext.last_revealed as external_last_revealed
            FROM network n
            LEFT JOIN keychain k_int ON n.wallet_name = k_int.wallet_name AND k_int.keychainkind = 'Internal'
            LEFT JOIN keychain k_ext ON n.wallet_name = k_ext.wallet_name AND k_ext.keychainkind = 'External'
            WHERE n.wallet_name = $1";

        // Fetch wallet data
        let row = sqlx::query(sql)
            .bind(&self.wallet_name)
            .fetch_optional(&mut *tx)
            .await?;

        //dbg!(&row);

        if let Some(row) = row {
            Self::changeset_from_row(&mut tx, &mut changeset, row).await?;
        }

        Ok(changeset)
    }

    //#[tracing::instrument]
    pub(crate) async fn changeset_from_row(
        tx: &mut Transaction<'_, Sqlite>,
        changeset: &mut ChangeSet,
        row: SqliteRow,
    ) -> Result<(), BdkSqlxError> {
        info!("changeset from row");

        let network: String = row.get("network");
        let internal_last_revealed: Option<i32> = row.get("internal_last_revealed");
        let external_last_revealed: Option<i32> = row.get("external_last_revealed");
        let internal_desc_str: Option<String> = row.get("internal_descriptor");
        let external_desc_str: Option<String> = row.get("external_descriptor");

        changeset.network = Some(Network::from_str(&network).expect("parse Network"));

        if let Some(desc_str) = external_desc_str {
            let descriptor: Descriptor<DescriptorPublicKey> = desc_str.parse()?;
            let did = descriptor.descriptor_id();
            changeset.descriptor = Some(descriptor);
            if let Some(last_rev) = external_last_revealed {
                changeset.indexer.last_revealed.insert(did, last_rev as u32);
            }
        }

        if let Some(desc_str) = internal_desc_str {
            let descriptor: Descriptor<DescriptorPublicKey> = desc_str.parse()?;
            let did = descriptor.descriptor_id();
            changeset.change_descriptor = Some(descriptor);
            if let Some(last_rev) = internal_last_revealed {
                changeset.indexer.last_revealed.insert(did, last_rev as u32);
            }
        }

        changeset.tx_graph = tx_graph_changeset_from_sqlite(tx).await?;
        changeset.local_chain = local_chain_changeset_from_sqlite(tx).await?;
        Ok(())
    }

    #[tracing::instrument]
    pub(crate) async fn write(&self, changeset: &ChangeSet) -> Result<(), BdkSqlxError> {
        info!("changeset write");
        if changeset.is_empty() {
            return Ok(());
        }

        let wallet_name = &self.wallet_name;
        let pool = self.pool.lock().await;
        let mut tx = pool.begin().await?;

        if let Some(ref descriptor) = changeset.descriptor {
            insert_descriptor(&mut tx, wallet_name, descriptor, External).await?;
        }

        if let Some(ref change_descriptor) = changeset.change_descriptor {
            insert_descriptor(&mut tx, wallet_name, change_descriptor, Internal).await?;
        }

        if let Some(network) = changeset.network {
            insert_network(&mut tx, wallet_name, network).await?;
        }

        let last_revealed_indices = &changeset.indexer.last_revealed;
        if !last_revealed_indices.is_empty() {
            for (desc_id, index) in last_revealed_indices {
                update_last_revealed(&mut tx, wallet_name, *desc_id, *index).await?;
            }
        }

        local_chain_changeset_persist_to_sqlite(&mut tx, wallet_name, &changeset.local_chain)
            .await?;
        tx_graph_changeset_persist_to_sqlite(&mut tx, wallet_name, &changeset.tx_graph).await?;

        tx.commit().await?;

        Ok(())
    }
}

/// Insert keychain descriptors.
#[tracing::instrument]
async fn insert_descriptor(
    tx: &mut Transaction<'_, Sqlite>,
    wallet_name: &str,
    descriptor: &ExtendedDescriptor,
    keychain: KeychainKind,
) -> Result<(), BdkSqlxError> {
    info!("insert descriptor");
    let descriptor_str = descriptor.to_string();

    let descriptor_id = descriptor.descriptor_id().to_byte_array();
    let keychain = match keychain {
        External => "External",
        Internal => "Internal",
    };

    sqlx::query(
        "INSERT INTO keychain (wallet_name, keychainkind, descriptor, descriptor_id) VALUES ($1, $2, $3, $4)",
    )
        .bind(wallet_name)
        .bind(keychain)
        .bind(descriptor_str)
        .bind(descriptor_id.as_slice())
        .execute(&mut **tx)
        .await?;

    Ok(())
}

/// Insert network.
#[tracing::instrument]
async fn insert_network(
    tx: &mut Transaction<'_, Sqlite>,
    wallet_name: &str,
    network: Network,
) -> Result<(), BdkSqlxError> {
    info!("insert network");
    sqlx::query("INSERT INTO network (wallet_name, name) VALUES ($1, $2)")
        .bind(wallet_name)
        .bind(network.to_string())
        .execute(&mut **tx)
        .await?;

    Ok(())
}

/// Update keychain last revealed
#[tracing::instrument]
async fn update_last_revealed(
    tx: &mut Transaction<'_, Sqlite>,
    wallet_name: &str,
    descriptor_id: DescriptorId,
    last_revealed: u32,
) -> Result<(), BdkSqlxError> {
    info!("update last revealed");

    sqlx::query::<Sqlite>(
        "UPDATE keychain SET last_revealed = $1 WHERE wallet_name = $2 AND descriptor_id = $3",
    )
    .bind(last_revealed as i32)
    .bind(wallet_name)
    .bind(descriptor_id.to_byte_array().as_slice())
    .execute(&mut **tx)
    .await?;

    Ok(())
}

/// Select transactions, txouts, and anchors.
#[tracing::instrument]
pub async fn tx_graph_changeset_from_sqlite(
    db_tx: &mut Transaction<'_, Sqlite>,
) -> Result<tx_graph::ChangeSet<ConfirmationBlockTime>, BdkSqlxError> {
    info!("tx graph changeset from sqlite");
    let mut changeset = tx_graph::ChangeSet::default();

    // Fetch transactions
    let rows = sqlx::query("SELECT txid, whole_tx, last_seen FROM tx")
        .fetch_all(&mut **db_tx)
        .await?;

    for row in rows {
        let txid: String = row.get("txid");
        let txid = Txid::from_str(&txid)?;
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
        let txid = Txid::from_str(&txid)?;
        let vout: i32 = row.get("vout");
        let value: i64 = row.get("value");
        let script: Vec<u8> = row.get("script");

        changeset.txouts.insert(
            OutPoint {
                txid,
                vout: vout as u32,
            },
            TxOut {
                value: Amount::from_sat(value as u64),
                script_pubkey: ScriptBuf::from(script),
            },
        );
    }

    // Fetch anchors
    let rows = sqlx::query("SELECT json(anchor) as anchor, txid FROM anchor_tx")
        .fetch_all(&mut **db_tx)
        .await?;

    for row in rows {
        let anchor: serde_json::Value = row.get("anchor");
        let txid: String = row.get("txid");
        let txid = Txid::from_str(&txid)?;

        if let Ok(anchor) = serde_json::from_value::<ConfirmationBlockTime>(anchor) {
            changeset.anchors.insert((anchor, txid));
        }
    }

    Ok(changeset)
}

/// Insert transactions, txouts, and anchors.
#[tracing::instrument]
pub async fn tx_graph_changeset_persist_to_sqlite(
    db_tx: &mut Transaction<'_, Sqlite>,
    wallet_name: &str,
    changeset: &tx_graph::ChangeSet<ConfirmationBlockTime>,
) -> Result<(), BdkSqlxError> {
    info!("tx graph changeset from sqlite");
    for tx in &changeset.txs {
        sqlx::query(
            "INSERT INTO tx (wallet_name, txid, whole_tx) VALUES ($1, $2, $3)
             ON CONFLICT (wallet_name, txid) DO UPDATE SET whole_tx = $3",
        )
        .bind(wallet_name)
        .bind(tx.compute_txid().to_string())
        .bind(consensus::serialize(tx.as_ref()))
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
            "INSERT INTO anchor_tx (wallet_name, block_hash, anchor, txid) VALUES ($1, $2, jsonb($3), $4)
             ON CONFLICT (wallet_name, block_hash, txid) DO UPDATE SET anchor = jsonb($3)",
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

/// Select blocks.
#[tracing::instrument]
pub async fn local_chain_changeset_from_sqlite(
    db_tx: &mut Transaction<'_, Sqlite>,
) -> Result<local_chain::ChangeSet, BdkSqlxError> {
    info!("local chain changeset from sqlite");
    let mut changeset = local_chain::ChangeSet::default();

    let rows = sqlx::query("SELECT hash, height FROM block")
        .fetch_all(&mut **db_tx)
        .await?;

    for row in rows {
        let hash: String = row.get("hash");
        let height: i32 = row.get("height");
        let block_hash = BlockHash::from_str(&hash)?;
        changeset.blocks.insert(height as u32, Some(block_hash));
    }

    Ok(changeset)
}

/// Insert blocks.
#[tracing::instrument]
pub async fn local_chain_changeset_persist_to_sqlite(
    db_tx: &mut Transaction<'_, Sqlite>,
    wallet_name: &str,
    changeset: &local_chain::ChangeSet,
) -> Result<(), BdkSqlxError> {
    info!("local chain changeset to sqlite");
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

/// Collects information on all the wallets in the database and dumps it to stdout.
#[tracing::instrument]
pub async fn easy_backup(db: Pool<Sqlite>) -> Result<(), BdkSqlxError> {
    info!("Starting easy backup");

    let statement = "SELECT * FROM keychain";

    let results = sqlx::query_as::<_, KeychainEntry>(statement)
        .fetch_all(&db)
        .await?;

    let json_array = json!(results);
    println!("{}", serde_json::to_string_pretty(&json_array)?);

    info!("Easy backup completed successfully");
    Ok(())
}

/// Represents a row in the keychain table.
#[derive(serde::Serialize, FromRow)]
struct KeychainEntry {
    wallet_name: String,
    keychainkind: String,
    descriptor: String,
    descriptor_id: Vec<u8>,
    last_revealed: i32,
}
