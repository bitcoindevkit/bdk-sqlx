//! bdk-sqlx sqlite store

#![warn(missing_docs)]

use std::str::FromStr;
use std::sync::Arc;

use super::{BdkSqlxError, FutureResult, Store};
use bdk_chain::{
    local_chain, tx_graph, Anchor, ConfirmationBlockTime, DescriptorExt, DescriptorId, Merge,
};
use bdk_wallet::bitcoin::{
    self, consensus, hashes::Hash, Amount, BlockHash, Network, OutPoint, ScriptBuf, TxOut, Txid,
};
use bdk_wallet::chain as bdk_chain;
use bdk_wallet::descriptor::{Descriptor, DescriptorPublicKey, ExtendedDescriptor};
use bdk_wallet::KeychainKind::{External, Internal};
use bdk_wallet::{AsyncWalletPersister, ChangeSet, KeychainKind};
use sqlx::sqlite::SqliteRow;
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};
use sqlx::sqlx_macros::migrate;
use sqlx::{sqlite::Sqlite, Pool, Row, Transaction};
use tracing::trace;

impl AsyncWalletPersister for Store<Sqlite> {
    type Error = BdkSqlxError;

    #[tracing::instrument(skip_all)]
    fn initialize<'a>(store: &'a mut Self) -> FutureResult<'a, ChangeSet, Self::Error>
    where
        Self: 'a,
    {
        trace!("initialize store");
        Box::pin(store.read())
    }

    #[tracing::instrument(skip_all)]
    fn persist<'a>(
        store: &'a mut Self,
        changeset: &'a ChangeSet,
    ) -> FutureResult<'a, (), Self::Error>
    where
        Self: 'a,
    {
        trace!("persist store");
        Box::pin(store.write(changeset))
    }
}

impl Store<Sqlite> {
    /// Construct a new [`Store`] with an existing sqlite connection pool.
    ///
    /// # Warning
    ///
    /// Do not pass a pool connected to `:memory:` with more than one connection:
    /// each sqlite connection gets its *own* private in-memory database, so a
    /// multi-connection pool silently reads and writes different databases (and
    /// per-connection `PRAGMA`s only apply to the connection that ran them).
    /// Use [`Store::new_with_url`] with `None` instead, which configures a
    /// single-connection pool correctly.
    #[tracing::instrument(skip_all)]
    pub async fn new(
        pool: Pool<Sqlite>,
        wallet_name: String,
        migrate: bool,
    ) -> Result<Self, BdkSqlxError> {
        trace!("new sqlite store");
        if migrate {
            trace!("migrate");
            migrate!("./migrations/sqlite").run(&pool).await?;
        }
        Ok(Self { pool, wallet_name })
    }

    /// Construct a new [`Store`] without an existing sqlite connection pool.
    ///
    /// The SQLite DB URL should look like "sqlite://bdk_wallet.sqlite?mode=rwc".
    ///
    /// If no URL is given a memory DB (non-persisted) will be used. A memory DB
    /// is useful for testing.
    #[tracing::instrument(skip_all)]
    pub async fn new_with_url(
        url: Option<String>,
        wallet_name: String,
        migrate: bool,
    ) -> Result<Store<Sqlite>, BdkSqlxError> {
        trace!("new store with url");
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
        Self::new(pool, wallet_name, migrate).await
    }
}

impl Store<Sqlite> {
    #[tracing::instrument(skip_all)]
    pub(crate) async fn read(&self) -> Result<ChangeSet, BdkSqlxError> {
        trace!("migrate and read");
        let mut tx = self.pool.begin().await?;
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
            Self::changeset_from_row(&mut tx, &mut changeset, row, &self.wallet_name).await?;
        }

        // The reads happened inside one transaction for a consistent snapshot;
        // close it out explicitly instead of relying on drop-rollback.
        tx.commit().await?;

        Ok(changeset)
    }

    //#[tracing::instrument(skip_all)]
    pub(crate) async fn changeset_from_row(
        tx: &mut Transaction<'_, Sqlite>,
        changeset: &mut ChangeSet,
        row: SqliteRow,
        wallet_name: &str,
    ) -> Result<(), BdkSqlxError> {
        trace!("changeset from row");

        let network: String = row.get("network");
        let internal_last_revealed: Option<i32> = row.get("internal_last_revealed");
        let external_last_revealed: Option<i32> = row.get("external_last_revealed");
        let internal_desc_str: Option<String> = row.get("internal_descriptor");
        let external_desc_str: Option<String> = row.get("external_descriptor");

        changeset.network =
            Some(
                Network::from_str(&network).map_err(|_| BdkSqlxError::InvalidNetwork {
                    expected: "a known network".to_string(),
                    got: network.clone(),
                })?,
            );

        if let Some(desc_str) = external_desc_str {
            let descriptor: Descriptor<DescriptorPublicKey> = desc_str.parse()?;
            let did = descriptor.descriptor_id();
            changeset.descriptor = Some(descriptor);
            if let Some(last_rev) = external_last_revealed {
                changeset.indexer.last_revealed.insert(
                    did,
                    crate::checked_conv(last_rev, "keychain.last_revealed")?,
                );
            }
        }

        if let Some(desc_str) = internal_desc_str {
            let descriptor: Descriptor<DescriptorPublicKey> = desc_str.parse()?;
            let did = descriptor.descriptor_id();
            changeset.change_descriptor = Some(descriptor);
            if let Some(last_rev) = internal_last_revealed {
                changeset.indexer.last_revealed.insert(
                    did,
                    crate::checked_conv(last_rev, "keychain.last_revealed")?,
                );
            }
        }

        changeset.tx_graph = tx_graph_changeset_from_sqlite(tx, wallet_name).await?;
        changeset.local_chain = local_chain_changeset_from_sqlite(tx, wallet_name).await?;
        Ok(())
    }

    #[tracing::instrument(skip_all)]
    pub(crate) async fn write(&self, changeset: &ChangeSet) -> Result<(), BdkSqlxError> {
        trace!("changeset write");
        if changeset.is_empty() {
            return Ok(());
        }

        let wallet_name = &self.wallet_name;
        let mut tx = self.pool.begin().await?;

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
#[tracing::instrument(skip_all)]
async fn insert_descriptor(
    tx: &mut Transaction<'_, Sqlite>,
    wallet_name: &str,
    descriptor: &ExtendedDescriptor,
    keychain: KeychainKind,
) -> Result<(), BdkSqlxError> {
    trace!("insert descriptor");
    let descriptor_str = descriptor.to_string();

    let descriptor_id = descriptor.descriptor_id().to_byte_array();
    let keychain = match keychain {
        External => "External",
        Internal => "Internal",
    };

    sqlx::query(
        "INSERT INTO keychain (wallet_name, keychainkind, descriptor, descriptor_id) VALUES ($1, $2, $3, $4)
         ON CONFLICT (wallet_name, keychainkind) DO UPDATE SET descriptor = excluded.descriptor, descriptor_id = excluded.descriptor_id",
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
#[tracing::instrument(skip_all)]
async fn insert_network(
    tx: &mut Transaction<'_, Sqlite>,
    wallet_name: &str,
    network: Network,
) -> Result<(), BdkSqlxError> {
    trace!("insert network");
    sqlx::query(
        "INSERT INTO network (wallet_name, name) VALUES ($1, $2)
         ON CONFLICT (wallet_name) DO UPDATE SET name = excluded.name",
    )
    .bind(wallet_name)
    .bind(network.to_string())
    .execute(&mut **tx)
    .await?;

    Ok(())
}

/// Update keychain last revealed
#[tracing::instrument(skip_all)]
async fn update_last_revealed(
    tx: &mut Transaction<'_, Sqlite>,
    wallet_name: &str,
    descriptor_id: DescriptorId,
    last_revealed: u32,
) -> Result<(), BdkSqlxError> {
    trace!("update last revealed");

    let result = sqlx::query::<Sqlite>(
        "UPDATE keychain SET last_revealed = $1 WHERE wallet_name = $2 AND descriptor_id = $3",
    )
    .bind(crate::checked_conv::<_, i32>(
        last_revealed,
        "keychain.last_revealed",
    )?)
    .bind(wallet_name)
    .bind(descriptor_id.to_byte_array().as_slice())
    .execute(&mut **tx)
    .await?;

    // Silently updating 0 rows would lose derivation state and cause address reuse.
    if result.rows_affected() == 0 {
        return Err(BdkSqlxError::QueryError {
            table: "keychain".to_string(),
            source: sqlx::Error::RowNotFound,
        });
    }

    Ok(())
}

/// Select transactions, txouts, and anchors.
#[tracing::instrument(skip_all)]
pub async fn tx_graph_changeset_from_sqlite(
    db_tx: &mut Transaction<'_, Sqlite>,
    wallet_name: &str,
) -> Result<tx_graph::ChangeSet<ConfirmationBlockTime>, BdkSqlxError> {
    trace!("tx graph changeset from sqlite");
    let mut changeset = tx_graph::ChangeSet::default();

    // Fetch transactions
    let rows = sqlx::query("SELECT txid, whole_tx, last_seen FROM tx WHERE wallet_name = $1")
        .bind(wallet_name)
        .fetch_all(&mut **db_tx)
        .await?;

    for row in rows {
        let txid: String = row.get("txid");
        let txid = Txid::from_str(&txid)?;
        let whole_tx: Option<Vec<u8>> = row.get("whole_tx");
        let last_seen: Option<i64> = row.get("last_seen");

        if let Some(tx_bytes) = whole_tx {
            let tx: bitcoin::Transaction = consensus::deserialize(&tx_bytes)?;
            let computed = tx.compute_txid();
            if computed != txid {
                return Err(BdkSqlxError::TxidMismatch {
                    stored: txid,
                    computed,
                });
            }
            changeset.txs.insert(Arc::new(tx));
        }
        if let Some(last_seen) = last_seen {
            changeset
                .last_seen
                .insert(txid, crate::checked_conv(last_seen, "tx.last_seen")?);
        }
    }

    // Fetch txouts
    let rows = sqlx::query("SELECT txid, vout, value, script FROM txout WHERE wallet_name = $1")
        .bind(wallet_name)
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
                vout: crate::checked_conv(vout, "txout.vout")?,
            },
            TxOut {
                value: Amount::from_sat(crate::checked_conv(value, "txout.value")?),
                script_pubkey: ScriptBuf::from(script),
            },
        );
    }

    // Fetch anchors
    let rows = sqlx::query(
        "SELECT json(anchor) as anchor, txid, block_hash FROM anchor_tx WHERE wallet_name = $1",
    )
    .bind(wallet_name)
    .fetch_all(&mut **db_tx)
    .await?;

    for row in rows {
        let anchor: serde_json::Value = row.get("anchor");
        let txid: String = row.get("txid");
        let txid = Txid::from_str(&txid)?;
        let block_hash: String = row.get("block_hash");
        let block_hash = BlockHash::from_str(&block_hash)?;

        let anchor: ConfirmationBlockTime = serde_json::from_value(anchor)?;
        let computed = anchor.anchor_block().hash;
        if computed != block_hash {
            return Err(BdkSqlxError::AnchorBlockHashMismatch {
                stored: block_hash,
                computed,
            });
        }
        changeset.anchors.insert((anchor, txid));
    }

    Ok(changeset)
}

/// Insert transactions, txouts, and anchors.
#[tracing::instrument(skip_all)]
pub async fn tx_graph_changeset_persist_to_sqlite(
    db_tx: &mut Transaction<'_, Sqlite>,
    wallet_name: &str,
    changeset: &tx_graph::ChangeSet<ConfirmationBlockTime>,
) -> Result<(), BdkSqlxError> {
    trace!("tx graph changeset from sqlite");
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
            .bind(crate::checked_conv::<_, i64>(last_seen, "tx.last_seen")?)
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
        .bind(crate::checked_conv::<_, i32>(op.vout, "txout.vout")?)
        .bind(crate::checked_conv::<_, i64>(
            txo.value.to_sat(),
            "txout.value",
        )?)
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
#[tracing::instrument(skip_all)]
pub async fn local_chain_changeset_from_sqlite(
    db_tx: &mut Transaction<'_, Sqlite>,
    wallet_name: &str,
) -> Result<local_chain::ChangeSet, BdkSqlxError> {
    trace!("local chain changeset from sqlite");
    let mut changeset = local_chain::ChangeSet::default();

    let rows = sqlx::query("SELECT hash, height FROM block WHERE wallet_name = $1")
        .bind(wallet_name)
        .fetch_all(&mut **db_tx)
        .await?;

    for row in rows {
        let hash: String = row.get("hash");
        let height: i32 = row.get("height");
        let block_hash = BlockHash::from_str(&hash)?;
        changeset.blocks.insert(
            crate::checked_conv(height, "block.height")?,
            Some(block_hash),
        );
    }

    Ok(changeset)
}

/// Insert blocks.
#[tracing::instrument(skip_all)]
pub async fn local_chain_changeset_persist_to_sqlite(
    db_tx: &mut Transaction<'_, Sqlite>,
    wallet_name: &str,
    changeset: &local_chain::ChangeSet,
) -> Result<(), BdkSqlxError> {
    trace!("local chain changeset to sqlite");
    for (&height, &hash) in &changeset.blocks {
        match hash {
            Some(hash) => {
                // A reorg can replace the block at this height with a different hash;
                // remove the stale row first (its anchors cascade away) so exactly one
                // row per (wallet_name, height) remains.
                sqlx::query(
                    "DELETE FROM block WHERE wallet_name = $1 AND height = $2 AND hash != $3",
                )
                .bind(wallet_name)
                .bind(crate::checked_conv::<_, i32>(height, "block.height")?)
                .bind(hash.to_string())
                .execute(&mut **db_tx)
                .await?;
                sqlx::query(
                    "INSERT INTO block (wallet_name, hash, height) VALUES ($1, $2, $3)
                     ON CONFLICT (wallet_name, hash) DO UPDATE SET height = $3",
                )
                .bind(wallet_name)
                .bind(hash.to_string())
                .bind(crate::checked_conv::<_, i32>(height, "block.height")?)
                .execute(&mut **db_tx)
                .await?;
            }
            None => {
                sqlx::query("DELETE FROM block WHERE wallet_name = $1 AND height = $2")
                    .bind(wallet_name)
                    .bind(crate::checked_conv::<_, i32>(height, "block.height")?)
                    .execute(&mut **db_tx)
                    .await?;
            }
        }
    }

    Ok(())
}
