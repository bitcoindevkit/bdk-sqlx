//! bdk-sqlx postgres store

#![warn(missing_docs)]

// Standard library imports
use std::{
    str::FromStr,
    sync::{Arc, OnceLock},
};
// Third party crates
use bdk_chain::{
    local_chain, tx_graph, Anchor, ConfirmationBlockTime, DescriptorExt, DescriptorId, Merge,
};
use bdk_wallet::{
    bitcoin::{
        self, consensus, hashes::Hash, Amount, BlockHash, Network, OutPoint, ScriptBuf, TxOut, Txid,
    },
    chain as bdk_chain,
    descriptor::{Descriptor, DescriptorPublicKey, ExtendedDescriptor},
    AsyncWalletPersister, ChangeSet, KeychainKind,
    KeychainKind::{External, Internal},
};
use sqlx::{
    postgres::{PgPool, PgRow, Postgres},
    sqlx_macros::migrate,
    Pool, Row, Transaction,
};
use tracing::{trace, warn};

// First party imports
use super::{BdkSqlxError, FutureResult, PgStoreBuilder, Store};

type Result<T> = core::result::Result<T, BdkSqlxError>;

/// Thread-safe storage for the network configuration that's shared across all Store instances.
/// This ensures consistent network validation across multiple threads.
static NETWORK: OnceLock<Network> = OnceLock::new();

/// Retrieves the current global network configuration for validation operations.
///
/// Returns the current network configuration or an error if not initialized.
fn get_network() -> Result<Network> {
    NETWORK
        .get()
        .copied()
        .ok_or_else(|| BdkSqlxError::GetNetworkFailure)
}

/// Sets the global network configuration to ensure consistent validation across threads.
///
/// Returns an error if the network is already initialized with a different network.
fn initialize_network(network: Network) -> Result<()> {
    match NETWORK.get() {
        Some(current) if *current == network => {
            warn!("initialize_network called more than once");
            Ok(())
        }
        Some(current) => Err(BdkSqlxError::DuplicateInitNetwork {
            current: *current,
            network,
        }),
        None => NETWORK
            .set(network)
            .map_err(BdkSqlxError::SetNetworkFailure),
    }
}

impl AsyncWalletPersister for Store<Postgres> {
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

impl PgStoreBuilder {
    /// Creates a new builder for a [`Store`] with the given wallet name.
    ///
    /// # Required fields
    /// Before building, you must set:
    /// - `network` - The Bitcoin network to use
    /// - Either provide a connection pool with `pool()` or a database URL with `build_with_url()`
    ///
    /// # Example
    /// ```
    /// # async fn example() -> Result<(), bdk_sqlx::BdkSqlxError> {
    /// use bdk_wallet::bitcoin::Network;
    /// use bdk_sqlx::PgStoreBuilder;
    ///
    /// let store = PgStoreBuilder::new("bdk_wallet_name".to_string())
    ///     .network(Network::Testnet)
    ///     .migrate(true)
    ///     .build_with_url("postgres://username:password@localhost/database")
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument]
    pub fn new(wallet_name: String) -> Self {
        Self {
            wallet_name,
            pool: None,
            migrate: false,
            network: None,
        }
    }

    /// Sets the database connection pool for the [`Store`].
    ///
    /// The pool is required to build a valid [`Store`]. If not provided,
    /// the build operation will fail with a MissingPool error.
    pub fn pool(mut self, pool: Pool<Postgres>) -> Self {
        self.pool = Some(pool);
        self
    }

    /// Sets whether database migrations should be run during [`Store`] initialization.
    ///
    /// When set to true, the necessary database schema and tables will be created
    /// if they don't already exist.
    pub fn migrate(mut self, migrate: bool) -> Self {
        self.migrate = migrate;
        self
    }

    /// Sets the Bitcoin network for the [`Store`].
    ///
    /// The network is required to build a valid [`Store`]. If not provided,
    /// the build operation will fail with a MissingNetwork error.
    pub fn network(mut self, network: Network) -> Self {
        self.network = Some(network);
        self
    }

    /// Builds the [`Store`] with the configured options.
    ///
    /// This method creates a new [`Store`] instance using the options that have been
    /// set on this builder. It requires both a network and a pool to be specified
    /// before building.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No network has been specified (MissingNetwork)
    /// - No pool has been specified (MissingPool)
    /// - Migration fails
    /// - Network initialization fails
    pub async fn build(self) -> Result<Store<Postgres>> {
        let network = self.network.ok_or_else(|| BdkSqlxError::MissingNetwork)?;

        match self.pool {
            Some(pool) => {
                let store = Store {
                    pool,
                    wallet_name: self.wallet_name,
                };
                if self.migrate {
                    store.migrate().await?;
                }

                initialize_network(network)?;

                Ok(store)
            }
            None => Err(BdkSqlxError::MissingPool),
        }
    }

    /// Builds the [`Store`] with a new connection pool created from the provided URL.
    ///
    /// This is a convenience method that creates a connection pool from the URL
    /// and then builds the [`Store`] using that pool.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Database connection fails
    /// - Any error that could occur in the build() method
    pub async fn build_with_url(self, url: &str) -> Result<Store<Postgres>> {
        let pool = PgPool::connect(url).await?;
        let store = self.pool(pool).build().await?;
        Ok(store)
    }
}

impl Store<Postgres> {
    /// Runs the versioned migrations in `migrations/postgres` for this [`Store`].
    ///
    /// Databases created by earlier releases (which created the schema without
    /// migration bookkeeping) are adopted transparently: migration 01 only uses
    /// `CREATE ... IF NOT EXISTS`, and migration 02 upgrades pre-existing
    /// `anchor_tx` constraints in place.
    #[tracing::instrument(skip_all)]
    pub async fn migrate(&self) -> Result<()> {
        trace!("migrating bdk sqlx");
        migrate!("./migrations/postgres").run(&self.pool).await?;
        Ok(())
    }
}

impl Store<Postgres> {
    #[tracing::instrument(skip_all)]
    pub(crate) async fn read(&self) -> Result<ChangeSet> {
        trace!("reading");
        let mut db_tx = self.pool.begin().await?;
        let mut changeset = ChangeSet::default();
        let sql = r#"SELECT n.name as network,
        k_int.descriptor as internal_descriptor, k_int.last_revealed as internal_last_revealed,
        k_ext.descriptor as external_descriptor, k_ext.last_revealed as external_last_revealed
        FROM "bdk_wallet"."network" n
        LEFT JOIN "bdk_wallet"."keychain" k_int ON n.wallet_name = k_int.wallet_name AND k_int.keychainkind = 'Internal'
        LEFT JOIN "bdk_wallet"."keychain" k_ext ON n.wallet_name = k_ext.wallet_name AND k_ext.keychainkind = 'External'
        WHERE n.wallet_name = $1"#;

        // Fetch wallet data
        let row = sqlx::query(sql)
            .bind(&self.wallet_name)
            .fetch_optional(&mut *db_tx)
            .await
            .map_err(|e| BdkSqlxError::QueryError {
                table: "read".to_string(),
                source: e,
            })?;

        if let Some(row) = row {
            Self::changeset_from_row(&mut db_tx, &mut changeset, row, &self.wallet_name).await?;
        }

        Ok(changeset)
    }

    #[tracing::instrument(skip(db_tx, changeset, row))]
    pub(crate) async fn changeset_from_row(
        db_tx: &mut Transaction<'_, Postgres>,
        changeset: &mut ChangeSet,
        row: PgRow,
        wallet_name: &str,
    ) -> Result<()> {
        trace!("changeset from row");

        let network: String = row.get("network");
        let internal_last_revealed: Option<i32> = row.get("internal_last_revealed");
        let external_last_revealed: Option<i32> = row.get("external_last_revealed");
        let internal_desc_str: Option<String> = row.get("internal_descriptor");
        let external_desc_str: Option<String> = row.get("external_descriptor");

        let stored_network =
            Network::from_str(&network).map_err(|_| BdkSqlxError::InvalidNetwork {
                expected: get_network()
                    .map(|n| n.to_string())
                    .unwrap_or_else(|_| "a known network".to_string()),
                got: network.clone(),
            })?;
        // Reject data persisted for a different network than this process was
        // configured for, instead of silently loading it.
        if let Ok(configured) = get_network() {
            if configured != stored_network {
                return Err(BdkSqlxError::InvalidNetwork {
                    expected: configured.to_string(),
                    got: stored_network.to_string(),
                });
            }
        }
        changeset.network = Some(stored_network);

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

        changeset.tx_graph = tx_graph_changeset_from_postgres(db_tx, wallet_name).await?;
        changeset.local_chain = local_chain_changeset_from_postgres(db_tx, wallet_name).await?;
        Ok(())
    }

    #[tracing::instrument(skip_all)]
    pub(crate) async fn write(&self, changeset: &ChangeSet) -> Result<()> {
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

        local_chain_changeset_persist_to_postgres(&mut tx, wallet_name, &changeset.local_chain)
            .await?;
        tx_graph_changeset_persist_to_postgres(&mut tx, wallet_name, &changeset.tx_graph).await?;

        tx.commit().await?;

        Ok(())
    }
}

/// Insert keychain descriptors.
#[tracing::instrument(skip(db_tx, descriptor))]
async fn insert_descriptor(
    db_tx: &mut Transaction<'_, Postgres>,
    wallet_name: &str,
    descriptor: &ExtendedDescriptor,
    keychain: KeychainKind,
) -> Result<()> {
    trace!("insert descriptor");
    let descriptor_str = descriptor.to_string();

    let descriptor_id = descriptor.descriptor_id().to_byte_array();
    let keychain = match keychain {
        External => "External",
        Internal => "Internal",
    };

    sqlx::query(
        r#"INSERT INTO "bdk_wallet"."keychain" (wallet_name, keychainkind, descriptor, descriptor_id) VALUES ($1, $2, $3, $4)
         ON CONFLICT (wallet_name, keychainkind) DO UPDATE SET descriptor = excluded.descriptor, descriptor_id = excluded.descriptor_id"#,
    )
        .bind(wallet_name)
        .bind(keychain)
        .bind(descriptor_str)
        .bind(descriptor_id.as_slice())
        .execute(&mut **db_tx)
        .await
        .map_err(|e| BdkSqlxError::QueryError {
            table: "insert keychain".to_string(),
            source: e,
        })?;

    Ok(())
}

/// Insert network.
#[tracing::instrument(skip(db_tx, network))]
async fn insert_network(
    db_tx: &mut Transaction<'_, Postgres>,
    wallet_name: &str,
    network: Network,
) -> Result<()> {
    trace!("insert network");
    sqlx::query(
        r#"INSERT INTO "bdk_wallet"."network" (wallet_name, name) VALUES ($1, $2)
         ON CONFLICT (wallet_name) DO UPDATE SET name = excluded.name"#,
    )
    .bind(wallet_name)
    .bind(network.to_string())
    .execute(&mut **db_tx)
    .await
    .map_err(|e| BdkSqlxError::QueryError {
        table: "insert network".to_string(),
        source: e,
    })?;

    Ok(())
}

/// Update keychain last revealed
#[tracing::instrument(skip(db_tx, descriptor_id, last_revealed))]
async fn update_last_revealed(
    db_tx: &mut Transaction<'_, Postgres>,
    wallet_name: &str,
    descriptor_id: DescriptorId,
    last_revealed: u32,
) -> Result<()> {
    trace!("update last revealed");

    let result = sqlx::query(
        r#"UPDATE "bdk_wallet"."keychain" SET last_revealed = $1 WHERE wallet_name = $2 AND descriptor_id = $3"#,
    )
    .bind(crate::checked_conv::<_, i32>(last_revealed, "keychain.last_revealed")?)
    .bind(wallet_name)
    .bind(descriptor_id.to_byte_array())
    .execute(&mut **db_tx)
    .await
        .map_err(|e| BdkSqlxError::QueryError {
            table: "update keychain".to_string(),
            source: e,
        })?;

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
#[tracing::instrument(skip(db_tx))]
pub async fn tx_graph_changeset_from_postgres(
    db_tx: &mut Transaction<'_, Postgres>,
    wallet_name: &str,
) -> Result<tx_graph::ChangeSet<ConfirmationBlockTime>> {
    trace!("tx graph changeset from postgres");
    let mut changeset = tx_graph::ChangeSet::default();

    // Fetch transactions
    let rows = sqlx::query(
        r#"SELECT txid, whole_tx, last_seen FROM "bdk_wallet"."tx" WHERE wallet_name = $1"#,
    )
    .bind(wallet_name)
    .fetch_all(&mut **db_tx)
    .await
    .map_err(|e| BdkSqlxError::QueryError {
        table: "select tx".to_string(),
        source: e,
    })?;

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
    let rows = sqlx::query(
        r#"SELECT txid, vout, value, script FROM "bdk_wallet"."txout" WHERE wallet_name = $1"#,
    )
    .bind(wallet_name)
    .fetch_all(&mut **db_tx)
    .await
    .map_err(|e| BdkSqlxError::QueryError {
        table: "select txout".to_string(),
        source: e,
    })?;

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
        r#"SELECT anchor, txid, block_hash FROM "bdk_wallet"."anchor_tx" WHERE wallet_name = $1"#,
    )
    .bind(wallet_name)
    .fetch_all(&mut **db_tx)
    .await
    .map_err(|e| BdkSqlxError::QueryError {
        table: "select anchor tx".to_string(),
        source: e,
    })?;

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
#[tracing::instrument(skip(db_tx, changeset))]
pub async fn tx_graph_changeset_persist_to_postgres(
    db_tx: &mut Transaction<'_, Postgres>,
    wallet_name: &str,
    changeset: &tx_graph::ChangeSet<ConfirmationBlockTime>,
) -> Result<()> {
    trace!("tx graph changeset from postgres");
    for tx in &changeset.txs {
        sqlx::query(
            r#"INSERT INTO "bdk_wallet"."tx" (wallet_name, txid, whole_tx) VALUES ($1, $2, $3)
             ON CONFLICT (wallet_name, txid) DO UPDATE SET whole_tx = $3"#,
        )
        .bind(wallet_name)
        .bind(tx.compute_txid().to_string())
        .bind(consensus::serialize(tx.as_ref()))
        .execute(&mut **db_tx)
        .await
        .map_err(|e| BdkSqlxError::QueryError {
            table: "insert tx".to_string(),
            source: e,
        })?;
    }

    for (&txid, &last_seen) in &changeset.last_seen {
        sqlx::query(
            r#"UPDATE "bdk_wallet"."tx" SET last_seen = $1 WHERE wallet_name = $2 AND txid = $3"#,
        )
        .bind(crate::checked_conv::<_, i64>(last_seen, "tx.last_seen")?)
        .bind(wallet_name)
        .bind(txid.to_string())
        .execute(&mut **db_tx)
        .await
        .map_err(|e| BdkSqlxError::QueryError {
            table: "update tx".to_string(),
            source: e,
        })?;
    }

    for (op, txo) in &changeset.txouts {
        sqlx::query(
            r#"INSERT INTO "bdk_wallet"."txout" (wallet_name, txid, vout, value, script) VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (wallet_name, txid, vout) DO UPDATE SET value = $4, script = $5"#,
        )
        .bind(wallet_name)
        .bind(op.txid.to_string())
        .bind(crate::checked_conv::<_, i32>(op.vout, "txout.vout")?)
        .bind(crate::checked_conv::<_, i64>(txo.value.to_sat(), "txout.value")?)
        .bind(txo.script_pubkey.as_bytes())
        .execute(&mut **db_tx)
        .await
            .map_err(|e| BdkSqlxError::QueryError {
                table: "insert txout".to_string(),
                source: e,
            })?;
    }

    for (anchor, txid) in &changeset.anchors {
        let block_hash = anchor.anchor_block().hash;
        let anchor = serde_json::to_value(anchor)?;
        sqlx::query(
            r#"INSERT INTO "bdk_wallet"."anchor_tx" (wallet_name, block_hash, anchor, txid) VALUES ($1, $2, $3, $4)
             ON CONFLICT (wallet_name, block_hash, txid) DO UPDATE SET anchor = $3"#,
        )
        .bind(wallet_name)
        .bind(block_hash.to_string())
        .bind(anchor)
        .bind(txid.to_string())
        .execute(&mut **db_tx)
        .await
            .map_err(|e| BdkSqlxError::QueryError {
                table: "insert anchor tx".to_string(),
                source: e,
            })?;
    }

    Ok(())
}

/// Select blocks.
#[tracing::instrument(skip(db_tx))]
pub async fn local_chain_changeset_from_postgres(
    db_tx: &mut Transaction<'_, Postgres>,
    wallet_name: &str,
) -> Result<local_chain::ChangeSet> {
    trace!("local chain changeset from postgres");
    let mut changeset = local_chain::ChangeSet::default();

    let rows =
        sqlx::query(r#"SELECT hash, height FROM "bdk_wallet"."block" WHERE wallet_name = $1"#)
            .bind(wallet_name)
            .fetch_all(&mut **db_tx)
            .await
            .map_err(|e| BdkSqlxError::QueryError {
                table: "select block".to_string(),
                source: e,
            })?;

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
#[tracing::instrument(skip(db_tx, changeset))]
pub async fn local_chain_changeset_persist_to_postgres(
    db_tx: &mut Transaction<'_, Postgres>,
    wallet_name: &str,
    changeset: &local_chain::ChangeSet,
) -> Result<()> {
    trace!("local chain changeset to postgres");
    for (&height, &hash) in &changeset.blocks {
        match hash {
            Some(hash) => {
                sqlx::query(
                    r#"INSERT INTO "bdk_wallet"."block" (wallet_name, hash, height) VALUES ($1, $2, $3)
                     ON CONFLICT (wallet_name, hash) DO UPDATE SET height = $3"#,
                )
                .bind(wallet_name)
                .bind(hash.to_string())
                .bind(crate::checked_conv::<_, i32>(height, "block.height")?)
                .execute(&mut **db_tx)
                .await
                    .map_err(|e| BdkSqlxError::QueryError {
                        table: "insert block".to_string(),
                        source: e,
                    })?;
            }
            None => {
                sqlx::query(
                    r#"DELETE FROM "bdk_wallet"."block" WHERE wallet_name = $1 AND height = $2"#,
                )
                .bind(wallet_name)
                .bind(crate::checked_conv::<_, i32>(height, "block.height")?)
                .execute(&mut **db_tx)
                .await
                .map_err(|e| BdkSqlxError::QueryError {
                    table: "delete block".to_string(),
                    source: e,
                })?;
            }
        }
    }

    Ok(())
}
