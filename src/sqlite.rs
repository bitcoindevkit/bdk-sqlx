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
use bdk_wallet::descriptor::ExtendedDescriptor;
use bdk_wallet::KeychainKind::{External, Internal};
use bdk_wallet::{AsyncWalletPersister, ChangeSet, KeychainKind};
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
    /// `network` fixes the process-global network (shared with the postgres
    /// backend): the first store built in the process sets it, later stores
    /// must use the same one, and stored or incoming data for a different
    /// network is rejected with [`BdkSqlxError::InvalidNetwork`].
    ///
    /// # Warning
    ///
    /// Do not pass a pool connected to `:memory:` with more than one connection:
    /// each sqlite connection gets its *own* private in-memory database, so a
    /// multi-connection pool silently reads and writes different databases (and
    /// per-connection `PRAGMA`s only apply to the connection that ran them).
    /// Use [`Store::new_with_url`] with `None` instead, which configures a
    /// single-connection pool correctly.
    ///
    /// The pool must not disable `PRAGMA foreign_keys` (sqlx enables it by
    /// default): reorg handling relies on `ON DELETE CASCADE`, and with
    /// foreign keys off a disconnected block's anchor rows are silently left
    /// behind and reload forever.
    #[tracing::instrument(skip_all)]
    pub async fn new(
        pool: Pool<Sqlite>,
        wallet_name: String,
        network: Network,
        migrate: bool,
    ) -> Result<Self, BdkSqlxError> {
        trace!("new sqlite store");
        let store = Self { pool, wallet_name };
        if migrate {
            trace!("migrate");
            store.migrate().await?;
        }
        crate::initialize_network(network)?;
        Ok(store)
    }

    /// Runs the versioned migrations in `migrations/sqlite` for this [`Store`].
    ///
    /// Mirrors [`Store::<Postgres>::migrate`]: migrations are recorded in
    /// sqlx's bookkeeping table, so re-running them is a no-op.
    #[tracing::instrument(skip_all)]
    pub async fn migrate(&self) -> Result<(), BdkSqlxError> {
        trace!("migrating bdk sqlx");
        migrate!("./migrations/sqlite").run(&self.pool).await?;
        Ok(())
    }

    /// Construct a new [`Store`] without an existing sqlite connection pool.
    ///
    /// The SQLite DB URL should look like "sqlite://bdk_wallet.sqlite?mode=rwc".
    ///
    /// If no URL is given a memory DB (non-persisted) will be used. A memory DB
    /// is useful for testing.
    ///
    /// `network` has the same process-global semantics as [`Store::new`].
    #[tracing::instrument(skip_all)]
    pub async fn new_with_url(
        url: Option<String>,
        wallet_name: String,
        network: Network,
        migrate: bool,
    ) -> Result<Store<Sqlite>, BdkSqlxError> {
        trace!("new store with url");
        crate::SqliteStoreBuilder::new(wallet_name)
            .network(network)
            .migrate(migrate)
            .build_with_url(url.as_deref())
            .await
    }
}

impl crate::SqliteStoreBuilder {
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
    /// use bdk_sqlx::SqliteStoreBuilder;
    ///
    /// let store = SqliteStoreBuilder::new("bdk_wallet_name".to_string())
    ///     .network(Network::Testnet)
    ///     .migrate(true)
    ///     .build_with_url(Some("sqlite://bdk_wallet.sqlite?mode=rwc"))
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
    ///
    /// # Warning
    ///
    /// Do not pass a pool connected to `:memory:` with more than one connection:
    /// each sqlite connection gets its *own* private in-memory database, so a
    /// multi-connection pool silently reads and writes different databases (and
    /// per-connection `PRAGMA`s only apply to the connection that ran them).
    /// Use [`SqliteStoreBuilder::build_with_url`] with `None` instead, which
    /// configures a single-connection pool correctly.
    pub fn pool(mut self, pool: Pool<Sqlite>) -> Self {
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
    ///
    /// The network is process-global and shared across backends: the first
    /// store built (postgres or sqlite) fixes it for the whole process, and
    /// later builds with a different network fail with
    /// [`BdkSqlxError::DuplicateInitNetwork`]. Every store validates stored
    /// and incoming data against it.
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
    pub async fn build(self) -> Result<Store<Sqlite>, BdkSqlxError> {
        let network = self.network.ok_or(BdkSqlxError::MissingNetwork)?;
        match self.pool {
            Some(pool) => Store::new(pool, self.wallet_name, network, self.migrate).await,
            None => Err(BdkSqlxError::MissingPool),
        }
    }

    /// Builds the [`Store`] with a new connection pool created from the provided URL.
    ///
    /// This is a convenience method that creates a connection pool from the URL
    /// and then builds the [`Store`] using that pool. The SQLite DB URL should
    /// look like "sqlite://bdk_wallet.sqlite?mode=rwc". If no URL is given, a
    /// single-connection in-memory database (useful for testing) is created.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Database connection fails
    /// - Any error that could occur in the build() method
    pub async fn build_with_url(self, url: Option<&str>) -> Result<Store<Sqlite>, BdkSqlxError> {
        let pool = if let Some(url) = url {
            SqlitePool::connect(url).await?
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
        self.pool(pool).build().await
    }
}

impl Store<Sqlite> {
    #[tracing::instrument(skip_all)]
    pub(crate) async fn read(&self) -> Result<ChangeSet, BdkSqlxError> {
        trace!("read");
        let mut tx = self.pool.begin().await?;
        let mut changeset = ChangeSet::default();

        // Fetch the network row. It is optional: rows persisted by a changeset
        // that carried no network must still be visible.
        let row = sqlx::query("SELECT name FROM network WHERE wallet_name = $1")
            .bind(&self.wallet_name)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| BdkSqlxError::QueryError {
                table: "read network".to_string(),
                source: e,
            })?;
        if let Some(row) = row {
            let network: String = row.get("name");
            changeset.network = Some(crate::parse_and_validate_network(&network)?);
        }

        // Fetch keychain rows unconditionally: anchoring them on the network
        // row (as the old join did) made descriptors persisted without a
        // network vanish from every subsequent read while sitting in the
        // database.
        let rows = sqlx::query(
            "SELECT keychainkind, descriptor, last_revealed FROM keychain WHERE wallet_name = $1",
        )
        .bind(&self.wallet_name)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| BdkSqlxError::QueryError {
            table: "read keychain".to_string(),
            source: e,
        })?;
        for row in rows {
            let keychainkind: String = row.get("keychainkind");
            let descriptor: String = row.get("descriptor");
            let last_revealed: Option<i32> = row.get("last_revealed");
            crate::keychain_changeset_from_parts(
                &mut changeset,
                &keychainkind,
                &descriptor,
                last_revealed,
            )?;
        }

        changeset.tx_graph = tx_graph_changeset_from_sqlite(&mut tx, &self.wallet_name).await?;
        changeset.local_chain =
            local_chain_changeset_from_sqlite(&mut tx, &self.wallet_name).await?;

        // The reads happened inside one transaction for a consistent snapshot;
        // close it out explicitly instead of relying on drop-rollback.
        tx.commit().await?;

        Ok(changeset)
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
            // Refuse to persist data for a different network than this process
            // was configured for (the same guard the postgres backend
            // applies); overwriting the network row would wedge all subsequent
            // reads with InvalidNetwork.
            crate::validate_network_matches_configured(network)?;
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

    // last_revealed is inserted explicitly as NULL: "no address revealed yet"
    // must be distinguishable from "address index 0 was revealed". The
    // historical DEFAULT 0 conflated the two and made never-revealed wallets
    // skip index 0 on reload. The conflict update keeps the stored
    // last_revealed only when the descriptor itself is unchanged; a different
    // descriptor under the same (wallet_name, keychainkind) must NOT inherit
    // the old derivation index, or the replacement wallet would silently skip
    // those addresses on load.
    sqlx::query(
        "INSERT INTO keychain (wallet_name, keychainkind, descriptor, descriptor_id, last_revealed) VALUES ($1, $2, $3, $4, NULL)
         ON CONFLICT (wallet_name, keychainkind) DO UPDATE SET
             descriptor = excluded.descriptor,
             descriptor_id = excluded.descriptor_id,
             last_revealed = CASE WHEN keychain.descriptor_id = excluded.descriptor_id
                                  THEN keychain.last_revealed ELSE NULL END",
    )
        .bind(wallet_name)
        .bind(keychain)
        .bind(descriptor_str)
        .bind(descriptor_id.as_slice())
        .execute(&mut **tx)
        .await
        .map_err(|e| BdkSqlxError::QueryError {
            table: "insert keychain".to_string(),
            source: e,
        })?;

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
    .await
    .map_err(|e| BdkSqlxError::QueryError {
        table: "insert network".to_string(),
        source: e,
    })?;

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

    // Derivation state must never move backwards: a stale or replayed
    // changeset carrying a smaller index would silently re-reveal already
    // handed-out addresses on the next load.
    let result = sqlx::query::<Sqlite>(
        "UPDATE keychain SET last_revealed = CASE WHEN last_revealed IS NULL OR $1 > last_revealed THEN $1 ELSE last_revealed END
         WHERE wallet_name = $2 AND descriptor_id = $3",
    )
    .bind(crate::checked_conv::<_, i32>(
        last_revealed,
        "keychain.last_revealed",
    )?)
    .bind(wallet_name)
    .bind(descriptor_id.to_byte_array().as_slice())
    .execute(&mut **tx)
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
#[tracing::instrument(skip_all)]
pub(crate) async fn tx_graph_changeset_from_sqlite(
    db_tx: &mut Transaction<'_, Sqlite>,
    wallet_name: &str,
) -> Result<tx_graph::ChangeSet<ConfirmationBlockTime>, BdkSqlxError> {
    trace!("tx graph changeset from sqlite");
    let mut changeset = tx_graph::ChangeSet::default();

    // Fetch transactions
    let rows = sqlx::query("SELECT txid, whole_tx, last_seen FROM tx WHERE wallet_name = $1")
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
    let rows = sqlx::query("SELECT txid, vout, value, script FROM txout WHERE wallet_name = $1")
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
        "SELECT json(anchor) as anchor, txid, block_hash FROM anchor_tx WHERE wallet_name = $1",
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
#[tracing::instrument(skip_all)]
pub(crate) async fn tx_graph_changeset_persist_to_sqlite(
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
        .await
        .map_err(|e| BdkSqlxError::QueryError {
            table: "insert tx".to_string(),
            source: e,
        })?;
    }

    for (&txid, &last_seen) in &changeset.last_seen {
        // Upsert a stub row when the full tx is not stored yet; a bare UPDATE
        // would affect 0 rows and silently drop the timestamp. whole_tx stays
        // NULL until a changeset carrying the full tx fills it in. The
        // conflict update never moves the timestamp backwards: bdk_chain's own
        // Merge only ever increases last_seen, and a stale or replayed
        // changeset must not regress the stored value (the same guarantee
        // update_last_revealed enforces for derivation state).
        sqlx::query(
            "INSERT INTO tx (wallet_name, txid, last_seen) VALUES ($1, $2, $3)
             ON CONFLICT (wallet_name, txid) DO UPDATE SET
                 last_seen = CASE WHEN tx.last_seen IS NULL OR $3 > tx.last_seen
                                  THEN $3 ELSE tx.last_seen END",
        )
        .bind(wallet_name)
        .bind(txid.to_string())
        .bind(crate::checked_conv::<_, i64>(last_seen, "tx.last_seen")?)
        .execute(&mut **db_tx)
        .await
        .map_err(|e| BdkSqlxError::QueryError {
            table: "update tx".to_string(),
            source: e,
        })?;
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
            "INSERT INTO anchor_tx (wallet_name, block_hash, anchor, txid) VALUES ($1, $2, jsonb($3), $4)
             ON CONFLICT (wallet_name, block_hash, txid) DO UPDATE SET anchor = jsonb($3)",
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
#[tracing::instrument(skip_all)]
pub(crate) async fn local_chain_changeset_from_sqlite(
    db_tx: &mut Transaction<'_, Sqlite>,
    wallet_name: &str,
) -> Result<local_chain::ChangeSet, BdkSqlxError> {
    trace!("local chain changeset from sqlite");
    let mut changeset = local_chain::ChangeSet::default();

    let rows = sqlx::query("SELECT hash, height FROM block WHERE wallet_name = $1")
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
#[tracing::instrument(skip_all)]
pub(crate) async fn local_chain_changeset_persist_to_sqlite(
    db_tx: &mut Transaction<'_, Sqlite>,
    wallet_name: &str,
    changeset: &local_chain::ChangeSet,
) -> Result<(), BdkSqlxError> {
    trace!("local chain changeset to sqlite");
    if changeset.blocks.is_empty() {
        return Ok(());
    }
    // The block table keys rows by (wallet_name, hash), so a changeset mapping
    // one hash to several heights cannot be represented: persisting it would
    // silently collapse to a single row and lose checkpoints. Reject it loudly
    // instead. Real chains never produce such changesets.
    let mut seen = std::collections::HashMap::new();
    for (&height, &hash) in &changeset.blocks {
        if let Some(hash) = hash {
            if let Some(&first_height) = seen.get(&hash) {
                return Err(BdkSqlxError::DuplicateBlockHash {
                    hash,
                    first_height,
                    second_height: height,
                });
            }
            seen.insert(hash, height);
        }
    }
    // Concurrent writers persisting different hashes at the same height need
    // no explicit serialization here (unlike postgres, which takes an advisory
    // lock): sqlite admits only one writer at a time, so the second writer's
    // DELETE blocks on the database write lock until the first commits, then
    // sees and replaces its row -- last-writer-wins, as if the writes had been
    // issued sequentially.
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
                .await
                .map_err(|e| BdkSqlxError::QueryError {
                    table: "delete stale block".to_string(),
                    source: e,
                })?;
                sqlx::query(
                    "INSERT INTO block (wallet_name, hash, height) VALUES ($1, $2, $3)
                     ON CONFLICT (wallet_name, hash) DO UPDATE SET height = $3",
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
                sqlx::query("DELETE FROM block WHERE wallet_name = $1 AND height = $2")
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
