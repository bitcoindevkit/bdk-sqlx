//! bdk-sqlx postgres store

#![warn(missing_docs)]

// Standard library imports
use std::{str::FromStr, sync::Arc};
// Third party crates
use bdk_chain::{
    local_chain, tx_graph, Anchor, ConfirmationBlockTime, DescriptorExt, DescriptorId, Merge,
};
use bdk_wallet::{
    bitcoin::{
        self, consensus, hashes::Hash, Amount, BlockHash, Network, OutPoint, ScriptBuf, TxOut, Txid,
    },
    chain as bdk_chain,
    descriptor::ExtendedDescriptor,
    AsyncWalletPersister, ChangeSet, KeychainKind,
    KeychainKind::{External, Internal},
};
use sqlx::{
    postgres::{PgPool, Postgres},
    sqlx_macros::migrate,
    Pool, Row, Transaction,
};
use tracing::trace;

// First party imports
use super::{BdkSqlxError, FutureResult, PgStoreBuilder, Store};

type Result<T> = core::result::Result<T, BdkSqlxError>;

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

                crate::initialize_network(network)?;

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
    /// # Security
    ///
    /// Without an explicit `sslmode`, postgres connections default to `prefer`, which
    /// silently falls back to plaintext if TLS negotiation fails. For any deployment
    /// where the database is not on the same host, require TLS in the URL (e.g.
    /// `?sslmode=require`, or `verify-full` to also authenticate the server), and
    /// connect with a least-privilege database role.
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
        // READ COMMITTED (the default) snapshots per statement, so a concurrent
        // writer committing between the SELECTs below could produce a
        // mixed-generation changeset. REPEATABLE READ gives one snapshot for
        // the whole read.
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(&mut *db_tx)
            .await
            .map_err(|e| BdkSqlxError::QueryError {
                table: "read".to_string(),
                source: e,
            })?;
        let mut changeset = ChangeSet::default();

        // Fetch the network row. It is optional: rows persisted by a changeset
        // that carried no network must still be visible.
        let row = sqlx::query(r#"SELECT name FROM "bdk_wallet"."network" WHERE wallet_name = $1"#)
            .bind(&self.wallet_name)
            .fetch_optional(&mut *db_tx)
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
            r#"SELECT keychainkind, descriptor, last_revealed FROM "bdk_wallet"."keychain" WHERE wallet_name = $1"#,
        )
        .bind(&self.wallet_name)
        .fetch_all(&mut *db_tx)
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

        changeset.tx_graph =
            tx_graph_changeset_from_postgres(&mut db_tx, &self.wallet_name).await?;
        changeset.local_chain =
            local_chain_changeset_from_postgres(&mut db_tx, &self.wallet_name).await?;

        // The reads happened inside one transaction for a consistent snapshot;
        // close it out explicitly instead of relying on drop-rollback.
        db_tx.commit().await?;

        Ok(changeset)
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
            // Refuse to persist data for a different network than this process
            // was configured for; overwriting the network row would wedge all
            // subsequent reads with InvalidNetwork.
            crate::validate_network_matches_configured(network)?;
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

    // last_revealed is inserted explicitly as NULL: "no address revealed yet"
    // must be distinguishable from "address index 0 was revealed". The
    // historical DEFAULT 0 conflated the two and made never-revealed wallets
    // skip index 0 on reload. The conflict update keeps the stored
    // last_revealed only when the descriptor itself is unchanged; a different
    // descriptor under the same (wallet_name, keychainkind) must NOT inherit
    // the old derivation index, or the replacement wallet would silently skip
    // those addresses on load.
    sqlx::query(
        r#"INSERT INTO "bdk_wallet"."keychain" (wallet_name, keychainkind, descriptor, descriptor_id, last_revealed) VALUES ($1, $2, $3, $4, NULL)
         ON CONFLICT (wallet_name, keychainkind) DO UPDATE SET
             descriptor = excluded.descriptor,
             descriptor_id = excluded.descriptor_id,
             last_revealed = CASE WHEN keychain.descriptor_id = excluded.descriptor_id
                                  THEN keychain.last_revealed ELSE NULL END"#,
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

    // Derivation state must never move backwards: a stale or replayed
    // changeset carrying a smaller index would silently re-reveal already
    // handed-out addresses on the next load.
    let result = sqlx::query(
        r#"UPDATE "bdk_wallet"."keychain" SET last_revealed = CASE WHEN last_revealed IS NULL OR $1 > last_revealed THEN $1 ELSE last_revealed END
         WHERE wallet_name = $2 AND descriptor_id = $3"#,
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
        // Upsert a stub row when the full tx is not stored yet; a bare UPDATE
        // would affect 0 rows and silently drop the timestamp. whole_tx stays
        // NULL until a changeset carrying the full tx fills it in.
        sqlx::query(
            r#"INSERT INTO "bdk_wallet"."tx" (wallet_name, txid, last_seen) VALUES ($1, $2, $3)
             ON CONFLICT (wallet_name, txid) DO UPDATE SET last_seen = $3"#,
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
    for (&height, &hash) in &changeset.blocks {
        match hash {
            Some(hash) => {
                // A reorg can replace the block at this height with a different hash;
                // remove the stale row first (its anchors cascade away) so exactly one
                // row per (wallet_name, height) remains.
                sqlx::query(
                    r#"DELETE FROM "bdk_wallet"."block" WHERE wallet_name = $1 AND height = $2 AND hash != $3"#,
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
