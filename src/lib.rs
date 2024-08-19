//! bdk-sqlx
use bdk_wallet::bitcoin::consensus::Decodable;
use std::str::FromStr;
use bitcoin::Network;
use bdk_wallet::descriptor::ExtendedDescriptor;
use bdk_wallet::bitcoin::secp256k1::Secp256k1;
use bdk_wallet::{bitcoin, ChangeSet};
use bdk_wallet::chain::{Anchor, DescriptorExt, DescriptorId, keychain_txout, local_chain, tx_graph};
use std::sync::Arc;

use std::future::Future;
use std::pin::Pin;

use bdk_wallet::chain::{Merge};
use bdk_wallet::{AsyncWalletPersister};
use sqlx::{PgPool, Postgres, Row, Transaction};
use sqlx::postgres::PgPoolOptions;
use sqlx::FromRow;

type FutureResult<'a, T, E> = Pin<Box<dyn Future<Output = Result<T, E>> + Send + 'a>>;

/// Represents a row in the wallet table.
#[derive(Debug, sqlx::FromRow)]
struct WalletRow {
    network: String,
    descriptor: String,
    last_revealed: i32,
}

/// Store.
#[derive(Debug)]
pub struct Store {
    pool: PgPool,
}

/// Error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("sqlx error: {0}")]
    Sqlx(#[from] sqlx::Error),
}

impl Store {
    /// Construct a new [`Store`].
    pub async fn new(url: &str) -> Result<Self, Error> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(url)
            .await?;

        Ok(Self { pool })
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

impl Store {
    /// Does schema migration and loads backend.
    async fn migrate_and_read(&self) -> Result<ChangeSet, Error> {
        let pool = &self.pool;
        migrate(pool).await?;

        // sqlx::migrate!("db/migrations").run(pool).await.unwrap();
        let mut changeset = ChangeSet::default();

        let row = match sqlx::query("SELECT network, descriptor, last_revealed FROM wallet LIMIT 1")
            .fetch_optional(pool)
            .await?
        {
            None => return Ok(changeset),
            Some(row) => row,
        };

        let WalletRow {
            network,
            descriptor,
            last_revealed,
        } = <WalletRow as FromRow<_>>::from_row(&row)?;

        let (descriptor, _) =
            <ExtendedDescriptor>::parse_descriptor(&Secp256k1::new(), &descriptor).unwrap();
        let did = descriptor.descriptor_id();
        changeset.descriptor = Some(descriptor);
        let network = Network::from_str(&network).expect("must parse");
        changeset.network = Some(network);
        changeset.indexer = keychain_txout::ChangeSet {
            last_revealed: [(did, last_revealed as u32)].into(),
        };

        let mut tx = pool.try_begin().await?.unwrap();


        changeset.tx_graph = tx_graph_changeset_from_postgres(&mut tx).await?;
        changeset.local_chain = local_chain_changeset_from_postgres(&mut tx).await?;
        changeset.indexer = keychain_txout_changeset_from_postgres(&mut tx).await?;

        tx.commit().await?;

        //
        // // not implemented: tables for local_chain and tx_graph
        // let genesis_hash = constants::genesis_block(network).block_hash();
        // changeset.local_chain = local_chain::ChangeSet {
        //     blocks: BTreeMap::from([(0, Some(genesis_hash))]),
        // };
        // changeset.tx_graph = tx_graph::ChangeSet::default();

        Ok(changeset)
    }

    /// Inserts data into tables.
    async fn write(&self, changeset: &ChangeSet) -> Result<(), Error> {
        if changeset.is_empty() {
            return Ok(());
        }

        let pool = &self.pool;
        let mut tx = pool.try_begin().await?.unwrap();

        if let Some(ref descriptor) = changeset.descriptor {
            insert_descriptor(pool, descriptor).await?;
        }
        if let Some(network) = changeset.network {
            insert_network(pool, network).await?;
        }
        if let Some(last_revealed) = changeset.indexer.last_revealed.values().next() {
            insert_last_revealed(pool, *last_revealed).await?;
        }

        tx_graph_changeset_persist_to_postgres(&mut tx, &changeset.tx_graph).await?;
        local_chain_changeset_persist_to_postgres(&mut tx, &changeset.local_chain).await?;
        keychain_txout_changeset_persist_to_postgres(&mut tx, &changeset.indexer).await?;

        tx.commit().await?;

        Ok(())

    }
}

async fn insert_descriptor(pool: &PgPool, descriptor: &ExtendedDescriptor) -> Result<(), Error> {
    Ok(sqlx::query("INSERT INTO wallet(descriptor) VALUES($1)")
        .bind(descriptor.to_string())
        .execute(pool)
        .await
        .map(|_| ())?)
}

async fn insert_network(pool: &PgPool, network: Network) -> Result<(), Error> {
    Ok(sqlx::query("UPDATE wallet SET network = $1")
        .bind(network.to_string())
        .execute(pool)
        .await
        .map(|_| ())?)
}

async fn insert_last_revealed(pool: &PgPool, last_revealed: u32) -> Result<(), Error> {
    Ok(sqlx::query("UPDATE wallet SET last_revealed = $1")
        .bind(last_revealed as i32)
        .execute(pool)
        .await
        .map(|_| ())?)
}

async fn migrate(pool: &PgPool) -> Result<(), Error> {
    let stmt = r#"
CREATE TABLE IF NOT EXISTS wallet(
    id SERIAL,
    network VARCHAR(8),
    descriptor VARCHAR(1024),
    last_revealed INTEGER
);
"#;

    let _ = sqlx::query(stmt).execute(pool).await?;

    Ok(())
}

pub async fn tx_graph_changeset_from_postgres<A>(
    db_tx: &mut Transaction<'_, Postgres>,
) -> sqlx::Result<tx_graph::ChangeSet<A>>
where
    A: Anchor + Clone + Ord + serde::Serialize + serde::de::DeserializeOwned,
{
    let mut changeset = tx_graph::ChangeSet::default();

    // Fetch transactions
    let rows = sqlx::query("SELECT txid, raw_tx, last_seen FROM bdk_txs")
        .fetch_all(&mut **db_tx)
        .await?;

    for row in rows {
        let txid: String = row.get("txid");
        let txid = bitcoin::Txid::from_str(&txid).expect("Invalid txid");
        let raw_tx: Option<Vec<u8>> = row.get("raw_tx");
        let last_seen: Option<i64> = row.get("last_seen");

        if let Some(tx_bytes) = raw_tx {
            if let Ok(tx) = bitcoin::Transaction::consensus_decode(&mut tx_bytes.as_slice()) {
                changeset.txs.insert(Arc::new(tx));
            }
        }
        if let Some(last_seen) = last_seen {
            changeset.last_seen.insert(txid, last_seen as u64);
        }
    }

    // Fetch txouts
    let rows = sqlx::query("SELECT txid, vout, value, script FROM bdk_txouts")
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
    let rows = sqlx::query("SELECT anchor, txid FROM bdk_anchors")
        .fetch_all(&mut **db_tx)
        .await?;

    for row in rows {
        let anchor: serde_json::Value = row.get("anchor");
        let txid: String = row.get("txid");
        let txid = bitcoin::Txid::from_str(&txid).expect("Invalid txid");

        if let Ok(anchor) = serde_json::from_value::<A>(anchor) {
            changeset.anchors.insert((anchor, txid));
        }
    }

    Ok(changeset)
}

pub async fn tx_graph_changeset_persist_to_postgres<A>(
    db_tx: &mut Transaction<'_, Postgres>,
    changeset: &tx_graph::ChangeSet<A>,
) -> sqlx::Result<()>
where
    A: Anchor + Clone + Ord + serde::Serialize + serde::de::DeserializeOwned,
{
    for tx in &changeset.txs {
        sqlx::query(
            "INSERT INTO bdk_txs (txid, raw_tx) VALUES ($1, $2)
             ON CONFLICT (txid) DO UPDATE SET raw_tx = $2",
        )
            .bind(tx.compute_txid().to_string())
            .bind(bitcoin::consensus::serialize(tx.as_ref()))
            .execute(&mut **db_tx)
            .await?;
    }

    for (&txid, &last_seen) in &changeset.last_seen {
        sqlx::query(
            "INSERT INTO bdk_txs (txid, last_seen) VALUES ($1, $2)
             ON CONFLICT (txid) DO UPDATE SET last_seen = $2",
        )
            .bind(txid.to_string())
            .bind(last_seen as i64)
            .execute(&mut **db_tx)
            .await?;
    }

    for (op, txo) in &changeset.txouts {
        sqlx::query(
            "INSERT INTO bdk_txouts (txid, vout, value, script) VALUES ($1, $2, $3, $4)
             ON CONFLICT (txid, vout) DO UPDATE SET value = $3, script = $4",
        )
            .bind(op.txid.to_string())
            .bind(op.vout as i32)
            .bind(txo.value.to_sat() as i64)
            .bind(txo.script_pubkey.as_bytes())
            .execute(&mut **db_tx)
            .await?;
    }

    for (anchor, txid) in &changeset.anchors {
        let anchor_block = anchor.anchor_block();
        sqlx::query(
            "INSERT INTO bdk_anchors (txid, block_height, block_hash, anchor) VALUES ($1, $2, $3, $4)
             ON CONFLICT (txid, block_height, block_hash) DO UPDATE SET anchor = $4",
        )
            .bind(txid.to_string())
            .bind(anchor_block.height as i32)
            .bind(anchor_block.hash.to_string())
            .bind(serde_json::to_value(anchor).unwrap())
            .execute(&mut **db_tx)
            .await?;
    }

    Ok(())
}

// local_chain::ChangeSet functions

pub async fn local_chain_changeset_from_postgres(
    db_tx: &mut Transaction<'_, Postgres>,
) -> sqlx::Result<local_chain::ChangeSet> {
    let mut changeset = local_chain::ChangeSet::default();

    let rows = sqlx::query("SELECT block_height, block_hash FROM bdk_blocks")
        .fetch_all(&mut **db_tx)
        .await?;

    for row in rows {
        let height: i32 = row.get("block_height");
        let hash: String = row.get("block_hash");
        if let Ok(block_hash) = bitcoin::BlockHash::from_str(&hash) {
            changeset.blocks.insert(height as u32, Some(block_hash));
        }
    }

    Ok(changeset)
}

pub async fn local_chain_changeset_persist_to_postgres(
    db_tx: &mut Transaction<'_, Postgres>,
    changeset: &local_chain::ChangeSet,
) -> sqlx::Result<()> {
    for (&height, &hash) in &changeset.blocks {
        match hash {
            Some(hash) => {
                sqlx::query(
                    "INSERT INTO bdk_blocks (block_height, block_hash) VALUES ($1, $2)
                     ON CONFLICT (block_height) DO UPDATE SET block_hash = $2",
                )
                    .bind(height as i32)
                    .bind(hash.to_string())
                    .execute(&mut **db_tx)
                    .await?;
            }
            None => {
                sqlx::query("DELETE FROM bdk_blocks WHERE block_height = $1")
                    .bind(height as i32)
                    .execute(&mut **db_tx)
                    .await?;
            }
        }
    }

    Ok(())
}

// keychain_txout::ChangeSet functions

pub async fn keychain_txout_changeset_from_postgres(
    db_tx: &mut Transaction<'_, Postgres>,
) -> sqlx::Result<keychain_txout::ChangeSet> {
    let mut changeset = keychain_txout::ChangeSet::default();

    let rows = sqlx::query("SELECT descriptor_id, last_revealed FROM bdk_descriptor_last_revealed")
        .fetch_all(&mut **db_tx)
        .await?;

    for row in rows {
        let descriptor_id: String = row.get("descriptor_id");
        let last_revealed: i64 = row.get("last_revealed");

        if let Ok(descriptor_id) = DescriptorId::from_str(&descriptor_id) {
            changeset
                .last_revealed
                .insert(descriptor_id, last_revealed as u32);
        }
    }

    Ok(changeset)
}

pub async fn keychain_txout_changeset_persist_to_postgres(
    db_tx: &mut Transaction<'_, Postgres>,
    changeset: &keychain_txout::ChangeSet,
) -> sqlx::Result<()> {
    for (&descriptor_id, &last_revealed) in &changeset.last_revealed {
        sqlx::query(
            "INSERT INTO bdk_descriptor_last_revealed (descriptor_id, last_revealed) VALUES ($1, $2)
             ON CONFLICT (descriptor_id) DO UPDATE SET last_revealed = $2",
        )
            .bind(descriptor_id.to_string())
            .bind(last_revealed as i64)
            .execute(&mut **db_tx)
            .await?;
    }

    Ok(())
}