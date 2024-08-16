//! bdk-sqlx

// #![allow(unused)]

use std::collections::BTreeMap;
use std::env;
use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;

use bdk_wallet::bitcoin::{constants, key::Secp256k1, Network};
use bdk_wallet::chain::{keychain_txout, local_chain, tx_graph, DescriptorExt, Merge};
use bdk_wallet::descriptor::ExtendedDescriptor;
use bdk_wallet::{AsyncWalletPersister, ChangeSet};
use sqlx::postgres::{PgPool, PgPoolOptions};
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
    pub async fn new() -> Result<Self, Error> {
        let url = env::var("DATABASE_URL").expect("must set DATABASE_URL");
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(&url)
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

        // not implemented: tables for local_chain and tx_graph
        let genesis_hash = constants::genesis_block(network).block_hash();
        changeset.local_chain = local_chain::ChangeSet {
            blocks: BTreeMap::from([(0, Some(genesis_hash))]),
        };
        changeset.tx_graph = tx_graph::ChangeSet::default();

        Ok(changeset)
    }

    /// Inserts data into tables.
    async fn write(&self, changeset: &ChangeSet) -> Result<(), Error> {
        if changeset.is_empty() {
            return Ok(());
        }

        let pool = &self.pool;

        if let Some(ref descriptor) = changeset.descriptor {
            insert_descriptor(pool, descriptor).await?;
        }
        if let Some(network) = changeset.network {
            insert_network(pool, network).await?;
        }
        if let Some(last_revealed) = changeset.indexer.last_revealed.values().next() {
            insert_last_revealed(pool, *last_revealed).await?;
        }

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
