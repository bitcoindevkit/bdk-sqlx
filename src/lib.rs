// #![allow(unused)]
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;

use anyhow::Context;
use bdk_wallet::bitcoin::{constants, key::Secp256k1, Network};
use bdk_wallet::chain::{keychain_txout, local_chain, tx_graph, DescriptorExt, Merge};
use bdk_wallet::descriptor::ExtendedDescriptor;
use bdk_wallet::{AsyncWalletPersister, ChangeSet};
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::FromRow;

type Error = anyhow::Error;

type Result<T, E = Error> = core::result::Result<T, E>;

type FutureResult<'a, T, E> = Pin<Box<dyn Future<Output = Result<T, E>> + Send + 'a>>;

#[derive(Debug, sqlx::FromRow)]
struct WalletRow {
    network: String,
    descriptor: String,
    last_revealed: i32,
}

#[derive(Debug)]
pub struct Store {
    pool: PgPool,
}

impl Store {
    pub async fn new() -> Result<Self> {
        let url = std::env::var("DATABASE_URL").context("must set DATABASE_URL")?;
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(&url)
            .await?;

        Ok(Self { pool })
    }
}

impl AsyncWalletPersister for Store {
    type Error = Error;

    fn initialize<'a>(&'a mut self) -> FutureResult<'a, ChangeSet, Self::Error>
    where
        Self: 'a,
    {
        Box::pin(migrate_and_read(&mut self.pool))
    }

    fn persist<'a>(&'a mut self, changeset: &'a ChangeSet) -> FutureResult<'a, (), Self::Error>
    where
        Self: 'a,
    {
        Box::pin(write(&mut self.pool, changeset))
    }
}

async fn migrate_and_read(pool: &PgPool) -> Result<ChangeSet> {
    migrate(pool).await?;
    let mut changeset = ChangeSet::default();

    let row = match sqlx::query("select network, descriptor, last_revealed from wallet limit 1")
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
    let network = Network::from_str(&network)?;
    changeset.network = Some(network);
    changeset.indexer = keychain_txout::ChangeSet {
        last_revealed: [(did, last_revealed as u32)].into(),
    };

    // No tables implemented for chain/graph
    let genesis_hash = constants::genesis_block(network).block_hash();
    changeset.local_chain = local_chain::ChangeSet {
        blocks: BTreeMap::from([(0, Some(genesis_hash))]),
    };
    changeset.tx_graph = tx_graph::ChangeSet::default();

    Ok(changeset)
}

async fn write(pool: &PgPool, changeset: &ChangeSet) -> Result<()> {
    if changeset.is_empty() {
        return Ok(());
    }
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

async fn insert_descriptor(pool: &PgPool, descriptor: &ExtendedDescriptor) -> Result<()> {
    Ok(sqlx::query("INSERT INTO wallet(descriptor) VALUES($1)")
        .bind(descriptor.to_string())
        .execute(pool)
        .await
        .map(|_| ())?)
}

async fn insert_network(pool: &PgPool, network: Network) -> Result<()> {
    Ok(sqlx::query("UPDATE wallet SET network = $1")
        .bind(network.to_string())
        .execute(pool)
        .await
        .map(|_| ())?)
}

async fn insert_last_revealed(pool: &PgPool, last_revealed: u32) -> Result<()> {
    Ok(sqlx::query("UPDATE wallet SET last_revealed = $1")
        .bind(last_revealed as i32)
        .execute(pool)
        .await
        .map(|_| ())?)
}

async fn migrate(pool: &PgPool) -> Result<()> {
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
