// #![allow(unused)]
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;

use bdk_wallet::bitcoin::{constants, key::Secp256k1, Network};
use bdk_wallet::chain::{keychain_txout, local_chain, tx_graph, DescriptorExt, Merge};
use bdk_wallet::descriptor::ExtendedDescriptor;
use bdk_wallet::{AsyncWalletPersister, ChangeSet};
use sqlx::sqlite::SqliteConnectOptions;
use sqlx::ConnectOptions;

type Error = anyhow::Error;

type Result<T, E = Error> = core::result::Result<T, E>;

type FutureResult<'a, T, E> = Pin<Box<dyn Future<Output = Result<T, E>> + Send + 'a>>;

type Conn = sqlx::SqliteConnection;

#[derive(Debug, sqlx::FromRow)]
struct WalletRow {
    descriptor: String,
    network: String,
    last_revealed: u32,
}

#[derive(Debug)]
pub struct Store {
    conn: sqlx::SqliteConnection,
}

impl Store {
    pub async fn new() -> Result<Self> {
        let db_path = std::env::var("DB_PATH")?;
        let _db_file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .open(&db_path)?;
        let conn = SqliteConnectOptions::from_str(&format!("sqlite://{db_path}"))?
            .connect()
            .await?;

        Ok(Self { conn })
    }
}

impl AsyncWalletPersister for Store {
    type Error = Error;

    fn initialize(&mut self) -> FutureResult<ChangeSet, Self::Error> {
        Box::pin(migrate_and_read(&mut self.conn))
    }

    fn persist<'a>(&'a mut self, changeset: &'a ChangeSet) -> FutureResult<'a, (), Self::Error> {
        Box::pin(write(&mut self.conn, changeset))
    }
}

async fn migrate_and_read(conn: &mut Conn) -> Result<ChangeSet> {
    migrate(conn).await?;
    let mut changeset = ChangeSet::default();

    let row = sqlx::query("select descriptor, network, last_revealed from wallet limit 1")
        .fetch_optional(conn)
        .await?;

    if row.is_none() {
        return Ok(changeset);
    }

    let WalletRow {
        descriptor,
        network,
        last_revealed,
    } = <WalletRow as sqlx::FromRow<_>>::from_row(&row.unwrap())?;

    let (descriptor, _) =
        <ExtendedDescriptor>::parse_descriptor(&Secp256k1::new(), &descriptor).unwrap();
    let did = descriptor.descriptor_id();
    changeset.descriptor = Some(descriptor);
    let network = Network::from_str(&network)?;
    changeset.network = Some(network);
    changeset.indexer = keychain_txout::ChangeSet {
        last_revealed: [(did, last_revealed)].into(),
    };

    // TODO: not implemented
    let genesis_hash = constants::genesis_block(network).block_hash();
    changeset.local_chain = local_chain::ChangeSet {
        blocks: BTreeMap::from([(0, Some(genesis_hash))]),
    };
    changeset.tx_graph = tx_graph::ChangeSet::default();

    Ok(changeset)
}

async fn write(conn: &mut Conn, changeset: &ChangeSet) -> Result<()> {
    if changeset.is_empty() {
        return Ok(());
    }
    if let Some(ref descriptor) = changeset.descriptor {
        insert_descriptor(conn, descriptor).await?;
    }
    if let Some(network) = changeset.network {
        insert_network(conn, network).await?;
    }
    if let Some(last_revealed) = changeset.indexer.last_revealed.values().next() {
        insert_last_revealed(conn, *last_revealed).await?;
    }

    Ok(())
}

async fn insert_descriptor(conn: &mut Conn, descriptor: &ExtendedDescriptor) -> Result<()> {
    _ = sqlx::query("insert into wallet(id, descriptor) values(1, $1)")
        .bind(descriptor.to_string())
        .execute(conn)
        .await?;
    Ok(())
}

async fn insert_network(conn: &mut Conn, network: Network) -> Result<()> {
    _ = sqlx::query("update wallet set network = $1 where id = 1")
        .bind(network.to_string())
        .execute(conn)
        .await?;
    Ok(())
}

async fn insert_last_revealed(conn: &mut Conn, last_revealed: u32) -> Result<()> {
    _ = sqlx::query("update wallet set last_revealed = $1 where id = 1")
        .bind(last_revealed)
        .execute(conn)
        .await?;
    Ok(())
}

async fn migrate(conn: &mut Conn) -> Result<()> {
    let stmt = r#"
CREATE TABLE IF NOT EXISTS wallet(
    id INTEGER PRIMARY KEY NOT NULL,
    network TEXT,
    descriptor TEXT,
    last_revealed INTEGER
);
"#;
    _ = sqlx::query(stmt).execute(conn).await?;

    Ok(())
}
