use std::env;
use std::ops::Add;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Once, OnceLock};

use assert_matches::assert_matches;
use bdk_chain::{BlockId, ConfirmationBlockTime, DescriptorExt, DescriptorId, Merge};
use bdk_wallet::{
    bitcoin, chain as bdk_chain,
    descriptor::ExtendedDescriptor,
    miniscript::{Descriptor, DescriptorPublicKey},
    test_utils, wallet_name_from_descriptor, AsyncWalletPersister, Balance, ChangeSet,
    KeychainKind::*,
    LoadError, LoadMismatch, LoadWithPersistError, Wallet,
};
use bitcoin::{
    constants::ChainHash,
    hashes::Hash,
    secp256k1::Secp256k1,
    Address, Amount, BlockHash,
    Network::{self, Regtest},
    OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid,
};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{Pool, Postgres, Sqlite};
use test_utils::{
    get_test_tr_single_sig_xprv_and_change_desc, get_test_wpkh, insert_anchor, insert_checkpoint,
    insert_tx, new_tx,
};
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

use crate::{BdkSqlxError, FutureResult, PgStoreBuilder, Store};

pub fn get_test_minisicript_with_change_desc() -> (&'static str, &'static str) {
    ("wsh(andor(multi(2,[a0d3c79c/48'/1'/79'/2']tpubDEsGdqFaKUVnVNZZw8AixJ8C3yD8o6nN7hsdLfbtVRDTk3PNrQ2pcWNWNbxhdcNSgQP25pUpgRQ7qiVtN3YvSzACKizrvzSwH9SQ2Bjbbwt/0/*,[ea2484f9/48'/1'/79'/2']tpubDFjkswBXoRHKkvmHsxv4xdDqbjg1peX9zJytLeSLbXuwVgYhXgbABzC2r5MAWxqWoaUr7hWGW5TPjA9sNvxa3mX6DrNBdynDsEvwDoXGFpm/0/*,[93f245d7/48'/1'/79'/2']tpubDEVnR72gRgTsqaPFMacV6fCfaSEe56gcDomuGhk9MFeUdEi18riJCokgsZr2x1KKGRM59TJ4AQ6FuNun3khh95ceoH2ytN13nVD7yDLP5LJ/0/*),or_i(and_v(v:pkh([61cdf766/48'/1'/79'/2']tpubDEXETCw2WurhazfW5gW1z4njP6yLXDQmCGfjWGP5k3BuTQ5iZqovMr1zz1zWPhDMRn11hXGpZHodus1LysXnwREsD1ig96M24JhQCpPPpf6/0/*),after(1753228800)),thresh(2,pk([39bf48a9/48'/1'/0'/2']tpubDEr9rVFQbT1keErwxb6GuGy3RM6TEACSkFxBgziUvrDprYuM1Wm7wi6jb1gcaLrSgk6MSkGx84dS2kQQwJKxGRJ59rAvmuKTU7E3saHJLf5/0/*),s:pk([9467fdb3/48'/1'/0'/2']tpubDFEjX5BY88AbWpshPwGscwgKLtcCjeVodMbmhS6D6cbz1eGNUs3546ephbVmbHpxEhbCDrezGmFBArLxBKzPEfBcBdzQuncPm8ww2xa6UUQ/0/*),s:pk([01adf45e/48'/1'/0'/2']tpubDFPYZPeShApyWndvDUtpLSjDHGYK4tTT4BkMyTukGqbP9AXQeQhiWsbwEzyZhxgud9ZPew1FPsoLbWjfnE3veSXLeU4ViofrhVAHNXtjQWE/0/*),snl:after(1739836800))),and_v(v:thresh(2,pkh([39bf48a9/48'/1'/0'/2']tpubDEr9rVFQbT1keErwxb6GuGy3RM6TEACSkFxBgziUvrDprYuM1Wm7wi6jb1gcaLrSgk6MSkGx84dS2kQQwJKxGRJ59rAvmuKTU7E3saHJLf5/2/*),a:pkh([9467fdb3/48'/1'/0'/2']tpubDFEjX5BY88AbWpshPwGscwgKLtcCjeVodMbmhS6D6cbz1eGNUs3546ephbVmbHpxEhbCDrezGmFBArLxBKzPEfBcBdzQuncPm8ww2xa6UUQ/2/*),a:pkh([01adf45e/48'/1'/0'/2']tpubDFPYZPeShApyWndvDUtpLSjDHGYK4tTT4BkMyTukGqbP9AXQeQhiWsbwEzyZhxgud9ZPew1FPsoLbWjfnE3veSXLeU4ViofrhVAHNXtjQWE/2/*)),after(1757116800))))",
     "wsh(andor(multi(2,[a0d3c79c/48'/1'/79'/2']tpubDEsGdqFaKUVnVNZZw8AixJ8C3yD8o6nN7hsdLfbtVRDTk3PNrQ2pcWNWNbxhdcNSgQP25pUpgRQ7qiVtN3YvSzACKizrvzSwH9SQ2Bjbbwt/1/*,[ea2484f9/48'/1'/79'/2']tpubDFjkswBXoRHKkvmHsxv4xdDqbjg1peX9zJytLeSLbXuwVgYhXgbABzC2r5MAWxqWoaUr7hWGW5TPjA9sNvxa3mX6DrNBdynDsEvwDoXGFpm/1/*,[93f245d7/48'/1'/79'/2']tpubDEVnR72gRgTsqaPFMacV6fCfaSEe56gcDomuGhk9MFeUdEi18riJCokgsZr2x1KKGRM59TJ4AQ6FuNun3khh95ceoH2ytN13nVD7yDLP5LJ/1/*),or_i(and_v(v:pkh([61cdf766/48'/1'/79'/2']tpubDEXETCw2WurhazfW5gW1z4njP6yLXDQmCGfjWGP5k3BuTQ5iZqovMr1zz1zWPhDMRn11hXGpZHodus1LysXnwREsD1ig96M24JhQCpPPpf6/1/*),after(1753228800)),thresh(2,pk([39bf48a9/48'/1'/0'/2']tpubDEr9rVFQbT1keErwxb6GuGy3RM6TEACSkFxBgziUvrDprYuM1Wm7wi6jb1gcaLrSgk6MSkGx84dS2kQQwJKxGRJ59rAvmuKTU7E3saHJLf5/1/*),s:pk([9467fdb3/48'/1'/0'/2']tpubDFEjX5BY88AbWpshPwGscwgKLtcCjeVodMbmhS6D6cbz1eGNUs3546ephbVmbHpxEhbCDrezGmFBArLxBKzPEfBcBdzQuncPm8ww2xa6UUQ/1/*),s:pk([01adf45e/48'/1'/0'/2']tpubDFPYZPeShApyWndvDUtpLSjDHGYK4tTT4BkMyTukGqbP9AXQeQhiWsbwEzyZhxgud9ZPew1FPsoLbWjfnE3veSXLeU4ViofrhVAHNXtjQWE/1/*),snl:after(1739836800))),and_v(v:thresh(2,pkh([39bf48a9/48'/1'/0'/2']tpubDEr9rVFQbT1keErwxb6GuGy3RM6TEACSkFxBgziUvrDprYuM1Wm7wi6jb1gcaLrSgk6MSkGx84dS2kQQwJKxGRJ59rAvmuKTU7E3saHJLf5/3/*),a:pkh([9467fdb3/48'/1'/0'/2']tpubDFEjX5BY88AbWpshPwGscwgKLtcCjeVodMbmhS6D6cbz1eGNUs3546ephbVmbHpxEhbCDrezGmFBArLxBKzPEfBcBdzQuncPm8ww2xa6UUQ/3/*),a:pkh([01adf45e/48'/1'/0'/2']tpubDFPYZPeShApyWndvDUtpLSjDHGYK4tTT4BkMyTukGqbP9AXQeQhiWsbwEzyZhxgud9ZPew1FPsoLbWjfnE3veSXLeU4ViofrhVAHNXtjQWE/3/*)),after(1757116800))))")
}

const NETWORK: Network = Regtest;

fn parse_descriptor(s: &str) -> ExtendedDescriptor {
    <Descriptor<DescriptorPublicKey>>::parse_descriptor(&Secp256k1::new(), s)
        .unwrap()
        .0
}

static INIT: Once = Once::new();

type SharedLogBuffer = Arc<Mutex<Vec<u8>>>;
static LOG_BUFFER: OnceLock<SharedLogBuffer> = OnceLock::new();

/// Buffer that captures every trace event emitted in this test process.
fn log_buffer() -> SharedLogBuffer {
    LOG_BUFFER.get().expect("initialize() first").clone()
}

// This must only be called once.
fn initialize() {
    INIT.call_once(|| {
        let buf: SharedLogBuffer = Arc::new(Mutex::new(Vec::new()));
        let writer_buf = buf.clone();
        LOG_BUFFER.set(buf).expect("log buffer set once");
        tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer().with_filter(EnvFilter::new(
                env::var("RUST_LOG").unwrap_or_else(|_| "sqlx=warn,bdk_sqlx=warn".into()),
            )))
            // A permanent global capture layer for the descriptor-leak test. A
            // scoped subscriber (`with_subscriber`) must NOT be used here: sqlx's
            // sqlite worker threads hold span references, and tearing the scoped
            // registry down while those threads are alive panics the worker and
            // wedges the pool. Each layer carries its own filter: a bare EnvFilter
            // layer would disable trace events globally for every layer.
            .with(
                tracing_subscriber::fmt::layer()
                    .with_writer(move || SharedWriter(writer_buf.clone()))
                    .with_filter(EnvFilter::new("trace")),
            )
            .try_init()
            .expect("setup tracing");
    });
}

static TEST_DB_COUNTER: AtomicU64 = AtomicU64::new(0);
static TEST_DB_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Name hashed into the postgres advisory lock that serializes test-database
/// management. `TEST_DB_LOCK` cannot exclude OTHER test processes sharing the
/// server, so creation/cleanup additionally runs under a session-scoped
/// advisory lock: only one process manages databases at a time, and a stale
/// database can never be dropped between its creation and first connection.
/// If a lock holder crashes, its session ends and postgres releases the lock.
const PG_MGMT_ADVISORY_NAME: &str = "bdk_sqlx_test_db_mgmt";

/// Takes the cross-process database-management lock on a dedicated session.
/// Must be paired with [`pg_mgmt_unlock`]; callers hold `TEST_DB_LOCK` first,
/// so contention can only come from other processes and no deadlock cycle
/// exists.
async fn pg_mgmt_lock(
    admin_pool: &Pool<Postgres>,
) -> anyhow::Result<sqlx::pool::PoolConnection<Postgres>> {
    let mut conn = admin_pool.acquire().await?;
    sqlx::query("SELECT pg_advisory_lock(hashtext($1))")
        .bind(PG_MGMT_ADVISORY_NAME)
        .execute(&mut *conn)
        .await?;
    Ok(conn)
}

/// Releases the cross-process database-management lock. Best-effort: if the
/// session is already gone, postgres has released the lock anyway.
async fn pg_mgmt_unlock(mut conn: sqlx::pool::PoolConnection<Postgres>) {
    let _ = sqlx::query("SELECT pg_advisory_unlock(hashtext($1))")
        .bind(PG_MGMT_ADVISORY_NAME)
        .execute(&mut *conn)
        .await;
}

/// Creates a uniquely named database on the postgres server at `DATABASE_TEST_URL` and
/// returns a pool connected to it, so every test gets an isolated database and no
/// pre-existing tables are ever dropped.
///
/// Databases left behind by previous test runs are removed opportunistically; a database
/// is never dropped while any session is connected to it, and creation/cleanup are
/// serialized (in-process by `TEST_DB_LOCK`, cross-process by the advisory lock) so a
/// parallel test cannot drop a database between its creation and first connection.
async fn create_test_pg_pool() -> anyhow::Result<Pool<Postgres>> {
    let admin_url = env::var("DATABASE_TEST_URL").expect("DATABASE_TEST_URL must be set for tests");
    let admin_pool = Pool::<Postgres>::connect(&admin_url).await?;

    let db_name = format!(
        "bdk_sqlx_test_{}_{}",
        std::process::id(),
        TEST_DB_COUNTER.fetch_add(1, Ordering::Relaxed)
    );

    let _guard = TEST_DB_LOCK.lock().await;
    let mut mgmt = pg_mgmt_lock(&admin_pool).await?;

    let result = async {
        let stale: Vec<String> = sqlx::query_scalar(
            "SELECT datname::text FROM pg_database d
             WHERE datname LIKE 'bdk_sqlx_test_%'
             AND NOT EXISTS (SELECT 1 FROM pg_stat_activity a WHERE a.datname = d.datname)",
        )
        .fetch_all(&mut *mgmt)
        .await?;
        for stale_db in stale {
            let _ = sqlx::query(&format!(r#"DROP DATABASE IF EXISTS "{stale_db}""#))
                .execute(&mut *mgmt)
                .await;
        }

        sqlx::query(&format!(r#"CREATE DATABASE "{db_name}""#))
            .execute(&mut *mgmt)
            .await?;

        // min_connections(1) keeps a session open for the pool's lifetime, which protects
        // this database from the stale-database cleanup of tests in other processes.
        let opts = PgConnectOptions::from_str(&admin_url)?.database(&db_name);
        let pool = PgPoolOptions::new()
            .min_connections(1)
            .connect_with(opts)
            .await?;
        anyhow::Ok(pool)
    }
    .await;

    pg_mgmt_unlock(mgmt).await;
    result
}

#[derive(Debug)]
enum TestStore {
    Postgres(Store<Postgres>),
    Sqlite(Store<Sqlite>),
}

impl TestStore {
    /// Read the full changeset, matching `Store::read` on either backend.
    async fn read(&self) -> Result<ChangeSet, BdkSqlxError> {
        match self {
            TestStore::Postgres(store) => store.read().await,
            TestStore::Sqlite(store) => store.read().await,
        }
    }
}

impl AsyncWalletPersister for TestStore {
    type Error = BdkSqlxError;

    #[tracing::instrument(skip_all)]
    fn initialize<'a>(store: &'a mut Self) -> FutureResult<'a, ChangeSet, Self::Error>
    where
        Self: 'a,
    {
        info!("initialize test store");
        match store {
            TestStore::Postgres(store) => Box::pin(store.read()),
            TestStore::Sqlite(store) => Box::pin(store.read()),
        }
    }

    #[tracing::instrument(skip_all)]
    fn persist<'a>(
        store: &'a mut Self,
        changeset: &'a ChangeSet,
    ) -> FutureResult<'a, (), Self::Error>
    where
        Self: 'a,
    {
        info!("persist test store");
        match store {
            TestStore::Postgres(store) => Box::pin(store.write(changeset)),
            TestStore::Sqlite(store) => Box::pin(store.write(changeset)),
        }
    }
}

/// A reorg that replaces the block at a height with a different hash must leave exactly
/// one row for that height (the old row's anchors cascade away), not accumulate
/// duplicate rows that make loads nondeterministic.
#[tokio::test]
async fn reorg_replaced_block_leaves_single_row() -> anyhow::Result<()> {
    initialize();

    let (external_desc, internal_desc) = get_test_tr_single_sig_xprv_and_change_desc();
    let wallet_name = wallet_name_from_descriptor(
        external_desc,
        Some(internal_desc),
        NETWORK,
        &Secp256k1::new(),
    )?;

    let stores = create_test_stores(wallet_name.clone()).await?;
    for mut store in stores {
        let mut wallet = Wallet::create(external_desc, internal_desc)
            .network(NETWORK)
            .create_wallet_async(&mut store)
            .await?;
        let _txid = insert_fake_tx(
            &mut wallet,
            Amount::from_sat(20_000),
            Amount::from_sat(10_000),
            Amount::from_sat(1_000),
        );
        assert!(wallet.persist_async(&mut store).await?);

        // Replace the block at height 2000 with a different hash, as a reorg does.
        let new_hash = BlockHash::from_byte_array([77u8; 32]);
        let mut reorg = ChangeSet::default();
        reorg.local_chain.blocks.insert(2_000, Some(new_hash));
        TestStore::persist(&mut store, &reorg).await?;

        let cs = TestStore::initialize(&mut store).await?;
        assert_eq!(cs.local_chain.blocks.get(&2_000), Some(&Some(new_hash)));
        // the anchor that referenced the replaced block is gone with it; the
        // anchor on the untouched block at height 1000 survives
        assert_eq!(cs.tx_graph.anchors.len(), 1);

        // exactly one row must remain at that height
        let rows_at_height: i64 = match &store {
            TestStore::Postgres(store) => sqlx::query_scalar(
                r#"SELECT count(*) FROM "bdk_wallet"."block" WHERE wallet_name=$1 AND height=2000"#,
            )
            .bind(&wallet_name)
            .fetch_one(&store.pool)
            .await?,
            TestStore::Sqlite(store) => {
                sqlx::query_scalar(
                    "SELECT count(*) FROM block WHERE wallet_name=$1 AND height=2000",
                )
                .bind(&wallet_name)
                .fetch_one(&store.pool)
                .await?
            }
        };
        assert_eq!(rows_at_height, 1);
    }
    Ok(())
}

/// Re-persisting a merged/full changeset must be idempotent (upsert, not bare INSERT),
/// and updating last_revealed for a keychain that was never stored must error rather
/// than silently updating 0 rows and losing derivation state.
#[tokio::test]
async fn repersisting_full_changeset_is_idempotent() -> anyhow::Result<()> {
    initialize();

    let (external_desc, internal_desc) = get_test_tr_single_sig_xprv_and_change_desc();
    let wallet_name = wallet_name_from_descriptor(
        external_desc,
        Some(internal_desc),
        NETWORK,
        &Secp256k1::new(),
    )?;

    let stores = create_test_stores(wallet_name).await?;
    for mut store in stores {
        let mut wallet = Wallet::create(external_desc, internal_desc)
            .network(NETWORK)
            .create_wallet_async(&mut store)
            .await?;
        let _ = wallet.reveal_next_address(External);
        assert!(wallet.persist_async(&mut store).await?);

        // A merged changeset carries the descriptors and network again; persisting it
        // previously failed with a unique-constraint violation on the bare INSERTs.
        let full = TestStore::initialize(&mut store).await?;
        assert!(full.descriptor.is_some() && full.network.is_some());
        TestStore::persist(&mut store, &full).await?;

        // last_revealed for a keychain that is not stored must error loudly
        let mut cs = ChangeSet::default();
        cs.indexer.last_revealed.insert(
            DescriptorId(bitcoin::hashes::sha256::Hash::hash(b"missing keychain")),
            5,
        );
        assert_matches!(
            TestStore::persist(&mut store, &cs).await,
            Err(BdkSqlxError::QueryError { .. })
        );
    }
    Ok(())
}

async fn corrupt_ranges_postgres(store: &Store<Postgres>, wallet_name: &str) -> anyhow::Result<()> {
    let pool = store.pool.clone();

    // a negative sat value must not wrap into astronomical amounts
    sqlx::query(r#"UPDATE "bdk_wallet"."txout" SET value=-1 WHERE wallet_name=$1"#)
        .bind(wallet_name)
        .execute(&pool)
        .await?;
    assert_matches!(store.read().await, Err(BdkSqlxError::IntOutOfRange { .. }));
    sqlx::query(r#"UPDATE "bdk_wallet"."txout" SET value=1 WHERE wallet_name=$1"#)
        .bind(wallet_name)
        .execute(&pool)
        .await?;

    // a negative block height must not wrap into a huge height
    sqlx::query(
        r#"UPDATE "bdk_wallet"."block" SET height=-1 WHERE wallet_name=$1 AND height=2000"#,
    )
    .bind(wallet_name)
    .execute(&pool)
    .await?;
    assert_matches!(store.read().await, Err(BdkSqlxError::IntOutOfRange { .. }));
    sqlx::query(
        r#"UPDATE "bdk_wallet"."block" SET height=2000 WHERE wallet_name=$1 AND height=-1"#,
    )
    .bind(wallet_name)
    .execute(&pool)
    .await?;

    store.read().await?;
    Ok(())
}

async fn corrupt_ranges_sqlite(store: &Store<Sqlite>, wallet_name: &str) -> anyhow::Result<()> {
    let pool = store.pool.clone();

    // a negative sat value must not wrap into astronomical amounts
    sqlx::query("UPDATE txout SET value=-1 WHERE wallet_name=$1")
        .bind(wallet_name)
        .execute(&pool)
        .await?;
    assert_matches!(store.read().await, Err(BdkSqlxError::IntOutOfRange { .. }));
    sqlx::query("UPDATE txout SET value=1 WHERE wallet_name=$1")
        .bind(wallet_name)
        .execute(&pool)
        .await?;

    // a negative block height must not wrap into a huge height
    sqlx::query("UPDATE block SET height=-1 WHERE wallet_name=$1 AND height=2000")
        .bind(wallet_name)
        .execute(&pool)
        .await?;
    assert_matches!(store.read().await, Err(BdkSqlxError::IntOutOfRange { .. }));
    sqlx::query("UPDATE block SET height=2000 WHERE wallet_name=$1 AND height=-1")
        .bind(wallet_name)
        .execute(&pool)
        .await?;

    store.read().await?;
    Ok(())
}

/// Out-of-range integers stored in the database (e.g. negative amounts or heights)
/// must error on load instead of wrapping around to huge unsigned values.
#[tokio::test]
async fn out_of_range_values_error_on_load() -> anyhow::Result<()> {
    initialize();

    let (external_desc, internal_desc) = get_test_tr_single_sig_xprv_and_change_desc();
    let wallet_name = wallet_name_from_descriptor(
        external_desc,
        Some(internal_desc),
        NETWORK,
        &Secp256k1::new(),
    )?;

    let stores = create_test_stores(wallet_name.clone()).await?;
    for mut store in stores {
        let mut wallet = Wallet::create(external_desc, internal_desc)
            .network(NETWORK)
            .create_wallet_async(&mut store)
            .await?;
        let txid = insert_fake_tx(
            &mut wallet,
            Amount::from_sat(20_000),
            Amount::from_sat(10_000),
            Amount::from_sat(1_000),
        );
        // add a floating txout row so the txout table is populated
        let mut extra = ChangeSet::default();
        extra.tx_graph.txouts.insert(
            OutPoint { txid, vout: 0 },
            TxOut {
                value: Amount::from_sat(1),
                script_pubkey: Default::default(),
            },
        );
        assert!(wallet.persist_async(&mut store).await?);
        TestStore::persist(&mut store, &extra).await?;

        match &store {
            TestStore::Postgres(store) => corrupt_ranges_postgres(store, &wallet_name).await?,
            TestStore::Sqlite(store) => corrupt_ranges_sqlite(store, &wallet_name).await?,
        }
    }
    Ok(())
}

/// Data stored for a different network than the store was configured with (or an
/// unparseable network string) must fail the load instead of being silently accepted.
#[tokio::test]
async fn mismatched_network_errors_on_load() -> anyhow::Result<()> {
    initialize();

    let (external_desc, internal_desc) = get_test_tr_single_sig_xprv_and_change_desc();
    let wallet_name = wallet_name_from_descriptor(
        external_desc,
        Some(internal_desc),
        NETWORK,
        &Secp256k1::new(),
    )?;

    let pool = create_test_pg_pool().await?;
    let mut store = PgStoreBuilder::new(wallet_name.clone())
        .network(NETWORK)
        .migrate(true)
        .pool(pool.clone())
        .build()
        .await?;
    Wallet::create(external_desc, internal_desc)
        .network(NETWORK)
        .create_wallet_async(&mut store)
        .await?;

    let set_network = r#"UPDATE "bdk_wallet"."network" SET name=$2 WHERE wallet_name=$1"#;

    // a parseable but different network than the configured one
    sqlx::query(set_network)
        .bind(&wallet_name)
        .bind("bitcoin")
        .execute(&pool)
        .await?;
    assert_matches!(store.read().await, Err(BdkSqlxError::InvalidNetwork { .. }));

    // an unparseable network string
    sqlx::query(set_network)
        .bind(&wallet_name)
        .bind("junknet")
        .execute(&pool)
        .await?;
    assert_matches!(store.read().await, Err(BdkSqlxError::InvalidNetwork { .. }));

    sqlx::query(set_network)
        .bind(&wallet_name)
        .bind(NETWORK.to_string())
        .execute(&pool)
        .await?;
    store.read().await?;
    Ok(())
}

#[derive(Clone)]
struct SharedWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for SharedWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Regression test for descriptor material leaking into tracing output: even at TRACE
/// verbosity, spans and events emitted while creating, persisting, and loading a wallet
/// must not record descriptors, public keys, or changesets.
///
/// The events are captured through the permanent global layer installed by
/// `initialize()`. A scoped subscriber previously used here raced sqlx's sqlite
/// worker threads at registry teardown and made the whole suite flaky.
#[tokio::test]
async fn tracing_output_contains_no_descriptor_material() -> anyhow::Result<()> {
    initialize();

    let buf = log_buffer();
    buf.lock().unwrap().clear();

    let (external_desc, internal_desc) = get_test_tr_single_sig_xprv_and_change_desc();
    let wallet_name = wallet_name_from_descriptor(
        external_desc,
        Some(internal_desc),
        NETWORK,
        &Secp256k1::new(),
    )?;

    let mut store = Store::<Sqlite>::new_with_url(None, wallet_name.clone(), NETWORK, true).await?;
    let mut wallet = Wallet::create(external_desc, internal_desc)
        .network(NETWORK)
        .create_wallet_async(&mut store)
        .await?;
    let _ = wallet.reveal_next_address(External);
    wallet.persist_async(&mut store).await?;
    Wallet::load().load_wallet_async(&mut store).await?;

    let logs = String::from_utf8_lossy(&buf.lock().unwrap()).into_owned();
    assert!(!logs.is_empty(), "expected tracing output to be captured");
    for needle in [
        "tprv",
        "tpub",
        "XPub",
        "XPrv",
        "DescriptorXKey",
        "PublicKey(",
    ] {
        assert!(
            !logs.contains(needle),
            "tracing output leaked descriptor material ({needle}):\n{logs}"
        );
    }
    Ok(())
}

async fn create_test_stores(wallet_name: String) -> anyhow::Result<Vec<TestStore>> {
    let mut stores: Vec<TestStore> = Vec::new();

    let pool = create_test_pg_pool().await?;
    let postgres_store = PgStoreBuilder::new(wallet_name.clone())
        .network(NETWORK)
        .migrate(true)
        .pool(pool)
        .build()
        .await?;
    stores.push(TestStore::Postgres(postgres_store));

    // Setup sqlite in-memory database. `new_with_url(None, ..)` configures the
    // single-connection pool a shared in-memory database requires.
    let sqlite_store =
        Store::<Sqlite>::new_with_url(None, wallet_name.clone(), NETWORK, true).await?;
    stores.push(TestStore::Sqlite(sqlite_store));

    Ok(stores)
}

/// Add a fake transaction to a wallet for testing.
///
/// The test wallet must use the `Regtest` network and the added tx will have the given spent,
/// change, and fee amounts.
///
/// The tx ids for the two created transactions (funding and spending) are returned.
pub fn insert_fake_tx(wallet: &mut Wallet, spent: Amount, change: Amount, fee: Amount) -> Txid {
    let receive_address = wallet.reveal_next_address(External).address;
    let change_address = wallet.reveal_next_address(Internal).address;
    let sendto_address = Address::from_str("bcrt1q3qtze4ys45tgdvguj66zrk4fu6hq3a3v9pfly5")
        .expect("address")
        .require_network(Network::Regtest)
        .unwrap();

    let tx0 = Transaction {
        input: vec![TxIn::default()],
        output: vec![TxOut {
            value: spent.add(change).add(fee),
            script_pubkey: receive_address.script_pubkey(),
        }],
        ..new_tx(0)
    };

    let tx1 = Transaction {
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: tx0.compute_txid(),
                vout: 0,
            },
            ..Default::default()
        }],
        output: vec![
            TxOut {
                value: change,
                script_pubkey: change_address.script_pubkey(),
            },
            TxOut {
                value: spent,
                script_pubkey: sendto_address.script_pubkey(),
            },
        ],
        ..new_tx(1)
    };

    // Checkpoints must use a distinct hash per height: the store rejects
    // changesets that map one hash to several heights (it cannot represent
    // them without silently losing checkpoints).
    insert_checkpoint(
        wallet,
        BlockId {
            height: 42,
            hash: block_hash(42),
        },
    );

    insert_checkpoint(
        wallet,
        BlockId {
            height: 1_000,
            hash: block_hash(1),
        },
    );
    insert_checkpoint(
        wallet,
        BlockId {
            height: 2_000,
            hash: block_hash(2),
        },
    );

    let anchor = ConfirmationBlockTime {
        block_id: BlockId {
            height: 1_000,
            hash: block_hash(1),
        },
        confirmation_time: 100,
    };
    insert_anchor(wallet, tx0.compute_txid(), anchor);
    insert_tx(wallet, tx0);

    let anchor = ConfirmationBlockTime {
        block_id: BlockId {
            height: 2_000,
            hash: block_hash(2),
        },
        confirmation_time: 200,
    };
    let txid_1 = tx1.compute_txid();
    insert_anchor(wallet, txid_1, anchor);
    insert_tx(wallet, tx1);

    txid_1
}

#[tracing::instrument]
#[tokio::test]
async fn wallet_is_persisted() -> anyhow::Result<()> {
    initialize();

    // Define descriptors (you may need to adjust these based on your exact requirements)
    let (external_desc, internal_desc) = get_test_tr_single_sig_xprv_and_change_desc();
    // Generate a unique name for this test wallet
    let wallet_name = wallet_name_from_descriptor(
        external_desc,
        Some(internal_desc),
        NETWORK,
        &Secp256k1::new(),
    )?;

    let stores = create_test_stores(wallet_name).await?;
    for mut store in stores {
        // Create a new wallet
        let mut wallet = Wallet::create(external_desc, internal_desc)
            .network(NETWORK)
            .create_wallet_async(&mut store)
            .await?;

        let external_addr0 = wallet.reveal_next_address(External);
        for keychain in [External, Internal] {
            let _ = wallet.reveal_addresses_to(keychain, 2);
        }

        assert!(wallet.persist_async(&mut store).await?);
        let wallet_spk_index = wallet.spk_index();

        {
            // Recover the wallet
            let wallet = Wallet::load()
                .descriptor(External, Some(external_desc))
                .descriptor(Internal, Some(internal_desc))
                .load_wallet_async(&mut store)
                .await?
                .expect("wallet must exist");

            assert_eq!(wallet.network(), NETWORK);
            assert_eq!(
                wallet.spk_index().keychains().collect::<Vec<_>>(),
                wallet_spk_index.keychains().collect::<Vec<_>>()
            );
            assert_eq!(
                wallet.spk_index().last_revealed_indices(),
                wallet_spk_index.last_revealed_indices()
            );

            let recovered_addr = wallet.peek_address(External, 0);
            assert_eq!(recovered_addr, external_addr0, "failed to recover address");

            assert_eq!(
                wallet.public_descriptor(External).to_string(),
                "tr(tpubD6NzVbkrYhZ4WgCeJid2Zds24zATB58r1q1qTLMuApUxZUxzETADNTeP6SvZKSsXs4qhvFAC21GFjXHwgxAcDtZqzzj8JMpsFDgqyjSJHGa/0/*)#celxt6vn".to_string(),
            );
        }
    }

    Ok(())
}

#[tracing::instrument]
#[tokio::test]
async fn test_three_wallets_list_transactions() -> anyhow::Result<()> {
    initialize();

    struct TestCase {
        descriptors: (String, String),
        spent: Amount,
        change: Amount,
        fee: Amount,
        store: TestStore,
    }
    impl TestCase {
        async fn new(
            descriptors: (&'static str, &'static str),
            spent: u64,
            change: u64,
            fee: u64,
        ) -> Vec<Self> {
            let wallet_name = wallet_name_from_descriptor(
                descriptors.0,
                Some(descriptors.1),
                NETWORK,
                &Secp256k1::new(),
            )
            .unwrap();
            let stores = create_test_stores(wallet_name.clone()).await.unwrap();
            stores
                .into_iter()
                .map(|store| Self {
                    descriptors: (descriptors.0.to_string(), descriptors.1.to_string()),
                    spent: Amount::from_sat(spent),
                    change: Amount::from_sat(change),
                    fee: Amount::from_sat(fee),
                    store,
                })
                .collect()
        }
    }
    let mut test_cases = [
        TestCase::new(get_test_tr_single_sig_xprv_and_change_desc(), 20_000, 11_000, 2000).await,
        TestCase::new(("wpkh([bdb9a801/84'/1'/0']tpubDCopxf4CiXF9dicdGrXgZV9f8j3pYbWBVfF8WxjaFHtic4DZsgp1tQ58hZdsSu6M7FFzUyAh9rMn7RZASUkPgZCMdByYKXvVtigzGi8VJs6/0/*)#j8mkwdgr",
                       "wpkh([bdb9a801/84'/1'/0']tpubDCopxf4CiXF9dicdGrXgZV9f8j3pYbWBVfF8WxjaFHtic4DZsgp1tQ58hZdsSu6M7FFzUyAh9rMn7RZASUkPgZCMdByYKXvVtigzGi8VJs6/1/*)#rn7hnccm"), 12_000, 30_000, 1500).await,
        TestCase::new(get_test_minisicript_with_change_desc(), 44_444, 20_000, 5000).await
    ].into_iter().flatten().collect::<Vec<_>>();

    let mut saved_tx_ids = Vec::<Txid>::new();
    let mut saved_balances = Vec::<Balance>::new();

    // create wallet and save test transaction
    for test_case in &mut test_cases {
        let mut wallet = Wallet::create(
            test_case.descriptors.0.clone(),
            test_case.descriptors.1.clone(),
        )
        .network(Regtest)
        .create_wallet_async(&mut test_case.store)
        .await?;
        let tx_id = insert_fake_tx(
            &mut wallet,
            test_case.spent,
            test_case.change,
            test_case.fee,
        );
        saved_tx_ids.push(tx_id);
        saved_balances.push(wallet.balance());
        wallet.persist_async(&mut test_case.store).await?;
    }

    saved_tx_ids.reverse();
    saved_balances.reverse();

    // load wallet and test transaction and verify with saved
    for test_case in &mut test_cases {
        let wallet = Wallet::load()
            .descriptor(External, Some(test_case.descriptors.0.clone()))
            .descriptor(Internal, Some(test_case.descriptors.1.clone()))
            .check_network(Regtest)
            .load_wallet_async(&mut test_case.store)
            .await?
            .expect("wallet must exist");
        let saved_tx_ids = saved_tx_ids.pop().unwrap();
        let loaded_tx_id = wallet
            .transactions()
            .map(|tx| tx.tx_node.tx.compute_txid())
            .next()
            .expect("txid must exist");
        assert_eq!(saved_tx_ids, loaded_tx_id);

        let saved_balance = saved_balances.pop().unwrap();
        let loaded_balance = wallet.balance();
        assert_eq!(saved_balance, loaded_balance);
    }
    Ok(())
}

#[tracing::instrument]
#[tokio::test]
async fn wallet_load_checks() -> anyhow::Result<()> {
    initialize();

    // Define descriptors (you may need to adjust these based on your exact requirements)
    let (external_desc, internal_desc) = get_test_tr_single_sig_xprv_and_change_desc();
    let parsed_ext = parse_descriptor(external_desc);
    let parsed_int = parse_descriptor(internal_desc);
    // Generate a unique name for this test wallet
    let wallet_name = wallet_name_from_descriptor(
        external_desc,
        Some(internal_desc),
        NETWORK,
        &Secp256k1::new(),
    )?;

    let stores = create_test_stores(wallet_name).await?;
    for mut store in stores {
        // Create a new wallet
        let _wallet = Wallet::create(external_desc, internal_desc)
            .network(NETWORK)
            .create_wallet_async(&mut store)
            .await?;

        {
            assert_matches!(
                Wallet::load()
                    .descriptor(External, Some(internal_desc))
                    .load_wallet_async(&mut store)
                    .await,
                Err(LoadWithPersistError::InvalidChangeSet(LoadError::Mismatch(
                    LoadMismatch::Descriptor { keychain, loaded, expected }
                )))
                if keychain == External && loaded == Some(parsed_ext.clone()) && expected == Some(parsed_int.clone()),
                "should error on wrong external descriptor"
            );
        }
        {
            assert_matches!(
                Wallet::load()
                    .descriptor(External, Option::<&str>::None)
                    .load_wallet_async(&mut store)
                    .await,
                Err(LoadWithPersistError::InvalidChangeSet(LoadError::Mismatch(
                    LoadMismatch::Descriptor { keychain, loaded, expected }
                )))
                if keychain == External && loaded == Some(parsed_ext.clone()) && expected.is_none(),
                "external descriptor check should error when expected is none"
            );
        }
        {
            let mainnet_hash = BlockHash::from_byte_array(ChainHash::BITCOIN.to_bytes());
            assert_matches!(
                Wallet::load().check_genesis_hash(mainnet_hash).load_wallet_async(&mut store).await
                , Err(LoadWithPersistError::InvalidChangeSet(LoadError::Mismatch(LoadMismatch::Genesis { .. }))),
                "unexpected genesis hash check result: mainnet hash (check) is not testnet hash (loaded)");
        }
    }
    Ok(())
}

#[tracing::instrument]
#[tokio::test]
async fn single_descriptor_wallet_persist_and_recover() -> anyhow::Result<()> {
    initialize();

    // Define descriptors
    let (desc, _) = get_test_tr_single_sig_xprv_and_change_desc();

    // Generate a unique name for this test wallet
    let wallet_name = wallet_name_from_descriptor(desc, Some(desc), NETWORK, &Secp256k1::new())?;

    let stores = create_test_stores(wallet_name).await?;
    for mut store in stores {
        // Create a new wallet
        let mut wallet = Wallet::create_single(desc)
            .network(NETWORK)
            .create_wallet_async(&mut store)
            .await?;

        let _ = wallet.reveal_addresses_to(External, 2);
        assert!(wallet.persist_async(&mut store).await?);

        {
            // Recover the wallet
            let wallet = Wallet::load().load_wallet_async(&mut store).await?.unwrap();
            assert_eq!(wallet.derivation_index(External), Some(2));
        }
        {
            // should error on wrong internal params
            let desc = get_test_wpkh();
            let exp_desc = parse_descriptor(desc);
            let err = Wallet::load()
                .descriptor(Internal, Some(desc))
                .load_wallet_async(&mut store)
                .await;
            assert_matches!(
                err,
                Err(LoadWithPersistError::InvalidChangeSet(LoadError::Mismatch(LoadMismatch::Descriptor { keychain, loaded, expected })))
                if keychain == Internal && loaded.is_none() && expected == Some(exp_desc),
                "single descriptor wallet should refuse change descriptor param"
            );
        }
    }
    Ok(())
}

const BOGUS_TXID: &str = "1111111111111111111111111111111111111111111111111111111111111111";

async fn corrupt_and_check_postgres(
    store: &Store<Postgres>,
    wallet_name: &str,
    txid: Txid,
) -> anyhow::Result<()> {
    let pool = store.pool.clone();
    let txid = txid.to_string();

    let valid_tx: Vec<u8> = sqlx::query_scalar(
        r#"SELECT whole_tx FROM "bdk_wallet"."tx" WHERE wallet_name=$1 AND txid=$2"#,
    )
    .bind(wallet_name)
    .bind(&txid)
    .fetch_one(&pool)
    .await?;
    let set_whole_tx =
        r#"UPDATE "bdk_wallet"."tx" SET whole_tx=$3 WHERE wallet_name=$1 AND txid=$2"#;

    // undecodable tx bytes must fail the load, not silently drop the tx
    sqlx::query(set_whole_tx)
        .bind(wallet_name)
        .bind(&txid)
        .bind(vec![0xde_u8, 0xad, 0xbe, 0xef])
        .execute(&pool)
        .await?;
    assert_matches!(store.read().await, Err(BdkSqlxError::Consensus(_)));

    // trailing bytes after a valid tx must be rejected
    let mut trailing = valid_tx.clone();
    trailing.push(0);
    sqlx::query(set_whole_tx)
        .bind(wallet_name)
        .bind(&txid)
        .bind(trailing)
        .execute(&pool)
        .await?;
    assert_matches!(store.read().await, Err(BdkSqlxError::Consensus(_)));

    sqlx::query(set_whole_tx)
        .bind(wallet_name)
        .bind(&txid)
        .bind(&valid_tx)
        .execute(&pool)
        .await?;

    // tx bytes that decode to a different txid than the stored txid must be rejected
    sqlx::query(r#"INSERT INTO "bdk_wallet"."tx" (wallet_name, txid, whole_tx) VALUES ($1,$2,$3)"#)
        .bind(wallet_name)
        .bind(BOGUS_TXID)
        .bind(&valid_tx)
        .execute(&pool)
        .await?;
    assert_matches!(store.read().await, Err(BdkSqlxError::TxidMismatch { .. }));
    sqlx::query(r#"DELETE FROM "bdk_wallet"."tx" WHERE wallet_name=$1 AND txid=$2"#)
        .bind(wallet_name)
        .bind(BOGUS_TXID)
        .execute(&pool)
        .await?;

    // an unparseable anchor must fail the load, not silently drop the anchor
    let valid_anchor: serde_json::Value = sqlx::query_scalar(
        r#"SELECT anchor FROM "bdk_wallet"."anchor_tx" WHERE wallet_name=$1 AND txid=$2"#,
    )
    .bind(wallet_name)
    .bind(&txid)
    .fetch_one(&pool)
    .await?;
    let set_anchor =
        r#"UPDATE "bdk_wallet"."anchor_tx" SET anchor=$3 WHERE wallet_name=$1 AND txid=$2"#;
    sqlx::query(set_anchor)
        .bind(wallet_name)
        .bind(&txid)
        .bind(serde_json::json!({"bogus": 1}))
        .execute(&pool)
        .await?;
    assert_matches!(store.read().await, Err(BdkSqlxError::SerdeJson(_)));

    // an anchor whose payload points at a different block than the stored block_hash
    let mut mutated = valid_anchor.clone();
    mutated["block_id"]["hash"] = serde_json::json!(BOGUS_TXID);
    sqlx::query(set_anchor)
        .bind(wallet_name)
        .bind(&txid)
        .bind(mutated)
        .execute(&pool)
        .await?;
    assert_matches!(
        store.read().await,
        Err(BdkSqlxError::AnchorBlockHashMismatch { .. })
    );

    sqlx::query(set_anchor)
        .bind(wallet_name)
        .bind(&txid)
        .bind(valid_anchor)
        .execute(&pool)
        .await?;
    store.read().await?;
    Ok(())
}

async fn corrupt_and_check_sqlite(
    store: &Store<Sqlite>,
    wallet_name: &str,
    txid: Txid,
) -> anyhow::Result<()> {
    let pool = store.pool.clone();
    let txid = txid.to_string();

    let valid_tx: Vec<u8> =
        sqlx::query_scalar("SELECT whole_tx FROM tx WHERE wallet_name=$1 AND txid=$2")
            .bind(wallet_name)
            .bind(&txid)
            .fetch_one(&pool)
            .await?;
    let set_whole_tx = "UPDATE tx SET whole_tx=$3 WHERE wallet_name=$1 AND txid=$2";

    // undecodable tx bytes must fail the load, not silently drop the tx
    sqlx::query(set_whole_tx)
        .bind(wallet_name)
        .bind(&txid)
        .bind(vec![0xde_u8, 0xad, 0xbe, 0xef])
        .execute(&pool)
        .await?;
    assert_matches!(store.read().await, Err(BdkSqlxError::Consensus(_)));

    // trailing bytes after a valid tx must be rejected
    let mut trailing = valid_tx.clone();
    trailing.push(0);
    sqlx::query(set_whole_tx)
        .bind(wallet_name)
        .bind(&txid)
        .bind(trailing)
        .execute(&pool)
        .await?;
    assert_matches!(store.read().await, Err(BdkSqlxError::Consensus(_)));

    sqlx::query(set_whole_tx)
        .bind(wallet_name)
        .bind(&txid)
        .bind(&valid_tx)
        .execute(&pool)
        .await?;

    // tx bytes that decode to a different txid than the stored txid must be rejected
    sqlx::query("INSERT INTO tx (wallet_name, txid, whole_tx) VALUES ($1,$2,$3)")
        .bind(wallet_name)
        .bind(BOGUS_TXID)
        .bind(&valid_tx)
        .execute(&pool)
        .await?;
    assert_matches!(store.read().await, Err(BdkSqlxError::TxidMismatch { .. }));
    sqlx::query("DELETE FROM tx WHERE wallet_name=$1 AND txid=$2")
        .bind(wallet_name)
        .bind(BOGUS_TXID)
        .execute(&pool)
        .await?;

    // an unparseable anchor must fail the load, not silently drop the anchor
    let valid_anchor: serde_json::Value =
        sqlx::query_scalar("SELECT json(anchor) FROM anchor_tx WHERE wallet_name=$1 AND txid=$2")
            .bind(wallet_name)
            .bind(&txid)
            .fetch_one(&pool)
            .await?;
    let set_anchor = "UPDATE anchor_tx SET anchor=jsonb($3) WHERE wallet_name=$1 AND txid=$2";
    sqlx::query(set_anchor)
        .bind(wallet_name)
        .bind(&txid)
        .bind(serde_json::json!({"bogus": 1}).to_string())
        .execute(&pool)
        .await?;
    assert_matches!(store.read().await, Err(BdkSqlxError::SerdeJson(_)));

    // an anchor whose payload points at a different block than the stored block_hash
    let mut mutated = valid_anchor.clone();
    mutated["block_id"]["hash"] = serde_json::json!(BOGUS_TXID);
    sqlx::query(set_anchor)
        .bind(wallet_name)
        .bind(&txid)
        .bind(mutated.to_string())
        .execute(&pool)
        .await?;
    assert_matches!(
        store.read().await,
        Err(BdkSqlxError::AnchorBlockHashMismatch { .. })
    );

    sqlx::query(set_anchor)
        .bind(wallet_name)
        .bind(&txid)
        .bind(valid_anchor.to_string())
        .execute(&pool)
        .await?;
    store.read().await?;
    Ok(())
}

/// Regression test for silent data loss: corrupted rows must produce an explicit error
/// on load instead of an `Ok` changeset that is quietly missing data.
#[tokio::test]
async fn corrupt_rows_error_on_load() -> anyhow::Result<()> {
    initialize();

    let (external_desc, internal_desc) = get_test_tr_single_sig_xprv_and_change_desc();
    let wallet_name = wallet_name_from_descriptor(
        external_desc,
        Some(internal_desc),
        NETWORK,
        &Secp256k1::new(),
    )?;

    let stores = create_test_stores(wallet_name.clone()).await?;
    for mut store in stores {
        let mut wallet = Wallet::create(external_desc, internal_desc)
            .network(NETWORK)
            .create_wallet_async(&mut store)
            .await?;
        let txid = insert_fake_tx(
            &mut wallet,
            Amount::from_sat(20_000),
            Amount::from_sat(10_000),
            Amount::from_sat(1_000),
        );
        assert!(wallet.persist_async(&mut store).await?);

        match &store {
            TestStore::Postgres(store) => {
                corrupt_and_check_postgres(store, &wallet_name, txid).await?
            }
            TestStore::Sqlite(store) => corrupt_and_check_sqlite(store, &wallet_name, txid).await?,
        }
    }
    Ok(())
}

/// Regression test for a reorg wedging persistence: deleting a block that still has
/// `anchor_tx` rows referencing it must succeed (the anchors are dropped with the block)
/// instead of aborting the whole persist transaction with a FK violation.
#[tokio::test]
async fn reorged_out_anchored_block_can_be_deleted() -> anyhow::Result<()> {
    initialize();

    let (external_desc, internal_desc) = get_test_tr_single_sig_xprv_and_change_desc();
    let wallet_name = wallet_name_from_descriptor(
        external_desc,
        Some(internal_desc),
        NETWORK,
        &Secp256k1::new(),
    )?;

    let stores = create_test_stores(wallet_name).await?;
    for mut store in stores {
        let mut wallet = Wallet::create(external_desc, internal_desc)
            .network(NETWORK)
            .create_wallet_async(&mut store)
            .await?;

        // Anchor transactions to blocks and persist, so anchor_tx rows reference block rows.
        let _txid = insert_fake_tx(
            &mut wallet,
            Amount::from_sat(20_000),
            Amount::from_sat(10_000),
            Amount::from_sat(1_000),
        );
        assert!(wallet.persist_async(&mut store).await?);

        // Simulate a reorg disconnecting the anchored block: BDK's local_chain
        // changeset carries (height, None), which deletes the block row.
        let mut reorg = ChangeSet::default();
        reorg.local_chain.blocks.insert(2_000, None);
        TestStore::persist(&mut store, &reorg)
            .await
            .expect("persisting a reorg over an anchored block must not fail");

        // The disconnected block and its anchor are gone; the rest survives.
        let changeset = TestStore::initialize(&mut store).await?;
        assert!(!changeset.local_chain.blocks.contains_key(&2_000));
        assert_eq!(
            changeset.tx_graph.anchors.len(),
            1,
            "only the anchor on the disconnected block is dropped"
        );
        assert_eq!(changeset.tx_graph.txs.len(), 2);

        // Persistence still works afterwards.
        let mut new_tip = ChangeSet::default();
        new_tip
            .local_chain
            .blocks
            .insert(2_001, Some(BlockHash::from_byte_array([1u8; 32])));
        TestStore::persist(&mut store, &new_tip).await?;
    }
    Ok(())
}

#[tracing::instrument]
#[tokio::test]
async fn two_wallets_load() -> anyhow::Result<()> {
    initialize();

    // Define descriptors
    let (external_desc_wallet_1, internal_desc_wallet_1) =
        get_test_tr_single_sig_xprv_and_change_desc();
    let (external_desc_wallet_2, internal_desc_wallet_2) = ("wpkh([bdb9a801/84'/1'/0']tpubDCopxf4CiXF9dicdGrXgZV9f8j3pYbWBVfF8WxjaFHtic4DZsgp1tQ58hZdsSu6M7FFzUyAh9rMn7RZASUkPgZCMdByYKXvVtigzGi8VJs6/0/*)#j8mkwdgr", "wpkh([bdb9a801/84'/1'/0']tpubDCopxf4CiXF9dicdGrXgZV9f8j3pYbWBVfF8WxjaFHtic4DZsgp1tQ58hZdsSu6M7FFzUyAh9rMn7RZASUkPgZCMdByYKXvVtigzGi8VJs6/1/*)#rn7hnccm");

    // Generate a unique name for test wallets
    let wallet_1_name = wallet_name_from_descriptor(
        external_desc_wallet_1,
        Some(internal_desc_wallet_1),
        NETWORK,
        &Secp256k1::new(),
    )?;

    let wallet_2_name = wallet_name_from_descriptor(
        external_desc_wallet_2,
        Some(internal_desc_wallet_2),
        NETWORK,
        &Secp256k1::new(),
    )?;

    let mut stores1 = create_test_stores(wallet_1_name).await?;
    let mut stores2 = create_test_stores(wallet_2_name).await?;

    for _ in 0..stores1.len() {
        let mut store_1 = stores1.pop().unwrap();
        let mut store_2 = stores2.pop().unwrap();

        let mut wallet_1 = Wallet::create(external_desc_wallet_1, internal_desc_wallet_1)
            .network(NETWORK)
            .create_wallet_async(&mut store_1)
            .await?;
        let _ = wallet_1.reveal_next_address(External);
        let _ = wallet_1.reveal_next_address(Internal);
        assert!(wallet_1.persist_async(&mut store_1).await?);

        // for wallet 2 we reveal an extra internal address and insert a new checkpoint
        // to check that loading returns the correct data for each wallet
        let mut wallet_2 = Wallet::create(external_desc_wallet_2, internal_desc_wallet_2)
            .network(NETWORK)
            .create_wallet_async(&mut store_2)
            .await?;
        let _ = wallet_2.reveal_next_address(External);
        let _ = wallet_2.reveal_addresses_to(Internal, 2);
        let block = BlockId {
            height: 100,
            hash: BlockHash::all_zeros(),
        };
        bdk_wallet::test_utils::insert_checkpoint(&mut wallet_2, block);
        assert!(wallet_2.persist_async(&mut store_2).await?);

        // Recover the wallet_1
        let wallet_1 = Wallet::load()
            .load_wallet_async(&mut store_1)
            .await?
            .unwrap();

        // Recover the wallet_2
        let wallet_2 = Wallet::load()
            .load_wallet_async(&mut store_2)
            .await?
            .unwrap();

        assert_eq!(
            wallet_1.derivation_index(External),
            wallet_2.derivation_index(External)
        );
        assert_ne!(
            wallet_1.derivation_index(Internal),
            wallet_2.derivation_index(Internal),
            "different wallets should not have same derivation index"
        );
        assert_ne!(
            wallet_1.latest_checkpoint(),
            wallet_2.latest_checkpoint(),
            "different wallets should not have same chain tip"
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Pure unit tests (no database)
// ---------------------------------------------------------------------------

#[test]
fn checked_conv_accepts_in_range_values() {
    assert_eq!(crate::checked_conv::<i32, u32>(42, "t").unwrap(), 42u32);
    assert_eq!(
        crate::checked_conv::<i32, u32>(i32::MAX, "t").unwrap(),
        i32::MAX as u32
    );
    assert_eq!(crate::checked_conv::<u32, i32>(0, "t").unwrap(), 0i32);
    assert_eq!(
        crate::checked_conv::<u32, i32>(i32::MAX as u32, "t").unwrap(),
        i32::MAX
    );
    assert_eq!(
        crate::checked_conv::<i64, u64>(i64::MAX, "t").unwrap(),
        i64::MAX as u64
    );
    assert_eq!(
        crate::checked_conv::<u64, i64>(i64::MAX as u64, "t").unwrap(),
        i64::MAX
    );
    assert_eq!(crate::checked_conv::<i32, u32>(0, "t").unwrap(), 0u32);
}

#[test]
fn checked_conv_rejects_out_of_range_values() {
    // negative into unsigned
    assert_matches!(
        crate::checked_conv::<i32, u32>(-1, "height"),
        Err(BdkSqlxError::IntOutOfRange {
            context: "height",
            value: -1
        })
    );
    assert_matches!(
        crate::checked_conv::<i64, u64>(-5, "last_seen"),
        Err(BdkSqlxError::IntOutOfRange {
            context: "last_seen",
            value: -5
        })
    );
    assert_matches!(
        crate::checked_conv::<i32, u32>(i32::MIN, "t"),
        Err(BdkSqlxError::IntOutOfRange { .. })
    );
    // too large for destination
    assert_matches!(
        crate::checked_conv::<u32, i32>(u32::MAX, "last_revealed"),
        Err(BdkSqlxError::IntOutOfRange {
            context: "last_revealed",
            value
        }) if value == u32::MAX as i128
    );
    assert_matches!(
        crate::checked_conv::<u64, i64>(u64::MAX, "value"),
        Err(BdkSqlxError::IntOutOfRange { context: "value", value }) if value == u64::MAX as i128
    );
    assert_matches!(
        crate::checked_conv::<u32, i32>(i32::MAX as u32 + 1, "t"),
        Err(BdkSqlxError::IntOutOfRange { .. })
    );
}

#[test]
fn error_display_messages_are_stable() {
    assert_eq!(BdkSqlxError::MissingNetwork.to_string(), "Network Missing");
    assert_eq!(
        BdkSqlxError::MissingPool.to_string(),
        "No database connection pool provided to the builder"
    );
    assert_eq!(
        BdkSqlxError::IntOutOfRange {
            context: "txout.value",
            value: -1
        }
        .to_string(),
        "integer value out of range for txout.value: -1"
    );
    assert_eq!(
        BdkSqlxError::InvalidNetwork {
            expected: "regtest".into(),
            got: "bitcoin".into()
        }
        .to_string(),
        "Invalid Network expected regtest, got bitcoin"
    );
    assert!(BdkSqlxError::GetNetworkFailure
        .to_string()
        .contains("not set"));
}

#[tokio::test]
async fn pg_builder_requires_network_and_pool() {
    initialize();

    // neither network nor pool set: network is validated first
    assert_matches!(
        PgStoreBuilder::new("w".into()).build().await,
        Err(BdkSqlxError::MissingNetwork)
    );

    // network set but no pool. This must fail with MissingPool and must NOT
    // touch the process-global network (build only initializes the global
    // network once a pool exists).
    assert_matches!(
        PgStoreBuilder::new("w".into())
            .network(Regtest)
            .build()
            .await,
        Err(BdkSqlxError::MissingPool)
    );
}

// ---------------------------------------------------------------------------
// Shared helpers for the store-level tests
// ---------------------------------------------------------------------------

/// A transaction with a single default input and a single output; `lock_time` and
/// `value` make each minted txid distinct.
fn sample_tx(lock_time: u32, value: u64) -> Transaction {
    Transaction {
        input: vec![TxIn::default()],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: ScriptBuf::new(),
        }],
        ..new_tx(lock_time)
    }
}

fn block_hash(byte: u8) -> BlockHash {
    BlockHash::from_byte_array([byte; 32])
}

fn anchor_at(height: u32, hash: BlockHash, confirmation_time: u64) -> ConfirmationBlockTime {
    ConfirmationBlockTime {
        block_id: BlockId { height, hash },
        confirmation_time,
    }
}

/// A changeset exercising every table: the network, a three-block chain with
/// distinct hashes, one confirmed tx (anchored to the block at height 10), one
/// unconfirmed tx (last_seen only), and txouts on both transactions.
fn populated_changeset() -> ChangeSet {
    let mut cs = ChangeSet {
        network: Some(Regtest),
        ..Default::default()
    };

    cs.local_chain.blocks.insert(5, Some(block_hash(1)));
    cs.local_chain.blocks.insert(10, Some(block_hash(2)));
    cs.local_chain.blocks.insert(15, Some(block_hash(3)));

    let tx_a = sample_tx(0, 50_000);
    let tx_b = sample_tx(1, 30_000);
    let txid_a = tx_a.compute_txid();
    let txid_b = tx_b.compute_txid();
    cs.tx_graph.txs.insert(Arc::new(tx_a));
    cs.tx_graph.txs.insert(Arc::new(tx_b));
    cs.tx_graph.txouts.insert(
        OutPoint {
            txid: txid_a,
            vout: 0,
        },
        TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::from(vec![0x51]),
        },
    );
    cs.tx_graph.txouts.insert(
        OutPoint {
            txid: txid_b,
            vout: 1,
        },
        TxOut {
            value: Amount::from_sat(30_000),
            script_pubkey: ScriptBuf::from(vec![0x52]),
        },
    );
    cs.tx_graph.last_seen.insert(txid_b, 1_700_000_123);
    cs.tx_graph
        .anchors
        .insert((anchor_at(10, block_hash(2), 12_345), txid_a));

    cs
}

fn assert_populated(loaded: &ChangeSet, expected: &ChangeSet) {
    assert_eq!(loaded.network, expected.network);
    assert_eq!(loaded.tx_graph, expected.tx_graph);
    assert_eq!(loaded.local_chain, expected.local_chain);
}

/// Row count for one of the wallet tables; table names are internal constants.
async fn table_count(store: &TestStore, table: &str, wallet_name: &str) -> anyhow::Result<i64> {
    let count = match store {
        TestStore::Postgres(store) => {
            sqlx::query_scalar(&format!(
                r#"SELECT count(*) FROM "bdk_wallet"."{table}" WHERE wallet_name=$1"#
            ))
            .bind(wallet_name)
            .fetch_one(&store.pool)
            .await?
        }
        TestStore::Sqlite(store) => {
            sqlx::query_scalar(&format!(
                "SELECT count(*) FROM {table} WHERE wallet_name=$1"
            ))
            .bind(wallet_name)
            .fetch_one(&store.pool)
            .await?
        }
    };
    Ok(count)
}

const ALL_TABLES: [&str; 6] = ["network", "keychain", "block", "tx", "txout", "anchor_tx"];

// ---------------------------------------------------------------------------
// Store behaviour: empty stores and empty changesets
// ---------------------------------------------------------------------------

#[tokio::test]
async fn empty_store_reads_default_changeset() -> anyhow::Result<()> {
    initialize();

    let wallet_name = "empty_store_reads_default_changeset".to_string();
    for mut store in create_test_stores(wallet_name).await? {
        let loaded = TestStore::initialize(&mut store).await?;
        assert!(loaded.is_empty(), "fresh store must read back empty");
    }
    Ok(())
}

#[tokio::test]
async fn persist_empty_changeset_writes_nothing() -> anyhow::Result<()> {
    initialize();

    let wallet_name = "persist_empty_changeset_writes_nothing".to_string();
    for mut store in create_test_stores(wallet_name.clone()).await? {
        TestStore::persist(&mut store, &ChangeSet::default()).await?;
        for table in ALL_TABLES {
            assert_eq!(table_count(&store, table, &wallet_name).await?, 0);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Roundtrips
// ---------------------------------------------------------------------------

/// Every table must survive a persist/load roundtrip unchanged, and reading
/// twice must be stable.
#[tokio::test]
async fn populated_changeset_roundtrip() -> anyhow::Result<()> {
    initialize();

    let wallet_name = "populated_changeset_roundtrip".to_string();
    for mut store in create_test_stores(wallet_name).await? {
        let cs = populated_changeset();
        TestStore::persist(&mut store, &cs).await?;

        let loaded = TestStore::initialize(&mut store).await?;
        assert_populated(&loaded, &cs);

        let loaded_again = TestStore::initialize(&mut store).await?;
        assert_eq!(loaded_again, loaded, "repeated reads must be identical");
    }
    Ok(())
}

/// Changesets persisted in sequence must accumulate (merge), not replace.
#[tokio::test]
async fn changesets_merge_across_persists() -> anyhow::Result<()> {
    initialize();

    let wallet_name = "changesets_merge_across_persists".to_string();
    for mut store in create_test_stores(wallet_name).await? {
        let tx_a = sample_tx(0, 50_000);
        let tx_b = sample_tx(1, 30_000);
        let txid_a = tx_a.compute_txid();
        let txid_b = tx_b.compute_txid();

        let mut delta1 = ChangeSet {
            network: Some(Regtest),
            ..Default::default()
        };
        delta1.tx_graph.txs.insert(Arc::new(tx_a));
        TestStore::persist(&mut store, &delta1).await?;

        let mut delta2 = ChangeSet::default();
        delta2.tx_graph.txs.insert(Arc::new(tx_b));
        delta2.tx_graph.last_seen.insert(txid_b, 42);
        delta2.local_chain.blocks.insert(5, Some(block_hash(1)));
        TestStore::persist(&mut store, &delta2).await?;

        let mut delta3 = ChangeSet::default();
        delta3.tx_graph.txouts.insert(
            OutPoint {
                txid: txid_a,
                vout: 0,
            },
            TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::new(),
            },
        );
        TestStore::persist(&mut store, &delta3).await?;

        let loaded = TestStore::initialize(&mut store).await?;
        assert_eq!(loaded.network, Some(Regtest));
        assert_eq!(loaded.tx_graph.txs.len(), 2);
        assert!(loaded
            .tx_graph
            .txs
            .iter()
            .any(|tx| tx.compute_txid() == txid_a));
        assert!(loaded
            .tx_graph
            .txs
            .iter()
            .any(|tx| tx.compute_txid() == txid_b));
        assert_eq!(loaded.tx_graph.last_seen.get(&txid_b), Some(&42));
        assert_eq!(
            loaded.local_chain.blocks.get(&5),
            Some(&Some(block_hash(1)))
        );
        assert_eq!(loaded.tx_graph.txouts.len(), 1);
    }
    Ok(())
}

/// A reorg that evicts an anchored block drops the anchor with it; anchoring the
/// same tx to the replacement block must then roundtrip cleanly.
#[tokio::test]
async fn reanchor_after_reorg_roundtrip() -> anyhow::Result<()> {
    initialize();

    let wallet_name = "reanchor_after_reorg_roundtrip".to_string();
    for mut store in create_test_stores(wallet_name).await? {
        TestStore::persist(&mut store, &populated_changeset()).await?;

        // replace the anchored block at height 10 with a different hash
        let mut reorg = ChangeSet::default();
        reorg.local_chain.blocks.insert(10, Some(block_hash(9)));
        TestStore::persist(&mut store, &reorg).await?;

        let loaded = TestStore::initialize(&mut store).await?;
        assert!(
            loaded.tx_graph.anchors.is_empty(),
            "anchors of the reorged-out block must be gone"
        );

        // re-anchor the same tx to the replacement block
        let txid_a = sample_tx(0, 50_000).compute_txid();
        let mut reanchor = ChangeSet::default();
        reanchor
            .tx_graph
            .anchors
            .insert((anchor_at(10, block_hash(9), 77_777), txid_a));
        TestStore::persist(&mut store, &reanchor).await?;

        let loaded = TestStore::initialize(&mut store).await?;
        assert_eq!(loaded.tx_graph.anchors.len(), 1);
        assert!(loaded
            .tx_graph
            .anchors
            .contains(&(anchor_at(10, block_hash(9), 77_777), txid_a)));
        assert_eq!(
            loaded.local_chain.blocks.get(&10),
            Some(&Some(block_hash(9)))
        );
        assert_eq!(loaded.tx_graph.txs.len(), 2, "txs must survive reorgs");
    }
    Ok(())
}

/// Advancing the derivation index across multiple persist/load cycles.
#[tokio::test]
async fn derivation_index_advances_across_loads() -> anyhow::Result<()> {
    initialize();

    let (external_desc, internal_desc) = get_test_tr_single_sig_xprv_and_change_desc();
    let wallet_name = wallet_name_from_descriptor(
        external_desc,
        Some(internal_desc),
        NETWORK,
        &Secp256k1::new(),
    )?;

    for mut store in create_test_stores(wallet_name).await? {
        let mut wallet = Wallet::create(external_desc, internal_desc)
            .network(NETWORK)
            .create_wallet_async(&mut store)
            .await?;
        let _ = wallet.reveal_addresses_to(External, 3);
        assert!(wallet.persist_async(&mut store).await?);

        let mut wallet = Wallet::load()
            .load_wallet_async(&mut store)
            .await?
            .expect("wallet must exist");
        assert_eq!(wallet.derivation_index(External), Some(3));
        let addr = wallet.reveal_addresses_to(External, 7).last().unwrap();
        assert_eq!(addr.index, 7);
        assert!(wallet.persist_async(&mut store).await?);

        let wallet = Wallet::load()
            .load_wallet_async(&mut store)
            .await?
            .expect("wallet must exist");
        assert_eq!(wallet.derivation_index(External), Some(7));
        assert_eq!(wallet.peek_address(External, 7).address, addr.address);
    }
    Ok(())
}

/// Persisting a descriptor without any derivation state must load back with
/// `last_revealed` UNSET (NULL), not 0: a reloaded fresh wallet must behave
/// exactly like the never-persisted one (its next address is index 0).
#[tokio::test]
async fn descriptor_persist_leaves_last_revealed_unset() -> anyhow::Result<()> {
    initialize();

    let (external_desc, internal_desc) = get_test_tr_single_sig_xprv_and_change_desc();
    let ext = parse_descriptor(external_desc);
    let int = parse_descriptor(internal_desc);

    let wallet_name = "descriptor_persist_leaves_last_revealed_unset".to_string();
    for mut store in create_test_stores(wallet_name).await? {
        let cs = ChangeSet {
            network: Some(Regtest),
            descriptor: Some(ext.clone()),
            change_descriptor: Some(int.clone()),
            ..Default::default()
        };
        TestStore::persist(&mut store, &cs).await?;

        let loaded = TestStore::initialize(&mut store).await?;
        assert_eq!(loaded.descriptor, Some(ext.clone()));
        assert_eq!(loaded.change_descriptor, Some(int.clone()));
        assert!(
            loaded.indexer.last_revealed.is_empty(),
            "no address was revealed, so no last_revealed entries must exist"
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Transactionality
// ---------------------------------------------------------------------------

/// A changeset that fails partway (here: an anchor referencing a block that was
/// never persisted, which violates the FK) must roll back everything it wrote.
#[tokio::test]
async fn failed_persist_rolls_back_everything() -> anyhow::Result<()> {
    initialize();

    let wallet_name = "failed_persist_rolls_back_everything".to_string();
    for mut store in create_test_stores(wallet_name.clone()).await? {
        let tx_a = sample_tx(0, 50_000);
        let txid_a = tx_a.compute_txid();

        let mut cs = ChangeSet {
            network: Some(Regtest),
            ..Default::default()
        };
        cs.tx_graph.txs.insert(Arc::new(tx_a));
        // no block row for this anchor -> FK violation on anchor_tx
        cs.tx_graph
            .anchors
            .insert((anchor_at(99, block_hash(9), 1), txid_a));

        let result = TestStore::persist(&mut store, &cs).await;
        match &store {
            TestStore::Postgres(_) => {
                assert_matches!(result, Err(BdkSqlxError::QueryError { .. }))
            }
            TestStore::Sqlite(_) => assert_matches!(result, Err(BdkSqlxError::Sqlx(_))),
        }

        let loaded = TestStore::initialize(&mut store).await?;
        assert!(
            loaded.is_empty(),
            "a failed persist must not leave partial data behind"
        );
        for table in ALL_TABLES {
            assert_eq!(table_count(&store, table, &wallet_name).await?, 0);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Integer boundaries at the database boundary
// ---------------------------------------------------------------------------

/// Values that do not fit the column types must error loudly on persist instead
/// of wrapping; maximum in-range values must roundtrip exactly.
#[tokio::test]
async fn integer_boundaries_checked_on_persist() -> anyhow::Result<()> {
    initialize();

    let (external_desc, internal_desc) = get_test_tr_single_sig_xprv_and_change_desc();
    let ext = parse_descriptor(external_desc);
    let ext_did = ext.descriptor_id();
    let txid = sample_tx(0, 1_000).compute_txid();

    let wallet_name = wallet_name_from_descriptor(
        external_desc,
        Some(internal_desc),
        NETWORK,
        &Secp256k1::new(),
    )?;

    for mut store in create_test_stores(wallet_name).await? {
        // arrange a network row and keychain row
        let base = ChangeSet {
            network: Some(Regtest),
            descriptor: Some(ext.clone()),
            ..Default::default()
        };
        TestStore::persist(&mut store, &base).await?;

        // last_revealed: u32 that does not fit i32 must error
        let mut cs = ChangeSet::default();
        cs.indexer.last_revealed.insert(ext_did, u32::MAX);
        assert_matches!(
            TestStore::persist(&mut store, &cs).await,
            Err(BdkSqlxError::IntOutOfRange { .. }),
            "u32::MAX last_revealed must not wrap into i32"
        );
        // the maximum representable value roundtrips
        cs.indexer.last_revealed.insert(ext_did, i32::MAX as u32);
        TestStore::persist(&mut store, &cs).await?;

        // txout value: u64 sats that do not fit BIGINT must error
        let mut cs = ChangeSet::default();
        cs.tx_graph.txouts.insert(
            OutPoint { txid, vout: 0 },
            TxOut {
                value: Amount::from_sat(u64::MAX),
                script_pubkey: ScriptBuf::new(),
            },
        );
        assert_matches!(
            TestStore::persist(&mut store, &cs).await,
            Err(BdkSqlxError::IntOutOfRange { .. }),
            "u64::MAX sats must not wrap into i64"
        );
        let mut cs = ChangeSet::default();
        cs.tx_graph.txouts.insert(
            OutPoint { txid, vout: 0 },
            TxOut {
                value: Amount::from_sat(i64::MAX as u64),
                script_pubkey: ScriptBuf::new(),
            },
        );
        TestStore::persist(&mut store, &cs).await?;

        // vout: u32 that does not fit INTEGER must error
        let mut cs = ChangeSet::default();
        cs.tx_graph.txouts.insert(
            OutPoint {
                txid,
                vout: u32::MAX,
            },
            TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::new(),
            },
        );
        assert_matches!(
            TestStore::persist(&mut store, &cs).await,
            Err(BdkSqlxError::IntOutOfRange { .. }),
            "u32::MAX vout must not wrap into i32"
        );
        let mut cs = ChangeSet::default();
        cs.tx_graph.txouts.insert(
            OutPoint {
                txid,
                vout: i32::MAX as u32,
            },
            TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::new(),
            },
        );
        TestStore::persist(&mut store, &cs).await?;

        // block height: u32 that does not fit INTEGER must error
        let mut cs = ChangeSet::default();
        cs.local_chain.blocks.insert(u32::MAX, Some(block_hash(8)));
        assert_matches!(
            TestStore::persist(&mut store, &cs).await,
            Err(BdkSqlxError::IntOutOfRange { .. }),
            "u32::MAX height must not wrap into i32"
        );
        let mut cs = ChangeSet::default();
        cs.local_chain
            .blocks
            .insert(i32::MAX as u32, Some(block_hash(8)));
        TestStore::persist(&mut store, &cs).await?;

        // last_seen: u64 epoch that does not fit BIGINT must error
        let mut cs = ChangeSet::default();
        cs.tx_graph.txs.insert(Arc::new(sample_tx(0, 1_000)));
        cs.tx_graph.last_seen.insert(txid, u64::MAX);
        assert_matches!(
            TestStore::persist(&mut store, &cs).await,
            Err(BdkSqlxError::IntOutOfRange { .. }),
            "u64::MAX last_seen must not wrap into i64"
        );
        let mut cs = ChangeSet::default();
        cs.tx_graph.txs.insert(Arc::new(sample_tx(0, 1_000)));
        cs.tx_graph.last_seen.insert(txid, i64::MAX as u64);
        TestStore::persist(&mut store, &cs).await?;

        // the failed persists rolled back; only the in-range values survive
        let loaded = TestStore::initialize(&mut store).await?;
        assert_eq!(
            loaded.indexer.last_revealed.get(&ext_did),
            Some(&(i32::MAX as u32))
        );
        assert_eq!(loaded.tx_graph.txouts.len(), 2);
        assert_eq!(
            loaded
                .tx_graph
                .txouts
                .get(&OutPoint { txid, vout: 0 })
                .map(|o| o.value),
            Some(Amount::from_sat(i64::MAX as u64))
        );
        assert_eq!(
            loaded.local_chain.blocks.get(&(i32::MAX as u32)),
            Some(&Some(block_hash(8)))
        );
        assert_eq!(
            loaded.tx_graph.last_seen.get(&txid),
            Some(&(i64::MAX as u64))
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Multi-tenancy and hostile input
// ---------------------------------------------------------------------------

/// Wallet names are user-controlled input; they must be treated as data, never
/// as SQL. Names containing injection payloads and unicode must roundtrip and
/// leave the schema intact.
#[tokio::test]
async fn hostile_wallet_names_are_inert() -> anyhow::Result<()> {
    initialize();

    for wallet_name in [
        "'; DROP TABLE bdk_wallet.network; --".to_string(),
        "钱包💰\"'\\;".to_string(),
    ] {
        for mut store in create_test_stores(wallet_name.clone()).await? {
            let cs = populated_changeset();
            TestStore::persist(&mut store, &cs).await?;
            let loaded = TestStore::initialize(&mut store).await?;
            assert_populated(&loaded, &cs);
            assert_eq!(
                table_count(&store, "network", &wallet_name).await?,
                1,
                "schema and rows must survive a hostile wallet name"
            );
        }
    }
    Ok(())
}

/// Two wallets sharing one connection pool must only ever see their own rows.
#[tokio::test]
async fn wallets_sharing_a_pool_are_isolated() -> anyhow::Result<()> {
    initialize();

    let tx_a = sample_tx(0, 50_000);
    let tx_b = sample_tx(1, 30_000);
    let txid_a = tx_a.compute_txid();
    let txid_b = tx_b.compute_txid();

    let mut cs_a = ChangeSet {
        network: Some(Regtest),
        ..Default::default()
    };
    cs_a.tx_graph.txs.insert(Arc::new(tx_a));
    cs_a.local_chain.blocks.insert(5, Some(block_hash(1)));

    let mut cs_b = ChangeSet {
        network: Some(Regtest),
        ..Default::default()
    };
    cs_b.tx_graph.txs.insert(Arc::new(tx_b));

    // postgres: two builders over one pool
    let pool = create_test_pg_pool().await?;
    let pg_a = PgStoreBuilder::new("pg_wallet_a".into())
        .network(Regtest)
        .migrate(true)
        .pool(pool.clone())
        .build()
        .await?;
    let pg_b = PgStoreBuilder::new("pg_wallet_b".into())
        .network(Regtest)
        .migrate(true)
        .pool(pool)
        .build()
        .await?;
    pg_a.write(&cs_a).await?;
    pg_b.write(&cs_b).await?;
    let loaded_a = pg_a.read().await?;
    let loaded_b = pg_b.read().await?;
    assert!(loaded_a
        .tx_graph
        .txs
        .iter()
        .any(|tx| tx.compute_txid() == txid_a));
    assert!(!loaded_a
        .tx_graph
        .txs
        .iter()
        .any(|tx| tx.compute_txid() == txid_b));
    assert!(loaded_b
        .tx_graph
        .txs
        .iter()
        .any(|tx| tx.compute_txid() == txid_b));
    assert!(!loaded_b
        .tx_graph
        .txs
        .iter()
        .any(|tx| tx.compute_txid() == txid_a));

    // sqlite: two stores over one pool
    let lite_a = Store::<Sqlite>::new_with_url(None, "lite_wallet_a".into(), NETWORK, true).await?;
    let lite_b =
        Store::<Sqlite>::new(lite_a.pool.clone(), "lite_wallet_b".into(), NETWORK, true).await?;
    lite_a.write(&cs_a).await?;
    lite_b.write(&cs_b).await?;
    let loaded_a = lite_a.read().await?;
    let loaded_b = lite_b.read().await?;
    assert!(loaded_a
        .tx_graph
        .txs
        .iter()
        .any(|tx| tx.compute_txid() == txid_a));
    assert!(!loaded_a
        .tx_graph
        .txs
        .iter()
        .any(|tx| tx.compute_txid() == txid_b));
    assert!(loaded_b
        .tx_graph
        .txs
        .iter()
        .any(|tx| tx.compute_txid() == txid_b));
    assert!(!loaded_b
        .tx_graph
        .txs
        .iter()
        .any(|tx| tx.compute_txid() == txid_a));

    Ok(())
}

/// Concurrent writers on separate connections of the same pool must both
/// succeed and both land.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_persists_both_land() -> anyhow::Result<()> {
    initialize();

    let tx_a = sample_tx(0, 50_000);
    let tx_b = sample_tx(1, 30_000);
    let txid_a = tx_a.compute_txid();
    let txid_b = tx_b.compute_txid();

    let mut cs_a = ChangeSet {
        network: Some(Regtest),
        ..Default::default()
    };
    cs_a.tx_graph.txs.insert(Arc::new(tx_a));

    let mut cs_b = ChangeSet::default();
    cs_b.tx_graph.txs.insert(Arc::new(tx_b));
    cs_b.tx_graph.last_seen.insert(txid_b, 123);

    let wallet_name = "concurrent_persists_both_land".to_string();
    for store in create_test_stores(wallet_name).await? {
        // Cloning a store shares its connection pool; this also guards the
        // manual `Clone` impl on `Store` (the derived impl was unusable because
        // it bounded `DB: Clone`, which sqlx's marker types don't satisfy).
        let (s1, s2) = match &store {
            TestStore::Postgres(store) => (
                TestStore::Postgres(store.clone()),
                TestStore::Postgres(store.clone()),
            ),
            TestStore::Sqlite(store) => (
                TestStore::Sqlite(store.clone()),
                TestStore::Sqlite(store.clone()),
            ),
        };

        let mut s1 = s1;
        let mut s2 = s2;
        let cs_a2 = cs_a.clone();
        let cs_b2 = cs_b.clone();
        let h1 = tokio::spawn(async move { TestStore::persist(&mut s1, &cs_a2).await });
        let h2 = tokio::spawn(async move { TestStore::persist(&mut s2, &cs_b2).await });
        h1.await??;
        h2.await??;

        let mut store = store;
        let loaded = TestStore::initialize(&mut store).await?;
        assert!(loaded
            .tx_graph
            .txs
            .iter()
            .any(|tx| tx.compute_txid() == txid_a));
        assert!(loaded
            .tx_graph
            .txs
            .iter()
            .any(|tx| tx.compute_txid() == txid_b));
        assert_eq!(loaded.tx_graph.last_seen.get(&txid_b), Some(&123));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Corrupt stored data must fail the load loudly
// ---------------------------------------------------------------------------

/// An unparseable descriptor string in the keychain table must error, not be
/// silently skipped.
#[tokio::test]
async fn corrupt_stored_descriptor_errors_on_load() -> anyhow::Result<()> {
    initialize();

    let (external_desc, internal_desc) = get_test_tr_single_sig_xprv_and_change_desc();
    let wallet_name = wallet_name_from_descriptor(
        external_desc,
        Some(internal_desc),
        NETWORK,
        &Secp256k1::new(),
    )?;

    for mut store in create_test_stores(wallet_name.clone()).await? {
        let cs = ChangeSet {
            network: Some(Regtest),
            descriptor: Some(parse_descriptor(external_desc)),
            ..Default::default()
        };
        TestStore::persist(&mut store, &cs).await?;

        match &store {
            TestStore::Postgres(store) => {
                sqlx::query(
                    r#"UPDATE "bdk_wallet"."keychain" SET descriptor=$2 WHERE wallet_name=$1"#,
                )
                .bind(&wallet_name)
                .bind("wpkh(definitely-not-a-descriptor)")
                .execute(&store.pool)
                .await?;
            }
            TestStore::Sqlite(store) => {
                sqlx::query("UPDATE keychain SET descriptor=$2 WHERE wallet_name=$1")
                    .bind(&wallet_name)
                    .bind("wpkh(definitely-not-a-descriptor)")
                    .execute(&store.pool)
                    .await?;
            }
        }
        assert_matches!(store.read().await, Err(BdkSqlxError::Miniscript(_)));
    }
    Ok(())
}

/// A txid column that is not a valid txid must error on load.
#[tokio::test]
async fn corrupt_stored_txid_errors_on_load() -> anyhow::Result<()> {
    initialize();

    let wallet_name = "corrupt_stored_txid_errors_on_load".to_string();
    for mut store in create_test_stores(wallet_name.clone()).await? {
        let mut cs = ChangeSet {
            network: Some(Regtest),
            ..Default::default()
        };
        cs.tx_graph.txs.insert(Arc::new(sample_tx(0, 1_000)));
        TestStore::persist(&mut store, &cs).await?;

        match &store {
            TestStore::Postgres(store) => {
                sqlx::query(r#"UPDATE "bdk_wallet"."tx" SET txid=$2 WHERE wallet_name=$1"#)
                    .bind(&wallet_name)
                    .bind("not-a-txid")
                    .execute(&store.pool)
                    .await?;
            }
            TestStore::Sqlite(store) => {
                sqlx::query("UPDATE tx SET txid=$2 WHERE wallet_name=$1")
                    .bind(&wallet_name)
                    .bind("not-a-txid")
                    .execute(&store.pool)
                    .await?;
            }
        }
        assert_matches!(store.read().await, Err(BdkSqlxError::HexToArray(_)));
    }
    Ok(())
}

/// A block hash column that is not a valid hash must error on load.
#[tokio::test]
async fn corrupt_stored_block_hash_errors_on_load() -> anyhow::Result<()> {
    initialize();

    let wallet_name = "corrupt_stored_block_hash_errors_on_load".to_string();
    for mut store in create_test_stores(wallet_name.clone()).await? {
        let mut cs = ChangeSet {
            network: Some(Regtest),
            ..Default::default()
        };
        cs.local_chain.blocks.insert(5, Some(block_hash(1)));
        TestStore::persist(&mut store, &cs).await?;

        match &store {
            TestStore::Postgres(store) => {
                sqlx::query(r#"UPDATE "bdk_wallet"."block" SET hash=$2 WHERE wallet_name=$1"#)
                    .bind(&wallet_name)
                    .bind("not-a-block-hash")
                    .execute(&store.pool)
                    .await?;
            }
            TestStore::Sqlite(store) => {
                sqlx::query("UPDATE block SET hash=$2 WHERE wallet_name=$1")
                    .bind(&wallet_name)
                    .bind("not-a-block-hash")
                    .execute(&store.pool)
                    .await?;
            }
        }
        assert_matches!(store.read().await, Err(BdkSqlxError::HexToArray(_)));
    }
    Ok(())
}

/// Negative values in columns whose domain is unsigned must error on load:
/// last_revealed, last_seen, and vout.
#[tokio::test]
async fn negative_stored_values_error_on_load() -> anyhow::Result<()> {
    initialize();

    let (external_desc, internal_desc) = get_test_tr_single_sig_xprv_and_change_desc();
    let wallet_name = wallet_name_from_descriptor(
        external_desc,
        Some(internal_desc),
        NETWORK,
        &Secp256k1::new(),
    )?;
    let txid = sample_tx(0, 1_000).compute_txid();

    for mut store in create_test_stores(wallet_name.clone()).await? {
        let mut cs = ChangeSet {
            network: Some(Regtest),
            descriptor: Some(parse_descriptor(external_desc)),
            ..Default::default()
        };
        cs.tx_graph.txs.insert(Arc::new(sample_tx(0, 1_000)));
        cs.tx_graph.last_seen.insert(txid, 100);
        cs.tx_graph.txouts.insert(
            OutPoint { txid, vout: 0 },
            TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new(),
            },
        );
        TestStore::persist(&mut store, &cs).await?;

        for (pg_sql, lite_sql) in [
            (
                r#"UPDATE "bdk_wallet"."keychain" SET last_revealed=-1 WHERE wallet_name=$1"#,
                "UPDATE keychain SET last_revealed=-1 WHERE wallet_name=$1",
            ),
            (
                r#"UPDATE "bdk_wallet"."tx" SET last_seen=-1 WHERE wallet_name=$1"#,
                "UPDATE tx SET last_seen=-1 WHERE wallet_name=$1",
            ),
            (
                r#"UPDATE "bdk_wallet"."txout" SET vout=-1 WHERE wallet_name=$1"#,
                "UPDATE txout SET vout=-1 WHERE wallet_name=$1",
            ),
        ] {
            match &store {
                TestStore::Postgres(store) => {
                    sqlx::query(pg_sql)
                        .bind(&wallet_name)
                        .execute(&store.pool)
                        .await?;
                    assert_matches!(store.read().await, Err(BdkSqlxError::IntOutOfRange { .. }));
                    sqlx::query(&pg_sql.replace("=-1", "=0"))
                        .bind(&wallet_name)
                        .execute(&store.pool)
                        .await?;
                }
                TestStore::Sqlite(store) => {
                    sqlx::query(lite_sql)
                        .bind(&wallet_name)
                        .execute(&store.pool)
                        .await?;
                    assert_matches!(store.read().await, Err(BdkSqlxError::IntOutOfRange { .. }));
                    sqlx::query(&lite_sql.replace("=-1", "=0"))
                        .bind(&wallet_name)
                        .execute(&store.pool)
                        .await?;
                }
            }
        }

        store.read().await?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Backend construction
// ---------------------------------------------------------------------------

/// Reading/writing a store whose migrations never ran must produce an error,
/// not a panic or silent success.
#[tokio::test]
async fn unmigrated_store_errors() -> anyhow::Result<()> {
    initialize();

    // postgres wraps statement failures in QueryError
    let pool = create_test_pg_pool().await?;
    let store = PgStoreBuilder::new("unmigrated".into())
        .network(Regtest)
        .migrate(false)
        .pool(pool)
        .build()
        .await?;
    assert_matches!(
        store.read().await,
        Err(BdkSqlxError::QueryError { .. }),
        "postgres read on unmigrated schema must error"
    );
    let cs = ChangeSet {
        network: Some(Regtest),
        ..Default::default()
    };
    assert_matches!(
        store.write(&cs).await,
        Err(BdkSqlxError::QueryError { .. }),
        "postgres write on unmigrated schema must error"
    );

    // sqlite propagates the raw sqlx error
    let store = Store::<Sqlite>::new_with_url(None, "unmigrated".into(), NETWORK, false).await?;
    assert_matches!(
        store.read().await,
        Err(BdkSqlxError::Sqlx(_)),
        "sqlite read on unmigrated schema must error"
    );
    assert_matches!(
        store.write(&cs).await,
        Err(BdkSqlxError::Sqlx(_)),
        "sqlite write on unmigrated schema must error"
    );
    Ok(())
}

/// A file-backed sqlite store must keep data across connections.
#[tokio::test]
async fn sqlite_file_backed_store_persists_across_connections() -> anyhow::Result<()> {
    initialize();

    let path = std::env::temp_dir().join(format!(
        "bdk_sqlx_test_{}_{}.sqlite3",
        std::process::id(),
        TEST_DB_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let url = format!("sqlite://{}?mode=rwc", path.display());
    let wallet_name = "sqlite_file_backed".to_string();

    {
        let store =
            Store::<Sqlite>::new_with_url(Some(url.clone()), wallet_name.clone(), NETWORK, true)
                .await?;
        store.write(&populated_changeset()).await?;
    }

    {
        // a fresh pool against the same file; migrate=false proves the schema
        // really lives in the file
        let store =
            Store::<Sqlite>::new_with_url(Some(url.clone()), wallet_name.clone(), NETWORK, false)
                .await?;
        let loaded = store.read().await?;
        assert_populated(&loaded, &populated_changeset());
    }

    std::fs::remove_file(&path)?;
    Ok(())
}

/// Running migrations twice must be a no-op the second time.
#[tokio::test]
async fn postgres_migrate_is_idempotent() -> anyhow::Result<()> {
    initialize();

    let pool = create_test_pg_pool().await?;
    let store = PgStoreBuilder::new("migrate_twice".into())
        .network(Regtest)
        .migrate(true)
        .pool(pool)
        .build()
        .await?;
    store.migrate().await?;
    store.migrate().await?;
    Ok(())
}

/// The builder's URL path must produce a working store end to end.
#[tokio::test]
async fn pg_build_with_url_creates_working_store() -> anyhow::Result<()> {
    initialize();

    let admin_url = env::var("DATABASE_TEST_URL").expect("DATABASE_TEST_URL must be set for tests");
    let admin_pool = Pool::<Postgres>::connect(&admin_url).await?;
    let db_name = format!(
        "bdk_sqlx_test_{}_{}",
        std::process::id(),
        TEST_DB_COUNTER.fetch_add(1, Ordering::Relaxed)
    );

    let base_url = admin_url
        .rsplit_once('/')
        .map(|(base, _)| base)
        .expect("DATABASE_TEST_URL has a database path");
    let store_url = format!("{base_url}/{db_name}");

    // Hold the database-management locks for the whole test: the scratch
    // database's pool has no minimum connections, so without the advisory
    // lock a concurrent cleanup could drop it between operations.
    let _guard = TEST_DB_LOCK.lock().await;
    let mut mgmt = pg_mgmt_lock(&admin_pool).await?;

    let result = async {
        sqlx::query(&format!(r#"CREATE DATABASE "{db_name}""#))
            .execute(&mut *mgmt)
            .await?;

        let result = async {
            let store = PgStoreBuilder::new("with_url".into())
                .network(Regtest)
                .migrate(true)
                .build_with_url(&store_url)
                .await?;
            assert!(store.read().await?.is_empty());
            store.write(&populated_changeset()).await?;
            assert_populated(&store.read().await?, &populated_changeset());
            anyhow::Ok(())
        }
        .await;

        // best-effort cleanup of the scratch database
        let _ = sqlx::query(&format!(r#"DROP DATABASE IF EXISTS "{db_name}""#))
            .execute(&mut *mgmt)
            .await;

        result
    }
    .await;

    pg_mgmt_unlock(mgmt).await;
    result
}

// ---------------------------------------------------------------------------
// Regression tests for previously confirmed defects
//
// Each test below pinned down a bug that has since been fixed. They are kept
// as always-on regression tests guarding the fixed behaviour.
// ---------------------------------------------------------------------------

/// Regression test: `tx.last_seen` was persisted with a bare `UPDATE tx ...`
/// that affected 0 rows when the tx row did not exist, silently dropping the
/// timestamp. The write now upserts a stub row (the schema's nullable
/// `whole_tx` column exists precisely for metadata-only rows).
#[tokio::test]
async fn bug_last_seen_without_tx_row_is_dropped() -> anyhow::Result<()> {
    initialize();

    let txid = sample_tx(0, 1_000).compute_txid();
    let wallet_name = "bug_last_seen_without_tx_row_is_dropped".to_string();
    for mut store in create_test_stores(wallet_name).await? {
        let mut cs = ChangeSet {
            network: Some(Regtest),
            ..Default::default()
        };
        // note: only last_seen, the full tx is not part of this changeset
        cs.tx_graph.last_seen.insert(txid, 1_700_000_000);
        TestStore::persist(&mut store, &cs).await?;

        let loaded = TestStore::initialize(&mut store).await?;
        assert_eq!(
            loaded.tx_graph.last_seen.get(&txid),
            Some(&1_700_000_000),
            "last_seen must survive even when the full tx was never persisted"
        );
    }
    Ok(())
}

/// Regression test: `read()` anchored its entire load on the `network` row,
/// so rows persisted by a changeset that carried no network landed in the
/// database but were invisible to every subsequent read. Reads now fetch the
/// tx/block tables unconditionally.
#[tokio::test]
async fn bug_rows_persisted_before_network_are_invisible() -> anyhow::Result<()> {
    initialize();

    let txid = sample_tx(0, 1_000).compute_txid();
    let wallet_name = "bug_rows_persisted_before_network_are_invisible".to_string();
    for mut store in create_test_stores(wallet_name).await? {
        let mut cs = ChangeSet::default();
        cs.tx_graph.txs.insert(Arc::new(sample_tx(0, 1_000)));
        cs.local_chain.blocks.insert(5, Some(block_hash(1)));
        // deliberately no network in this changeset
        TestStore::persist(&mut store, &cs).await?;

        let loaded = TestStore::initialize(&mut store).await?;
        assert!(
            loaded
                .tx_graph
                .txs
                .iter()
                .any(|tx| tx.compute_txid() == txid),
            "a persisted tx must be visible on load"
        );
        assert_eq!(
            loaded.local_chain.blocks.get(&5),
            Some(&Some(block_hash(1))),
            "a persisted block must be visible on load"
        );
    }
    Ok(())
}

/// Regression test: the block table keys rows by `(wallet_name, hash)` and
/// upserts on the hash, so a changeset mapping the same hash to two heights
/// silently moved the row and lost the other checkpoints. Such changesets are
/// now rejected with `DuplicateBlockHash` instead of being lossily persisted.
#[tokio::test]
async fn bug_same_hash_at_multiple_heights_collapses() -> anyhow::Result<()> {
    initialize();

    let hash = block_hash(7);
    let wallet_name = "bug_same_hash_at_multiple_heights_collapses".to_string();
    for mut store in create_test_stores(wallet_name.clone()).await? {
        let mut cs = ChangeSet {
            network: Some(Regtest),
            ..Default::default()
        };
        cs.local_chain.blocks.insert(1, Some(hash));
        cs.local_chain.blocks.insert(2, Some(hash));
        cs.local_chain.blocks.insert(3, Some(hash));
        assert_matches!(
            TestStore::persist(&mut store, &cs).await,
            Err(BdkSqlxError::DuplicateBlockHash {
                hash: h,
                first_height: 1,
                second_height: 2,
            }) if h == hash,
            "a non-injective block changeset must be rejected"
        );
        assert_eq!(
            table_count(&store, "block", &wallet_name).await?,
            0,
            "the rejected changeset must not leave partial rows behind"
        );

        // the same heights with distinct hashes roundtrip fine
        let mut cs = ChangeSet {
            network: Some(Regtest),
            ..Default::default()
        };
        cs.local_chain.blocks.insert(1, Some(block_hash(1)));
        cs.local_chain.blocks.insert(2, Some(block_hash(2)));
        cs.local_chain.blocks.insert(3, Some(block_hash(3)));
        TestStore::persist(&mut store, &cs).await?;

        let loaded = TestStore::initialize(&mut store).await?;
        assert_eq!(loaded.local_chain.blocks.len(), 3);
        assert_eq!(table_count(&store, "block", &wallet_name).await?, 3);
    }
    Ok(())
}

/// Regression test: the postgres `write()` path never validated
/// `changeset.network` against the configured network, letting a foreign
/// network overwrite the network row and wedge all subsequent reads with
/// `InvalidNetwork`. The write is now rejected up front.
#[tokio::test]
async fn bug_postgres_write_accepts_foreign_network() -> anyhow::Result<()> {
    initialize();

    let pool = create_test_pg_pool().await?;
    let store = PgStoreBuilder::new("bug_foreign_network".into())
        .network(Regtest)
        .migrate(true)
        .pool(pool)
        .build()
        .await?;

    let cs = ChangeSet {
        network: Some(Network::Bitcoin),
        ..Default::default()
    };

    // a store configured for regtest must refuse to persist a bitcoin row
    assert_matches!(
        store.write(&cs).await,
        Err(_),
        "write() must reject a changeset for a different network"
    );
    // and the store must still be readable afterwards
    assert!(store.read().await?.is_empty());
    Ok(())
}

/// Regression test: both schemas declared `keychain.last_revealed INTEGER
/// DEFAULT 0`, so a wallet persisted before ever revealing an address reloaded
/// with `last_revealed = Some(0)` instead of `None` and skipped index 0
/// forever. New rows now store NULL explicitly (and migration 04 drops the
/// default), matching upstream bdk's semantics.
///
/// Note: no data migration rewrites existing rows -- a stored `0` is ambiguous
/// ("revealed index 0" vs "never revealed") and guessing could cause address
/// reuse. Only new rows are protected.
#[tokio::test]
async fn bug_unrevealed_wallet_reloads_skipping_index_zero() -> anyhow::Result<()> {
    initialize();

    let (external_desc, internal_desc) = get_test_tr_single_sig_xprv_and_change_desc();
    let wallet_name = wallet_name_from_descriptor(
        external_desc,
        Some(internal_desc),
        NETWORK,
        &Secp256k1::new(),
    )?;

    for mut store in create_test_stores(wallet_name).await? {
        let mut wallet = Wallet::create(external_desc, internal_desc)
            .network(NETWORK)
            .create_wallet_async(&mut store)
            .await?;
        // never reveal anything; the creation changeset is already persisted
        assert_eq!(wallet.derivation_index(External), None);
        assert_eq!(wallet.reveal_next_address(External).index, 0);

        let mut loaded = Wallet::load()
            .load_wallet_async(&mut store)
            .await?
            .expect("wallet must exist");
        assert_eq!(
            loaded.derivation_index(External),
            None,
            "a never-revealed wallet must reload with no derivation index"
        );
        assert_eq!(
            loaded.reveal_next_address(External).index,
            0,
            "a reloaded wallet must not skip address index 0"
        );
    }
    Ok(())
}

/// Regression test: `update_last_revealed` was a plain `UPDATE`, so a stale or
/// replayed changeset moved `last_revealed` BACKWARDS and the next load
/// silently re-revealed already handed-out addresses. The update now never
/// decreases the stored value.
#[tokio::test]
async fn bug_last_revealed_regresses_causing_address_reuse() -> anyhow::Result<()> {
    initialize();

    let (external_desc, internal_desc) = get_test_tr_single_sig_xprv_and_change_desc();
    let wallet_name = wallet_name_from_descriptor(
        external_desc,
        Some(internal_desc),
        NETWORK,
        &Secp256k1::new(),
    )?;

    for mut store in create_test_stores(wallet_name).await? {
        let mut wallet = Wallet::create(external_desc, internal_desc)
            .network(NETWORK)
            .create_wallet_async(&mut store)
            .await?;
        let _ = wallet.reveal_addresses_to(External, 5);
        assert!(wallet.persist_async(&mut store).await?);

        // a stale changeset (replayed backup, older app instance) regresses
        // the derivation state to 2
        let mut stale = ChangeSet::default();
        stale
            .indexer
            .last_revealed
            .insert(parse_descriptor(external_desc).descriptor_id(), 2);
        TestStore::persist(&mut store, &stale).await?;

        let loaded = Wallet::load()
            .load_wallet_async(&mut store)
            .await?
            .expect("wallet must exist");
        assert_eq!(
            loaded.derivation_index(External),
            Some(5),
            "last_revealed must never move backwards"
        );
    }
    Ok(())
}

/// Regression test: `Store::<Postgres>::read` claimed "a consistent snapshot"
/// from running inside one transaction, but postgres ran it at the default
/// READ COMMITTED
/// isolation, which takes a NEW snapshot for every statement, so a writer
/// committing between the keychain SELECT and the tx/block SELECTs produced a
/// mixed-generation changeset. `Store::read` now opens its transaction with
/// REPEATABLE READ; this test pins the mechanism deterministically.
#[tokio::test]
async fn bug_postgres_read_tx_is_not_snapshot_consistent() -> anyhow::Result<()> {
    initialize();

    let pool = create_test_pg_pool().await?;
    let _store = PgStoreBuilder::new("isolation_demo".into())
        .network(Regtest)
        .migrate(true)
        .pool(pool.clone())
        .build()
        .await?;

    // one REPEATABLE READ transaction, two identical statements, a concurrent
    // commit in between -- the second statement must see the same snapshot
    let mut read_tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *read_tx)
        .await?;
    let before: i64 = sqlx::query_scalar(r#"SELECT count(*) FROM "bdk_wallet"."block""#)
        .fetch_one(&mut *read_tx)
        .await?;

    sqlx::query(
        r#"INSERT INTO "bdk_wallet"."block" (wallet_name, hash, height) VALUES ('isolation_demo', $1, 1)"#,
    )
    .bind(block_hash(9).to_string())
    .execute(&pool)
    .await?;

    let after: i64 = sqlx::query_scalar(r#"SELECT count(*) FROM "bdk_wallet"."block""#)
        .fetch_one(&mut *read_tx)
        .await?;
    read_tx.rollback().await?;

    assert_eq!(
        before, after,
        "statements inside one read transaction must observe a single snapshot"
    );
    Ok(())
}
/// Migration 04 upgrade path: a database created with the old 01-03 schema
/// (with `last_revealed INTEGER DEFAULT 0`) must keep its data verbatim when 04
/// is applied -- the ambiguous stored 0s are NOT rewritten -- and afterwards
/// new rows must default to NULL instead of 0.
#[tokio::test]
async fn migration_04_preserves_data_and_drops_default() -> anyhow::Result<()> {
    initialize();

    // sqlite: 01-03 by hand, old-schema rows, then 04
    let path = std::env::temp_dir().join(format!(
        "bdk_sqlx_mig04_{}_{}.sqlite3",
        std::process::id(),
        TEST_DB_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let url = format!("sqlite://{}?mode=rwc", path.display());
    let pool = sqlx::SqlitePool::connect(&url).await?;
    for file in [
        "01_bdk_wallet.sql",
        "02_anchor_tx_on_delete_cascade.sql",
        "03_block_unique_height.sql",
    ] {
        let sql = std::fs::read_to_string(format!("migrations/sqlite/{file}"))?;
        sqlx::raw_sql(&sql).execute(&pool).await?;
    }
    // an old-schema row relying on DEFAULT 0 (never revealed) and one with a
    // real revealed index
    sqlx::query("INSERT INTO keychain (wallet_name, keychainkind, descriptor, descriptor_id) VALUES ('w','External','d1',x'01')").execute(&pool).await?;
    sqlx::query("INSERT INTO keychain (wallet_name, keychainkind, descriptor, descriptor_id, last_revealed) VALUES ('w','Internal','d2',x'02',9)").execute(&pool).await?;
    let default_row: Option<i32> =
        sqlx::query_scalar("SELECT last_revealed FROM keychain WHERE keychainkind='External'")
            .fetch_one(&pool)
            .await?;
    assert_eq!(default_row, Some(0), "old schema must have DEFAULT 0");

    let sql04 =
        std::fs::read_to_string("migrations/sqlite/04_keychain_last_revealed_drop_default.sql")?;
    sqlx::raw_sql(&sql04).execute(&pool).await?;

    let ext: Option<i32> =
        sqlx::query_scalar("SELECT last_revealed FROM keychain WHERE keychainkind='External'")
            .fetch_one(&pool)
            .await?;
    let int: Option<i32> =
        sqlx::query_scalar("SELECT last_revealed FROM keychain WHERE keychainkind='Internal'")
            .fetch_one(&pool)
            .await?;
    assert_eq!(ext, Some(0), "existing 0 must NOT be rewritten (ambiguous)");
    assert_eq!(int, Some(9), "revealed index must survive the rebuild");
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM keychain")
        .fetch_one(&pool)
        .await?;
    assert_eq!(rows, 2);

    sqlx::query("INSERT INTO keychain (wallet_name, keychainkind, descriptor, descriptor_id) VALUES ('w2','External','d3',x'03')").execute(&pool).await?;
    let new_row: Option<i32> =
        sqlx::query_scalar("SELECT last_revealed FROM keychain WHERE wallet_name='w2'")
            .fetch_one(&pool)
            .await?;
    assert_eq!(new_row, None, "new rows must default to NULL after 04");
    drop(pool);
    std::fs::remove_file(&path)?;

    // postgres: same upgrade path
    let pool = create_test_pg_pool().await?;
    for file in [
        "01_bdk_wallet.sql",
        "02_anchor_tx_on_delete_cascade.sql",
        "03_block_unique_height.sql",
    ] {
        let sql = std::fs::read_to_string(format!("migrations/postgres/{file}"))?;
        sqlx::raw_sql(&sql).execute(&pool).await?;
    }
    sqlx::query(r#"INSERT INTO "bdk_wallet"."keychain" (wallet_name, keychainkind, descriptor, descriptor_id) VALUES ('w','External','d1','\x01'::bytea)"#).execute(&pool).await?;
    sqlx::query(r#"INSERT INTO "bdk_wallet"."keychain" (wallet_name, keychainkind, descriptor, descriptor_id, last_revealed) VALUES ('w','Internal','d2','\x02'::bytea,9)"#).execute(&pool).await?;
    let default_row: Option<i32> = sqlx::query_scalar(
        r#"SELECT last_revealed FROM "bdk_wallet"."keychain" WHERE keychainkind='External'"#,
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(default_row, Some(0), "old schema must have DEFAULT 0");

    let sql04 =
        std::fs::read_to_string("migrations/postgres/04_keychain_last_revealed_drop_default.sql")?;
    sqlx::raw_sql(&sql04).execute(&pool).await?;

    let ext: Option<i32> = sqlx::query_scalar(
        r#"SELECT last_revealed FROM "bdk_wallet"."keychain" WHERE keychainkind='External'"#,
    )
    .fetch_one(&pool)
    .await?;
    let int: Option<i32> = sqlx::query_scalar(
        r#"SELECT last_revealed FROM "bdk_wallet"."keychain" WHERE keychainkind='Internal'"#,
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(ext, Some(0), "existing 0 must NOT be rewritten (ambiguous)");
    assert_eq!(int, Some(9), "revealed index must survive");

    sqlx::query(r#"INSERT INTO "bdk_wallet"."keychain" (wallet_name, keychainkind, descriptor, descriptor_id) VALUES ('w2','External','d3','\x03'::bytea)"#).execute(&pool).await?;
    let new_row: Option<i32> = sqlx::query_scalar(
        r#"SELECT last_revealed FROM "bdk_wallet"."keychain" WHERE wallet_name='w2'"#,
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(new_row, None, "new rows must default to NULL after 04");
    Ok(())
}

/// Regression test: reads anchored keychain rows on the `network` row, so a
/// changeset carrying descriptors (and derivation state) but no network wrote
/// rows that every subsequent read silently skipped -- the same defect class
/// as the tx/block invisibility bug, one table over. Keychain rows are now
/// read unconditionally, like the tx/block tables.
#[tokio::test]
async fn keychain_persisted_without_network_roundtrips() -> anyhow::Result<()> {
    initialize();

    let (external_desc, internal_desc) = get_test_tr_single_sig_xprv_and_change_desc();
    let ext = parse_descriptor(external_desc);
    let int = parse_descriptor(internal_desc);
    let ext_did = ext.descriptor_id();

    let wallet_name = "keychain_persisted_without_network_roundtrips".to_string();
    for mut store in create_test_stores(wallet_name).await? {
        let mut cs = ChangeSet {
            descriptor: Some(ext.clone()),
            change_descriptor: Some(int.clone()),
            ..Default::default()
        };
        cs.indexer.last_revealed.insert(ext_did, 3);
        // deliberately no network in this changeset
        TestStore::persist(&mut store, &cs).await?;

        let loaded = TestStore::initialize(&mut store).await?;
        assert_eq!(loaded.network, None);
        assert_eq!(
            loaded.descriptor,
            Some(ext.clone()),
            "a descriptor persisted without a network must be visible on load"
        );
        assert_eq!(loaded.change_descriptor, Some(int.clone()));
        assert_eq!(loaded.indexer.last_revealed.get(&ext_did), Some(&3));
    }
    Ok(())
}

/// Regression test: the sqlite backend had no network validation at all -- it
/// accepted and loaded data for any network, while postgres rejects foreign
/// networks on write and validates the stored network on read. The sqlite
/// store now takes the process-global network at construction and applies the
/// same guards.
#[tokio::test]
async fn sqlite_store_enforces_configured_network() -> anyhow::Result<()> {
    initialize();

    let wallet_name = "sqlite_store_enforces_configured_network".to_string();
    let store = Store::<Sqlite>::new_with_url(None, wallet_name.clone(), NETWORK, true).await?;

    // a write carrying a foreign network is rejected, and the store survives
    let cs = ChangeSet {
        network: Some(Network::Bitcoin),
        ..Default::default()
    };
    assert_matches!(
        store.write(&cs).await,
        Err(BdkSqlxError::InvalidNetwork { .. }),
        "sqlite write must reject a changeset for a different network"
    );
    assert!(store.read().await?.is_empty());

    // data for the configured network roundtrips
    store
        .write(&ChangeSet {
            network: Some(NETWORK),
            ..Default::default()
        })
        .await?;
    assert_eq!(store.read().await?.network, Some(NETWORK));

    // a foreign network written behind the store's back fails the load
    sqlx::query("UPDATE network SET name=$2 WHERE wallet_name=$1")
        .bind(&wallet_name)
        .bind("bitcoin")
        .execute(&store.pool)
        .await?;
    assert_matches!(
        store.read().await,
        Err(BdkSqlxError::InvalidNetwork { .. }),
        "sqlite read must reject a stored foreign network"
    );
    Ok(())
}

/// Regression test: `insert_descriptor`'s conflict update kept the stored
/// `last_revealed` unconditionally, so replacing a descriptor under the same
/// (wallet_name, keychainkind) made the NEW descriptor inherit the old
/// derivation index -- the wallet would silently skip those addresses on
/// load. The keep is now conditional on the descriptor being unchanged.
#[tokio::test]
async fn descriptor_rotation_resets_last_revealed() -> anyhow::Result<()> {
    initialize();

    let (external_desc, _) = get_test_tr_single_sig_xprv_and_change_desc();
    let other_desc = get_test_wpkh();
    let ext = parse_descriptor(external_desc);
    let other = parse_descriptor(other_desc);
    let ext_did = ext.descriptor_id();

    let wallet_name = "descriptor_rotation_resets_last_revealed".to_string();
    for mut store in create_test_stores(wallet_name).await? {
        let mut cs = ChangeSet {
            network: Some(Regtest),
            descriptor: Some(ext.clone()),
            ..Default::default()
        };
        cs.indexer.last_revealed.insert(ext_did, 5);
        TestStore::persist(&mut store, &cs).await?;

        // re-persisting the SAME descriptor keeps the derivation state
        TestStore::persist(&mut store, &cs).await?;
        let loaded = TestStore::initialize(&mut store).await?;
        assert_eq!(loaded.indexer.last_revealed.get(&ext_did), Some(&5));

        // replacing the descriptor resets the derivation state
        let rotated = ChangeSet {
            descriptor: Some(other.clone()),
            ..Default::default()
        };
        TestStore::persist(&mut store, &rotated).await?;
        let loaded = TestStore::initialize(&mut store).await?;
        assert_eq!(loaded.descriptor, Some(other.clone()));
        assert!(
            loaded.indexer.last_revealed.is_empty(),
            "a replaced descriptor must not inherit the old derivation index"
        );
    }
    Ok(())
}

/// A keychainkind value the store never writes is corrupt data and must fail
/// the load loudly rather than silently drop the keychain.
#[tokio::test]
async fn corrupt_keychainkind_errors_on_load() -> anyhow::Result<()> {
    initialize();

    let (external_desc, _) = get_test_tr_single_sig_xprv_and_change_desc();
    let ext = parse_descriptor(external_desc);
    let wallet_name = "corrupt_keychainkind_errors_on_load".to_string();

    for mut store in create_test_stores(wallet_name.clone()).await? {
        let cs = ChangeSet {
            network: Some(Regtest),
            descriptor: Some(ext.clone()),
            ..Default::default()
        };
        TestStore::persist(&mut store, &cs).await?;

        match &store {
            TestStore::Postgres(store) => {
                sqlx::query(
                    r#"UPDATE "bdk_wallet"."keychain" SET keychainkind=$2 WHERE wallet_name=$1"#,
                )
                .bind(&wallet_name)
                .bind("Bogus")
                .execute(&store.pool)
                .await?;
            }
            TestStore::Sqlite(store) => {
                sqlx::query("UPDATE keychain SET keychainkind=$2 WHERE wallet_name=$1")
                    .bind(&wallet_name)
                    .bind("Bogus")
                    .execute(&store.pool)
                    .await?;
            }
        }
        assert_matches!(
            store.read().await,
            Err(BdkSqlxError::InvalidKeychainKind { .. })
        );
    }
    Ok(())
}

/// Migration 05 drops the dead `version` table and the redundant
/// `idx_block_height` index; the store must keep working afterwards.
#[tokio::test]
async fn migration_05_drops_dead_schema() -> anyhow::Result<()> {
    initialize();

    let wallet_name = "migration_05_drops_dead_schema".to_string();
    for mut store in create_test_stores(wallet_name.clone()).await? {
        match &store {
            TestStore::Postgres(store) => {
                let version_exists: bool = sqlx::query_scalar(
                    "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='bdk_wallet' AND table_name='version')",
                )
                .fetch_one(&store.pool)
                .await?;
                assert!(!version_exists, "version table must be dropped");
                let idx_exists: bool = sqlx::query_scalar(
                    "SELECT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname='bdk_wallet' AND indexname='idx_block_height')",
                )
                .fetch_one(&store.pool)
                .await?;
                assert!(!idx_exists, "idx_block_height must be dropped");
            }
            TestStore::Sqlite(store) => {
                let objects: Vec<String> = sqlx::query_scalar(
                    "SELECT name FROM sqlite_master WHERE name IN ('version','idx_block_height')",
                )
                .fetch_all(&store.pool)
                .await?;
                assert!(
                    objects.is_empty(),
                    "dead schema objects must be dropped: {objects:?}"
                );
            }
        }

        // the store still roundtrips every table
        let cs = populated_changeset();
        TestStore::persist(&mut store, &cs).await?;
        assert_populated(&TestStore::initialize(&mut store).await?, &cs);
    }
    Ok(())
}
