#![allow(unused)]
use crate::{BdkSqlxError, FutureResult, Store};
use assert_matches::assert_matches;
use bdk_chain::bitcoin::constants::ChainHash;
use bdk_chain::bitcoin::hashes::Hash;
use bdk_chain::bitcoin::secp256k1::Secp256k1;
use bdk_chain::bitcoin::Network::Signet;
use bdk_chain::bitcoin::{BlockHash, Network};
use bdk_chain::miniscript::{Descriptor, DescriptorPublicKey};
use bdk_chain::BlockId;
use bdk_electrum::{electrum_client, BdkElectrumClient};
use bdk_testenv::bitcoincore_rpc::RpcApi;
use bdk_testenv::TestEnv;
use bdk_wallet::{
    descriptor,
    descriptor::ExtendedDescriptor,
    wallet_name_from_descriptor, AsyncWalletPersister, ChangeSet,
    KeychainKind::{self, *},
    LoadError, LoadMismatch, LoadWithPersistError, Wallet,
};
use better_panic::Settings;
use sqlx::{Database, PgPool, Pool, Postgres, Sqlite, SqlitePool};
use std::collections::HashSet;
use std::env;
use std::io::Write;
use std::ops::Deref;
use std::sync::Arc;
use std::sync::Once;
use std::time::Duration;
use tracing::info;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

pub fn get_test_tr_single_sig_xprv_with_change_desc() -> (&'static str, &'static str) {
    ("tr(tprv8ZgxMBicQKsPdDArR4xSAECuVxeX1jwwSXR4ApKbkYgZiziDc4LdBy2WvJeGDfUSE4UT4hHhbgEwbdq8ajjUHiKDegkwrNU6V55CxcxonVN/0/*)",
        "tr(tprv8ZgxMBicQKsPdDArR4xSAECuVxeX1jwwSXR4ApKbkYgZiziDc4LdBy2WvJeGDfUSE4UT4hHhbgEwbdq8ajjUHiKDegkwrNU6V55CxcxonVN/1/*)")
}

pub fn get_test_tr_single_sig_xprv() -> &'static str {
    "tr(tprv8ZgxMBicQKsPdDArR4xSAECuVxeX1jwwSXR4ApKbkYgZiziDc4LdBy2WvJeGDfUSE4UT4hHhbgEwbdq8ajjUHiKDegkwrNU6V55CxcxonVN/*)"
}

pub fn get_test_wpkh() -> &'static str {
    "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)"
}

const NETWORK: Network = Signet;
const STOP_GAP: usize = 10;
const BATCH_SIZE: usize = 1;

fn parse_descriptor(s: &str) -> ExtendedDescriptor {
    <Descriptor<DescriptorPublicKey>>::parse_descriptor(&Secp256k1::new(), s)
        .unwrap()
        .0
}

static INIT: Once = Once::new();

// This must only be called once.
fn initialize() {
    INIT.call_once(|| {
        tracing_subscriber::registry()
            .with(EnvFilter::new(
                env::var("RUST_LOG").unwrap_or_else(|_| "sqlx=warn,bdk_sqlx=info".into()),
            ))
            .with(tracing_subscriber::fmt::layer())
            .try_init()
            .expect("setup tracing");
    });
}

trait DropAll {
    async fn drop_all(&self) -> anyhow::Result<()>;
}

impl DropAll for Pool<Postgres> {
    /// Drops all tables.
    ///
    /// Clean up (optional, depending on your test database strategy)
    /// You might want to delete the test wallet from the database here.
    #[tracing::instrument]
    async fn drop_all(&self) -> anyhow::Result<()> {
        let drop_statements = vec![
            "DROP TABLE IF EXISTS _sqlx_migrations",
            "DROP TABLE IF EXISTS vault_addresses",
            "DROP TABLE IF EXISTS used_anchorwatch_keys",
            "DROP TABLE IF EXISTS anchorwatch_keys",
            "DROP TABLE IF EXISTS psbts",
            "DROP TABLE IF EXISTS whitelist_update",
            "DROP TABLE IF EXISTS vault_parameters",
            "DROP TABLE IF EXISTS users",
            "DROP TABLE IF EXISTS version",
            "DROP TABLE IF EXISTS anchor_tx",
            "DROP TABLE IF EXISTS txout",
            "DROP TABLE IF EXISTS tx",
            "DROP TABLE IF EXISTS block",
            "DROP TABLE IF EXISTS keychain",
            "DROP TABLE IF EXISTS network",
        ];

        let mut tx = self.begin().await?;

        for statement in drop_statements {
            sqlx::query(statement).execute(&mut *tx).await?;
        }

        tx.commit().await?;

        Ok(())
    }
}

#[derive(Debug)]
enum TestStore {
    Postgres(Store<Postgres>),
    Sqlite(Store<Sqlite>),
}

impl AsyncWalletPersister for TestStore {
    type Error = BdkSqlxError;

    #[tracing::instrument]
    fn initialize<'a>(store: &'a mut Self) -> FutureResult<'a, ChangeSet, Self::Error>
    where
        Self: 'a,
    {
        info!("initialize test store");
        match store {
            TestStore::Postgres(store) => Box::pin(store.migrate_and_read()),
            TestStore::Sqlite(store) => Box::pin(store.migrate_and_read()),
        }
    }

    #[tracing::instrument]
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

async fn create_test_stores(wallet_name: String) -> anyhow::Result<Vec<TestStore>> {
    let mut stores: Vec<TestStore> = Vec::new();

    // Set up postgres database URL (you might want to use a test-specific database)
    let url = env::var("DATABASE_TEST_URL").expect("DATABASE_TEST_URL must be set for tests");
    let pool = Pool::<Postgres>::connect(&url.clone()).await?;
    // Drop all before creating new store for testing
    pool.drop_all().await?;
    let postgres_store =
        Store::<Postgres>::new_with_url(url.clone(), Some(wallet_name.clone())).await?;
    stores.push(TestStore::Postgres(postgres_store));

    // Setup sqlite in-memory database
    let pool = SqlitePool::connect(":memory:").await?;
    let sqlite_store = Store::<Sqlite>::new(pool.clone(), Some(wallet_name.clone()), true).await?;
    stores.push(TestStore::Sqlite(sqlite_store));

    Ok(stores)
}

#[tracing::instrument]
#[tokio::test]
async fn wallet_is_persisted() -> anyhow::Result<()> {
    Settings::debug()
        .most_recent_first(false)
        .lineno_suffix(true)
        .install();

    initialize();

    // Define descriptors (you may need to adjust these based on your exact requirements)
    let (external_desc, internal_desc) = get_test_tr_single_sig_xprv_with_change_desc();
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
async fn wallet_load_checks() -> anyhow::Result<()> {
    Settings::debug()
        .most_recent_first(false)
        .lineno_suffix(true)
        .install();

    // Define descriptors (you may need to adjust these based on your exact requirements)
    let (external_desc, internal_desc) = get_test_tr_single_sig_xprv_with_change_desc();
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
        let mut wallet = Wallet::create(external_desc, internal_desc)
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
    Settings::debug()
        .most_recent_first(false)
        .lineno_suffix(true)
        .install();

    // Define descriptors
    let desc = get_test_tr_single_sig_xprv();

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
            let secp = wallet.secp_ctx();
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

#[tracing::instrument]
#[tokio::test]
async fn two_wallets_load() -> anyhow::Result<()> {
    Settings::debug()
        .most_recent_first(false)
        .lineno_suffix(true)
        .install();

    // Define descriptors
    let (external_desc_wallet_1, internal_desc_wallet_1) =
        get_test_tr_single_sig_xprv_with_change_desc();
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
        let _ = wallet_2.insert_checkpoint(block).unwrap();
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
        // FIXME: see https://github.com/bitcoindevkit/bdk-sqlx/pull/10
        // assert_ne!(
        //     wallet_1.derivation_index(Internal),
        //     wallet_2.derivation_index(Internal),
        //     "different wallets should not have same derivation index"
        // );
        // assert_ne!(
        //     wallet_1.latest_checkpoint(),
        //     wallet_2.latest_checkpoint(),
        //     "different wallets should not have same chain tip"
        // );
    }

    Ok(())
}

#[tracing::instrument]
#[tokio::test]
async fn sync_with_electrum() -> anyhow::Result<()> {
    Settings::debug()
        .most_recent_first(false)
        .lineno_suffix(true)
        .install();

    // Define descriptors (you may need to adjust these based on your exact requirements)
    let (external_desc, internal_desc) = get_test_tr_single_sig_xprv_with_change_desc();
    // Generate a unique name for this test wallet
    let wallet_name = wallet_name_from_descriptor(
        external_desc,
        Some(internal_desc),
        Network::Regtest,
        &Secp256k1::new(),
    )?;

    let stores = create_test_stores(wallet_name).await?;
    for mut store in stores {
        let mut wallet = Wallet::create(external_desc, internal_desc)
            .network(Network::Regtest)
            .create_wallet_async(&mut store)
            .await?;

        // mine blocks and sync with electrum
        let env = TestEnv::new()?;
        let electrum_client = electrum_client::Client::new(env.electrsd.electrum_url.as_str())?;
        let client = BdkElectrumClient::new(electrum_client);
        let _hashes = env.mine_blocks(9, None)?;
        env.wait_until_electrum_sees_block(Duration::from_secs(10))?;
        let new_tip_height: u32 = env.rpc_client().get_block_count()?.try_into().unwrap();
        assert_eq!(new_tip_height, 10);

        let request = wallet.start_full_scan();
        let update = client.full_scan(request, STOP_GAP, BATCH_SIZE, false)?;
        wallet.apply_update(update)?;
        assert!(wallet.persist_async(&mut store).await?);

        // Recover the wallet
        let wallet = Wallet::load().load_wallet_async(&mut store).await?.unwrap();
        assert_eq!(wallet.latest_checkpoint().height(), new_tip_height);
    }

    Ok(())
}
