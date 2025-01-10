use crate::{BdkSqlxError, FutureResult, Store};
use assert_matches::assert_matches;
use bdk_wallet::bitcoin::constants::ChainHash;
use bdk_wallet::bitcoin::hashes::Hash;
use bdk_wallet::bitcoin::secp256k1::Secp256k1;
use bdk_wallet::bitcoin::Network::{Regtest, Signet};
use bdk_wallet::bitcoin::{
    transaction, Address, Amount, BlockHash, Network, OutPoint, Transaction, TxIn, TxOut, Txid,
};
use bdk_wallet::chain::{tx_graph, BlockId, ConfirmationBlockTime};
use bdk_wallet::miniscript::{Descriptor, DescriptorPublicKey};
use bdk_wallet::{
    bitcoin, descriptor::ExtendedDescriptor, wallet_name_from_descriptor, AsyncWalletPersister,
    Balance, ChangeSet, KeychainKind::*, LoadError, LoadMismatch, LoadWithPersistError, Update,
    Wallet,
};
use sqlx::{Pool, Postgres, Sqlite, SqlitePool};
use std::env;
use std::ops::Add;
use std::str::FromStr;
use std::sync::Once;
use tracing::info;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

pub fn get_test_minisicript_with_change_desc() -> (&'static str, &'static str) {
    ("wsh(andor(multi(2,[a0d3c79c/48'/1'/79'/2']tpubDEsGdqFaKUVnVNZZw8AixJ8C3yD8o6nN7hsdLfbtVRDTk3PNrQ2pcWNWNbxhdcNSgQP25pUpgRQ7qiVtN3YvSzACKizrvzSwH9SQ2Bjbbwt/0/*,[ea2484f9/48'/1'/79'/2']tpubDFjkswBXoRHKkvmHsxv4xdDqbjg1peX9zJytLeSLbXuwVgYhXgbABzC2r5MAWxqWoaUr7hWGW5TPjA9sNvxa3mX6DrNBdynDsEvwDoXGFpm/0/*,[93f245d7/48'/1'/79'/2']tpubDEVnR72gRgTsqaPFMacV6fCfaSEe56gcDomuGhk9MFeUdEi18riJCokgsZr2x1KKGRM59TJ4AQ6FuNun3khh95ceoH2ytN13nVD7yDLP5LJ/0/*),or_i(and_v(v:pkh([61cdf766/48'/1'/79'/2']tpubDEXETCw2WurhazfW5gW1z4njP6yLXDQmCGfjWGP5k3BuTQ5iZqovMr1zz1zWPhDMRn11hXGpZHodus1LysXnwREsD1ig96M24JhQCpPPpf6/0/*),after(1753228800)),thresh(2,pk([39bf48a9/48'/1'/0'/2']tpubDEr9rVFQbT1keErwxb6GuGy3RM6TEACSkFxBgziUvrDprYuM1Wm7wi6jb1gcaLrSgk6MSkGx84dS2kQQwJKxGRJ59rAvmuKTU7E3saHJLf5/0/*),s:pk([9467fdb3/48'/1'/0'/2']tpubDFEjX5BY88AbWpshPwGscwgKLtcCjeVodMbmhS6D6cbz1eGNUs3546ephbVmbHpxEhbCDrezGmFBArLxBKzPEfBcBdzQuncPm8ww2xa6UUQ/0/*),s:pk([01adf45e/48'/1'/0'/2']tpubDFPYZPeShApyWndvDUtpLSjDHGYK4tTT4BkMyTukGqbP9AXQeQhiWsbwEzyZhxgud9ZPew1FPsoLbWjfnE3veSXLeU4ViofrhVAHNXtjQWE/0/*),snl:after(1739836800))),and_v(v:thresh(2,pkh([39bf48a9/48'/1'/0'/2']tpubDEr9rVFQbT1keErwxb6GuGy3RM6TEACSkFxBgziUvrDprYuM1Wm7wi6jb1gcaLrSgk6MSkGx84dS2kQQwJKxGRJ59rAvmuKTU7E3saHJLf5/2/*),a:pkh([9467fdb3/48'/1'/0'/2']tpubDFEjX5BY88AbWpshPwGscwgKLtcCjeVodMbmhS6D6cbz1eGNUs3546ephbVmbHpxEhbCDrezGmFBArLxBKzPEfBcBdzQuncPm8ww2xa6UUQ/2/*),a:pkh([01adf45e/48'/1'/0'/2']tpubDFPYZPeShApyWndvDUtpLSjDHGYK4tTT4BkMyTukGqbP9AXQeQhiWsbwEzyZhxgud9ZPew1FPsoLbWjfnE3veSXLeU4ViofrhVAHNXtjQWE/2/*)),after(1757116800))))",
     "wsh(andor(multi(2,[a0d3c79c/48'/1'/79'/2']tpubDEsGdqFaKUVnVNZZw8AixJ8C3yD8o6nN7hsdLfbtVRDTk3PNrQ2pcWNWNbxhdcNSgQP25pUpgRQ7qiVtN3YvSzACKizrvzSwH9SQ2Bjbbwt/1/*,[ea2484f9/48'/1'/79'/2']tpubDFjkswBXoRHKkvmHsxv4xdDqbjg1peX9zJytLeSLbXuwVgYhXgbABzC2r5MAWxqWoaUr7hWGW5TPjA9sNvxa3mX6DrNBdynDsEvwDoXGFpm/1/*,[93f245d7/48'/1'/79'/2']tpubDEVnR72gRgTsqaPFMacV6fCfaSEe56gcDomuGhk9MFeUdEi18riJCokgsZr2x1KKGRM59TJ4AQ6FuNun3khh95ceoH2ytN13nVD7yDLP5LJ/1/*),or_i(and_v(v:pkh([61cdf766/48'/1'/79'/2']tpubDEXETCw2WurhazfW5gW1z4njP6yLXDQmCGfjWGP5k3BuTQ5iZqovMr1zz1zWPhDMRn11hXGpZHodus1LysXnwREsD1ig96M24JhQCpPPpf6/1/*),after(1753228800)),thresh(2,pk([39bf48a9/48'/1'/0'/2']tpubDEr9rVFQbT1keErwxb6GuGy3RM6TEACSkFxBgziUvrDprYuM1Wm7wi6jb1gcaLrSgk6MSkGx84dS2kQQwJKxGRJ59rAvmuKTU7E3saHJLf5/1/*),s:pk([9467fdb3/48'/1'/0'/2']tpubDFEjX5BY88AbWpshPwGscwgKLtcCjeVodMbmhS6D6cbz1eGNUs3546ephbVmbHpxEhbCDrezGmFBArLxBKzPEfBcBdzQuncPm8ww2xa6UUQ/1/*),s:pk([01adf45e/48'/1'/0'/2']tpubDFPYZPeShApyWndvDUtpLSjDHGYK4tTT4BkMyTukGqbP9AXQeQhiWsbwEzyZhxgud9ZPew1FPsoLbWjfnE3veSXLeU4ViofrhVAHNXtjQWE/1/*),snl:after(1739836800))),and_v(v:thresh(2,pkh([39bf48a9/48'/1'/0'/2']tpubDEr9rVFQbT1keErwxb6GuGy3RM6TEACSkFxBgziUvrDprYuM1Wm7wi6jb1gcaLrSgk6MSkGx84dS2kQQwJKxGRJ59rAvmuKTU7E3saHJLf5/3/*),a:pkh([9467fdb3/48'/1'/0'/2']tpubDFEjX5BY88AbWpshPwGscwgKLtcCjeVodMbmhS6D6cbz1eGNUs3546ephbVmbHpxEhbCDrezGmFBArLxBKzPEfBcBdzQuncPm8ww2xa6UUQ/3/*),a:pkh([01adf45e/48'/1'/0'/2']tpubDFPYZPeShApyWndvDUtpLSjDHGYK4tTT4BkMyTukGqbP9AXQeQhiWsbwEzyZhxgud9ZPew1FPsoLbWjfnE3veSXLeU4ViofrhVAHNXtjQWE/3/*)),after(1757116800))))")
}

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
                env::var("RUST_LOG").unwrap_or_else(|_| "sqlx=warn,bdk_sqlx=warn".into()),
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
            TestStore::Postgres(store) => Box::pin(store.read()),
            TestStore::Sqlite(store) => Box::pin(store.read()),
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
        Store::<Postgres>::new_with_url(url.clone(), wallet_name.clone(), true).await?;
    stores.push(TestStore::Postgres(postgres_store));

    // Setup sqlite in-memory database
    let pool = SqlitePool::connect(":memory:").await?;
    let sqlite_store = Store::<Sqlite>::new(pool.clone(), wallet_name.clone(), true).await?;
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
        version: transaction::Version::ONE,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::all_zeros(),
                vout: 0,
            },
            script_sig: Default::default(),
            sequence: Default::default(),
            witness: Default::default(),
        }],
        output: vec![TxOut {
            value: spent.add(change).add(fee),
            script_pubkey: receive_address.script_pubkey(),
        }],
    };

    let tx1 = Transaction {
        version: transaction::Version::ONE,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: tx0.compute_txid(),
                vout: 0,
            },
            script_sig: Default::default(),
            sequence: Default::default(),
            witness: Default::default(),
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
    };

    bdk_wallet::test_utils::insert_checkpoint(
        wallet,
        BlockId {
            height: 42,
            hash: BlockHash::all_zeros(),
        },
    );

    bdk_wallet::test_utils::insert_checkpoint(
        wallet,
        BlockId {
            height: 1_000,
            hash: BlockHash::all_zeros(),
        },
    );
    bdk_wallet::test_utils::insert_checkpoint(
        wallet,
        BlockId {
            height: 2_000,
            hash: BlockHash::all_zeros(),
        },
    );

    bdk_wallet::test_utils::insert_tx(wallet, tx0.clone());

    bdk_wallet::test_utils::insert_tx(wallet, tx0.clone());
    insert_anchor_from_conf(
        wallet,
        tx0.compute_txid(),
        ConfirmationBlockTime {
            block_id: BlockId {
                height: 1_000,
                hash: BlockHash::all_zeros(),
            },
            confirmation_time: 100,
        },
    );

    bdk_wallet::test_utils::insert_tx(wallet, tx1.clone());
    insert_anchor_from_conf(
        wallet,
        tx1.compute_txid(),
        ConfirmationBlockTime {
            block_id: BlockId {
                height: 2_000,
                hash: BlockHash::all_zeros(),
            },
            confirmation_time: 200,
        },
    );

    tx1.compute_txid()
}

/// Simulates confirming a tx with `txid` at the specified `position` by inserting an anchor
/// at the lowest height in local chain that is greater or equal to `position`'s height,
/// assuming the confirmation time matches `ConfirmationTime::Confirmed`.
pub fn insert_anchor_from_conf(wallet: &mut Wallet, txid: Txid, position: ConfirmationBlockTime) {
    let ConfirmationBlockTime {
        block_id,
        confirmation_time,
    } = position;

    // anchor tx to checkpoint with lowest height that is >= position's height
    let anchor = wallet
        .local_chain()
        .range(block_id.height..)
        .last()
        .map(|anchor_cp| ConfirmationBlockTime {
            block_id: anchor_cp.block_id(),
            confirmation_time,
        })
        .expect("confirmation height cannot be greater than tip");

    wallet
        .apply_update(Update {
            tx_update: tx_graph::TxUpdate {
                anchors: [(anchor, txid)].into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .unwrap();
}

#[tracing::instrument]
#[tokio::test]
async fn wallet_is_persisted() -> anyhow::Result<()> {
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
        TestCase::new(get_test_tr_single_sig_xprv_with_change_desc(), 20_000, 11_000, 2000).await,
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
    initialize();

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
        let _ = bdk_wallet::test_utils::insert_checkpoint(&mut wallet_2, block);
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
