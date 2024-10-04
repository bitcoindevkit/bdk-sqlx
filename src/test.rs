use assert_matches::assert_matches;
use bdk_chain::bitcoin::constants::ChainHash;
use bdk_chain::bitcoin::hashes::Hash;
use crate::{postgres::drop_all, Store};
use bdk_chain::bitcoin::secp256k1::Secp256k1;
use bdk_chain::bitcoin::Network::Signet;
use bdk_chain::bitcoin::{BlockHash, Network, Txid};
use bdk_chain::miniscript::{Descriptor, DescriptorPublicKey};
use bdk_chain::BlockId;
use bdk_electrum::electrum_client::Client;
use bdk_electrum::{electrum_client, BdkElectrumClient};
use bdk_testenv::bitcoincore_rpc::RpcApi;
use bdk_testenv::TestEnv;
use bdk_wallet::{
    descriptor::ExtendedDescriptor,
    wallet_name_from_descriptor,
    KeychainKind::{self, *},
    LoadError, LoadMismatch, LoadWithPersistError, PersistedWallet, Wallet,
};
use better_panic::Settings;
use rustls::crypto::ring::default_provider;
use std::collections::HashSet;
use sqlx::{PgPool, Postgres, Sqlite, SqlitePool};
use std::env;
use std::io::Write;
use std::time::Duration;
use std::sync::Arc;
use std::sync::Once;
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
const STOP_GAP: usize = 50;
const BATCH_SIZE: usize = 50;

fn parse_descriptor(s: &str) -> ExtendedDescriptor {
    <Descriptor<DescriptorPublicKey>>::parse_descriptor(&Secp256k1::new(), s)
        .unwrap()
        .0
}

static INIT: Once = Once::new();

// This must only be called once.
pub fn initialize() {
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

#[tracing::instrument]
#[tokio::test]
async fn wallet_is_persisted_postgres() -> anyhow::Result<()> {
    Settings::debug()
        .most_recent_first(false)
        .lineno_suffix(true)
        .install();

    initialize();

    // Set up the database URL (you might want to use a test-specific database)
    let url = env::var("DATABASE_TEST_URL").expect("DATABASE_TEST_URL must be set for tests");
    let pg = PgPool::connect(&url.clone()).await?;
    drop_all(pg).await?;
    println!("tables dropped");

    // Define descriptors (you may need to adjust these based on your exact requirements)
    let (external_desc, internal_desc) = get_test_tr_single_sig_xprv_with_change_desc();
    // Generate a unique name for this test wallet
    let wallet_name = wallet_name_from_descriptor(
        external_desc,
        Some(internal_desc),
        NETWORK,
        &Secp256k1::new(),
    )?;

    // Create a new wallet
    let wallet_spk_index = {
        let mut store = Store::new_with_url(url.clone(), Some(wallet_name.clone())).await?;
        let mut wallet = Wallet::create(external_desc, internal_desc)
            .network(NETWORK)
            .create_wallet_async(&mut store)
            .await?;

        let deposit_address = wallet.reveal_next_address(KeychainKind::External);
        let change_address = wallet.reveal_next_address(KeychainKind::Internal);
        dbg!(deposit_address.address);
        dbg!(change_address.address);

        assert!(wallet.persist_async(&mut store).await?);
        wallet.spk_index().clone()
    };

    {
        // Recover the wallet
        let mut store = Store::new_with_url(url.clone(), Some(wallet_name.clone())).await?;
        let mut wallet = Wallet::load()
            .descriptor(KeychainKind::External, Some(external_desc))
            .descriptor(KeychainKind::Internal, Some(internal_desc))
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

        let recovered_address = wallet.reveal_next_address(KeychainKind::External);
        println!("Recovered next address: {}", recovered_address.address);

        assert_eq!(
            wallet.public_descriptor(KeychainKind::External).to_string(),
            "tr(tpubD6NzVbkrYhZ4WgCeJid2Zds24zATB58r1q1qTLMuApUxZUxzETADNTeP6SvZKSsXs4qhvFAC21GFjXHwgxAcDtZqzzj8JMpsFDgqyjSJHGa/0/*)#celxt6vn".to_string(),
        );
    }

    // Clean up (optional, depending on your test database strategy)
    // You might want to delete the test wallet from the database here
    let db = PgPool::connect(&url).await?;
    drop_all(db).await.expect("hope its not mainet");

    Ok(())
}

async fn setup_database() -> anyhow::Result<String> {
    let url = env::var("DATABASE_TEST_URL").expect("DATABASE_TEST_URL must be set for tests");
    let pg = PgPool::connect(&url).await?;
    match drop_all(pg).await {
        Ok(_) => dbg!("tables dropped"),
        Err(_) => dbg!("Error dropping tables"),
    };
    Ok(url)
}

fn get_wallet_descriptors(wallet_type: u8) -> (&'static str, &'static str) {
    match wallet_type {
        1 => get_test_tr_single_sig_xprv_with_change_desc(),
        2 => ("wpkh([bdb9a801/84'/1'/0']tpubDCopxf4CiXF9dicdGrXgZV9f8j3pYbWBVfF8WxjaFHtic4DZsgp1tQ58hZdsSu6M7FFzUyAh9rMn7RZASUkPgZCMdByYKXvVtigzGi8VJs6/0/*)#j8mkwdgr",
              "wpkh([bdb9a801/84'/1'/0']tpubDCopxf4CiXF9dicdGrXgZV9f8j3pYbWBVfF8WxjaFHtic4DZsgp1tQ58hZdsSu6M7FFzUyAh9rMn7RZASUkPgZCMdByYKXvVtigzGi8VJs6/1/*)#rn7hnccm"),
        3 => get_test_minisicript_with_change_desc(),
        _ => panic!("Invalid wallet type"),
    }
}

async fn create_and_scan_wallet(
    url: &str,
    external_desc: &str,
    internal_desc: &str,
) -> anyhow::Result<(Store<Postgres>, String)> {
    let wallet_name = wallet_name_from_descriptor(
        external_desc,
        Some(internal_desc),
        NETWORK,
        &Secp256k1::new(),
    )?;
    let mut store = Store::new_with_url(url.to_string(), Some(wallet_name.clone())).await?;
    let mut wallet = Wallet::create(external_desc.to_string(), internal_desc.to_string())
        .network(NETWORK)
        .create_wallet_async(&mut store)
        .await?;
    let _ = electrum_full_scan(&mut wallet).await?;
    assert!(wallet.persist_async(&mut store).await?);
    Ok((store, wallet_name))
}

async fn load_wallet_and_get_transactions(
    store: &mut Store<Postgres>,
    external_desc: &str,
    internal_desc: &str,
) -> anyhow::Result<Vec<Txid>> {
    let wallet = Wallet::load()
        .descriptor(KeychainKind::External, Some(external_desc.to_string()))
        .descriptor(KeychainKind::Internal, Some(internal_desc.to_string()))
        .load_wallet_async(store)
        .await?
        .expect("wallet must exist");
    Ok(wallet.transactions().map(|tx| tx.tx_node.txid).collect())
}

async fn recover_wallet_and_get_transactions(
    external_desc: &str,
    internal_desc: &str,
) -> anyhow::Result<Vec<Txid>> {
    let mut wallet = Wallet::create(external_desc.to_string(), internal_desc.to_string())
        .network(NETWORK)
        .create_wallet_no_persist()?;
    let _ = electrum_full_scan_no_persist(&mut wallet).await?;
    Ok(wallet.transactions().map(|tx| tx.tx_node.txid).collect())
}

#[tracing::instrument]
#[tokio::test]
async fn test_three_wallets_list_transactions() -> anyhow::Result<()> {
    Settings::debug()
        .most_recent_first(false)
        .lineno_suffix(true)
        .install();

    default_provider()
        .install_default()
        .expect("Failed to install rustls default crypto provider");

    let url = setup_database().await?;

    let wallet_types = [1, 2, 3];
    let mut stores = Vec::new();
    let mut persisted_txs = Vec::new();
    let mut recovered_txs = Vec::new();

    for wallet_type in wallet_types.iter() {
        let (external_desc, internal_desc) = get_wallet_descriptors(*wallet_type);
        let (store, _) = create_and_scan_wallet(&url, external_desc, internal_desc).await?;
        stores.push(store);
    }

    for (i, store) in stores.iter_mut().enumerate() {
        let (external_desc, internal_desc) = get_wallet_descriptors(wallet_types[i]);
        let mut txs = load_wallet_and_get_transactions(store, external_desc, internal_desc).await?;
        txs.sort();
        persisted_txs.push(txs);
    }

    for wallet_type in wallet_types.iter() {
        let (external_desc, internal_desc) = get_wallet_descriptors(*wallet_type);
        let mut txs = recover_wallet_and_get_transactions(external_desc, internal_desc).await?;
        txs.sort();
        recovered_txs.push(txs);
    }

    for i in 0..3 {
        assert_eq!(persisted_txs[i], recovered_txs[i]);
    }

    // Clean up
    let db = PgPool::connect(&url).await?;
    drop_all(db).await.expect("hope it's not mainnet");
    Ok(())
}

async fn electrum_full_scan(wallet: &mut PersistedWallet<Store<Postgres>>) -> anyhow::Result<()> {
    let client = BdkElectrumClient::new(Client::new("ssl://mempool.space:60602").unwrap());
    client.populate_tx_cache(wallet.tx_graph().full_txs().map(|tx_node| tx_node.tx));

    let request = wallet.start_full_scan().inspect({
        let mut stdout = std::io::stdout();
        let mut once = HashSet::<KeychainKind>::new();
        move |k, spk_i, _| {
            if once.insert(k) {
                print!("\nScanning keychain [{:?}]", k);
            }
            print!(" {:<3}", spk_i);
            stdout.flush().expect("must flush");
        }
    });

    let update = client.full_scan(request, STOP_GAP, BATCH_SIZE, true)?;
    wallet.apply_update(update)?;
    Ok(())
}

async fn electrum_full_scan_no_persist(wallet: &mut Wallet) -> anyhow::Result<()> {
    let client = BdkElectrumClient::new(Client::new("ssl://mempool.space:60602").unwrap());
    client.populate_tx_cache(wallet.tx_graph().full_txs().map(|tx_node| tx_node.tx));

    let request = wallet.start_full_scan().inspect({
        let mut stdout = std::io::stdout();
        let mut once = HashSet::<KeychainKind>::new();
        move |k, spk_i, _| {
            if once.insert(k) {
                print!("\nScanning keychain [{:?}]", k);
            }
            print!(" {:<3}", spk_i);
            stdout.flush().expect("must flush");
        }
    });

    let update = client.full_scan(request, STOP_GAP, BATCH_SIZE, true)?;
    wallet.apply_update(update)?;
    Ok(())
}

#[tracing::instrument]
#[tokio::test]
async fn wallet_load_checks() -> anyhow::Result<()> {
    Settings::debug()
        .most_recent_first(false)
        .lineno_suffix(true)
        .install();

    // Set up the database URL (you might want to use a test-specific database)
    let url = env::var("DATABASE_TEST_URL").expect("DATABASE_TEST_URL must be set for tests");

    let pg = PgPool::connect(&url.clone()).await?;
    match drop_all(pg).await {
        Ok(_) => {
            dbg!("tables dropped")
        }
        Err(_) => {
            dbg!("Error dropping tables")
        }
    };

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

    // Create a new wallet
    let mut store = Store::new_with_url(url.clone(), Some(wallet_name)).await?;
    let _wallet = Wallet::create(external_desc, internal_desc)
        .network(NETWORK)
        .create_wallet_async(&mut store)
        .await?;

    {
        assert_matches!(
            Wallet::load()
                .descriptor(KeychainKind::External, Some(internal_desc))
                .load_wallet_async(&mut store)
                .await,
            Err(LoadWithPersistError::InvalidChangeSet(LoadError::Mismatch(
                LoadMismatch::Descriptor { keychain, loaded, expected }
            )))
            if keychain == KeychainKind::External && loaded == Some(parsed_ext.clone()) && expected == Some(parsed_int),
            "should error on wrong external descriptor"
        );
    }
    {
        assert_matches!(
            Wallet::load()
                .descriptor(KeychainKind::External, Option::<&str>::None)
                .load_wallet_async(&mut store)
                .await,
            Err(LoadWithPersistError::InvalidChangeSet(LoadError::Mismatch(
                LoadMismatch::Descriptor { keychain, loaded, expected }
            )))
            if keychain == KeychainKind::External && loaded == Some(parsed_ext) && expected.is_none(),
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

    // Clean up (optional, depending on your test database strategy)
    // You might want to delete the test wallet from the database here
    let db = PgPool::connect(&url).await?;
    drop_all(db).await.expect("hope its not mainnet");

    Ok(())
}

#[tracing::instrument]
#[tokio::test]
async fn single_descriptor_wallet_persist_and_recover() -> anyhow::Result<()> {
    Settings::debug()
        .most_recent_first(false)
        .lineno_suffix(true)
        .install();
    // Set up the database URL (you might want to use a test-specific database)
    let url = env::var("DATABASE_TEST_URL").expect("DATABASE_TEST_URL must be set for tests");

    let pg = PgPool::connect(&url.clone()).await?;
    match drop_all(pg).await {
        Ok(_) => {
            dbg!("tables dropped")
        }
        Err(_) => {
            dbg!("Error dropping tables")
        }
    };

    // Define descriptors
    let desc = get_test_tr_single_sig_xprv();

    // Generate a unique name for this test wallet
    let wallet_name = wallet_name_from_descriptor(desc, Some(desc), NETWORK, &Secp256k1::new())?;

    // Create a new wallet
    let mut store = Store::new_with_url(url.clone(), Some(wallet_name)).await?;
    let mut wallet = Wallet::create_single(desc)
        .network(NETWORK)
        .create_wallet_async(&mut store)
        .await?;

    let _ = wallet.reveal_addresses_to(KeychainKind::External, 2);
    assert!(wallet.persist_async(&mut store).await?);

    {
        // Recover the wallet
        let wallet = Wallet::load().load_wallet_async(&mut store).await?.unwrap();
        assert_eq!(wallet.derivation_index(KeychainKind::External), Some(2));
    }
    {
        // should error on wrong internal params
        let desc = get_test_wpkh();
        let exp_desc = parse_descriptor(desc);
        let err = Wallet::load()
            .descriptor(KeychainKind::Internal, Some(desc))
            .load_wallet_async(&mut store)
            .await;
        assert_matches!(
            err,
            Err(LoadWithPersistError::InvalidChangeSet(LoadError::Mismatch(LoadMismatch::Descriptor { keychain, loaded, expected })))
            if keychain == KeychainKind::Internal && loaded.is_none() && expected == Some(exp_desc),
            "single descriptor wallet should refuse change descriptor param"
        );
    }

    // Clean up (optional, depending on your test database strategy)
    // You might want to delete the test wallet from the database here
    let db = PgPool::connect(&url).await?;
    drop_all(db).await.expect("hope its not mainnet");
    Ok(())
}

#[tracing::instrument]
#[tokio::test]
async fn two_wallets_load() -> anyhow::Result<()> {
    Settings::debug()
        .most_recent_first(false)
        .lineno_suffix(true)
        .install();
    // Set up the database URL (you might want to use a test-specific database)
    let url = env::var("DATABASE_TEST_URL").expect("DATABASE_TEST_URL must be set for tests");

    let pg = PgPool::connect(&url.clone()).await?;
    match drop_all(pg).await {
        Ok(_) => {
            dbg!("tables dropped")
        }
        Err(_) => {
            dbg!("Error dropping tables")
        }
    };

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

    // Create wallets
    let mut store_1 = Store::new_with_url(url.clone(), Some(wallet_1_name)).await?;
    let mut store_2 = Store::new_with_url(url.clone(), Some(wallet_2_name)).await?;

    let mut wallet_1 = Wallet::create(external_desc_wallet_1, internal_desc_wallet_1)
        .network(NETWORK)
        .create_wallet_async(&mut store_1)
        .await?;
    let _ = wallet_1.reveal_next_address(KeychainKind::External);
    let _ = wallet_1.reveal_next_address(KeychainKind::Internal);
    assert!(wallet_1.persist_async(&mut store_1).await?);

    // for wallet 2 we reveal an extra internal address and insert a new checkpoint
    // to check that loading returns the correct data for each wallet
    let mut wallet_2 = Wallet::create(external_desc_wallet_2, internal_desc_wallet_2)
        .network(NETWORK)
        .create_wallet_async(&mut store_2)
        .await?;
    let _ = wallet_2.reveal_next_address(KeychainKind::External);
    let _ = wallet_2.reveal_addresses_to(KeychainKind::Internal, 2);
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
        wallet_1.derivation_index(KeychainKind::External),
        wallet_2.derivation_index(KeychainKind::External)
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

    // Clean up (optional, depending on your test database strategy)
    // You might want to delete the test wallet from the database here
    let db = PgPool::connect(&url).await?;
    drop_all(db).await.expect("hope its not mainnet");
    Ok(())
}

#[tracing::instrument]
#[tokio::test]
async fn sync_with_electrum() -> anyhow::Result<()> {
    Settings::debug()
        .most_recent_first(false)
        .lineno_suffix(true)
        .install();

    // Set up the database URL (you might want to use a test-specific database)
    let url = env::var("DATABASE_TEST_URL").expect("DATABASE_TEST_URL must be set for tests");

    let pg = PgPool::connect(&url.clone()).await?;
    match drop_all(pg).await {
        Ok(_) => {
            dbg!("tables dropped")
        }
        Err(_) => {
            dbg!("Error dropping tables")
        }
    };

    // Define descriptors (you may need to adjust these based on your exact requirements)
    let (external_desc, internal_desc) = get_test_tr_single_sig_xprv_with_change_desc();
    // Generate a unique name for this test wallet
    let wallet_name = wallet_name_from_descriptor(
        external_desc,
        Some(internal_desc),
        Network::Regtest,
        &Secp256k1::new(),
    )?;

    let mut store = Store::new_with_url(url.clone(), Some(wallet_name)).await?;
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
    let new_tip_height: u32 = env.rpc_client().get_block_count()?.try_into()?;
    assert_eq!(new_tip_height, 10);

    let request = wallet.start_full_scan();
    let update = client.full_scan(request, STOP_GAP, BATCH_SIZE, false)?;
    wallet.apply_update(update)?;
    assert!(wallet.persist_async(&mut store).await?);

    // Recover the wallet
    let wallet = Wallet::load().load_wallet_async(&mut store).await?.unwrap();
    assert_eq!(wallet.latest_checkpoint().height(), new_tip_height);

    let db = PgPool::connect(&url).await?;
    drop_all(db).await.expect("hope its not mainnet");

    Ok(())
}

// This test uses the in-memory sqlite DB so tables don't need to be dropped at the end.
#[tracing::instrument]
#[tokio::test]
async fn wallet_is_persisted_sqlite() -> anyhow::Result<()> {
    Settings::debug()
        .most_recent_first(false)
        .lineno_suffix(true)
        .install();

    initialize();

    // Set up the database URL (you might want to use a test-specific database)
    let pool = SqlitePool::connect(":memory:").await?;

    // Define descriptors (you may need to adjust these based on your exact requirements)
    let (external_desc, internal_desc) = get_test_tr_single_sig_xprv_with_change_desc();
    // Generate a unique name for this test wallet
    let wallet_name = wallet_name_from_descriptor(
        external_desc,
        Some(internal_desc),
        NETWORK,
        &Secp256k1::new(),
    )?;

    // Create a new wallet, use sqlite in memory DB
    let mut store = Store::<Sqlite>::new(pool.clone(), Some(wallet_name.clone()), true).await?;
    let mut wallet = Wallet::create(external_desc, internal_desc)
        .network(NETWORK)
        .create_wallet_async(&mut store)
        .await?;

    let external_addr0 = wallet.reveal_next_address(KeychainKind::External);
    for keychain in [External, Internal] {
        let _ = wallet.reveal_addresses_to(keychain, 2);
    }

    assert!(wallet.persist_async(&mut store).await?);
    let wallet_spk_index = wallet.spk_index();

    {
        // Recover the wallet
        let mut store = Store::<Sqlite>::new(pool, Some(wallet_name), false).await?;
        let wallet = Wallet::load()
            .descriptor(KeychainKind::External, Some(external_desc))
            .descriptor(KeychainKind::Internal, Some(internal_desc))
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

        let recovered_addr = wallet.peek_address(KeychainKind::External, 0);
        assert_eq!(recovered_addr, external_addr0, "failed to recover address");

        assert_eq!(
            wallet.public_descriptor(KeychainKind::External).to_string(),
            "tr(tpubD6NzVbkrYhZ4WgCeJid2Zds24zATB58r1q1qTLMuApUxZUxzETADNTeP6SvZKSsXs4qhvFAC21GFjXHwgxAcDtZqzzj8JMpsFDgqyjSJHGa/0/*)#celxt6vn".to_string(),
        );
    }

    Ok(())
}
