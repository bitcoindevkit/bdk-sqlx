use crate::{drop_all, Store};
use assert_matches::assert_matches;
use bdk_chain::bitcoin::constants::ChainHash;
use bdk_chain::bitcoin::hashes::Hash;
use bdk_chain::bitcoin::secp256k1::Secp256k1;
use bdk_chain::bitcoin::Network::Signet;
use bdk_chain::bitcoin::{BlockHash, Network};
use bdk_chain::miniscript::{Descriptor, DescriptorPublicKey};
use bdk_electrum::{electrum_client, BdkElectrumClient};
use bdk_testenv::TestEnv;
use bdk_wallet::{
    wallet_name_from_descriptor, KeychainKind, LoadError, LoadMismatch, LoadWithPersistError,
    Wallet,
};
use better_panic::Settings;
use sqlx::PgPool;
use std::collections::HashSet;
use std::env;
use std::io::Write;
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
const STOP_GAP: usize = 50;
const BATCH_SIZE: usize = 5;

#[tracing::instrument]
#[tokio::test]
async fn wallet_is_persisted() -> anyhow::Result<()> {
    Settings::debug()
        .most_recent_first(false)
        .lineno_suffix(true)
        .install();

    tracing_subscriber::registry()
        .with(EnvFilter::new(
            env::var("RUST_LOG").unwrap_or_else(|_| "sqlx=warn,bdk_postgres=info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .try_init()?;

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
    let mut store = Store::new_with_url(url.clone(), Some(wallet_name.clone())).await?;
    let mut wallet = Wallet::create(external_desc, internal_desc)
        .network(NETWORK)
        .create_wallet_async(&mut store)
        .await?;

    let external_addr0 = wallet.reveal_next_address(KeychainKind::External);
    for keychain in [KeychainKind::External, KeychainKind::Internal] {
        let _ = wallet.reveal_addresses_to(keychain, 2);
    }

    assert!(wallet.persist_async(&mut store).await?);
    let wallet_spk_index = wallet.spk_index();

    {
        // Recover the wallet
        let mut store = Store::new_with_url(url.clone(), Some(wallet_name)).await?;
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

    // Clean up (optional, depending on your test database strategy)
    // You might want to delete the test wallet from the database here
    let db = PgPool::connect(&url).await?;
    drop_all(db).await.expect("hope its not mainnet");

    Ok(())
}

#[tracing::instrument]
#[tokio::test]
async fn test_wallet_load_checks() -> anyhow::Result<()> {
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

        assert_matches!(
            Wallet::load()
                .descriptor(KeychainKind::External, Some(internal_desc))
                .load_wallet_async(&mut store)
                .await,
            Err(LoadWithPersistError::InvalidChangeSet(LoadError::Mismatch(
                LoadMismatch::Descriptor { .. }
            ))),
            "unexpected descriptors check result"
        );

        assert_matches!(
            Wallet::load()
                .descriptor(KeychainKind::External, Option::<&str>::None)
                .load_wallet_async(&mut store)
                .await,
            Err(LoadWithPersistError::InvalidChangeSet(LoadError::Mismatch(
                LoadMismatch::Descriptor { .. }
            ))),
            "unexpected descriptors check result"
        );

        let mainnet_hash = BlockHash::from_byte_array(ChainHash::BITCOIN.to_bytes());

        assert_matches!(
            Wallet::load().check_genesis_hash(mainnet_hash).load_wallet_async(&mut store).await
            , Err(LoadWithPersistError::InvalidChangeSet(LoadError::Mismatch(LoadMismatch::Genesis { .. }))),
            "unexpected genesis hash check result: mainnet hash (check) is not testnet hash (loaded)");
    }

    // Clean up (optional, depending on your test database strategy)
    // You might want to delete the test wallet from the database here
    let db = PgPool::connect(&url).await?;
    drop_all(db).await.expect("hope its not mainet");

    Ok(())
}

#[tracing::instrument]
#[tokio::test]
async fn test_single_descriptor_wallet_persist_and_recover() -> anyhow::Result<()> {
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
    let mut store = Store::new_with_url(url.clone(), Some(wallet_name.clone())).await?;
    let mut wallet = Wallet::create_single(desc)
        .network(NETWORK)
        .create_wallet_async(&mut store)
        .await?;

    let _ = wallet.reveal_addresses_to(KeychainKind::External, 2);

    assert!(wallet.persist_async(&mut store).await?);
    {
        // Recover the wallet

        let secp = wallet.secp_ctx();
        let (_, keymap) = <Descriptor<DescriptorPublicKey>>::parse_descriptor(secp, desc).unwrap();
        assert!(!keymap.is_empty());
        let mut store = Store::new_with_url(url.clone(), Some(wallet_name.clone())).await?;
        let wallet = Wallet::load()
            .descriptor(KeychainKind::External, Some(desc))
            .extract_keys()
            .load_wallet_async(&mut store)
            .await?
            .expect("wallet must exist");
        assert_eq!(wallet.derivation_index(KeychainKind::External), Some(2));
        // should have private key
        assert_eq!(
            wallet.get_signers(KeychainKind::External).as_key_map(secp),
            keymap,
        );

        // should error on wrong internal params
        let desc = get_test_wpkh();
        let (exp_desc, _) =
            <Descriptor<DescriptorPublicKey>>::parse_descriptor(secp, desc).unwrap();
        let err = Wallet::load()
            .descriptor(KeychainKind::Internal, Some(desc))
            .extract_keys()
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
    drop_all(db).await.expect("hope its not mainet");
    Ok(())
}

#[tracing::instrument]
#[tokio::test]
async fn test_two_wallets_load() -> anyhow::Result<()> {
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
    let mut store_1 = Store::new_with_url(url.clone(), Some(wallet_1_name.clone())).await?;
    let mut store_2 = Store::new_with_url(url.clone(), Some(wallet_2_name.clone())).await?;

    let wallet_1_spk_index = {
        let mut wallet_1 = Wallet::create(external_desc_wallet_1, internal_desc_wallet_1)
            .network(NETWORK)
            .create_wallet_async(&mut store_1)
            .await?;
        let deposit_address = wallet_1.reveal_next_address(KeychainKind::External);
        let change_address = wallet_1.reveal_next_address(KeychainKind::Internal);
        dbg!(deposit_address.address);
        dbg!(change_address.address);

        assert!(wallet_1.persist_async(&mut store_1).await?);
        wallet_1.spk_index().clone()
    };

    let wallet_2_spk_index = {
        let mut wallet_2 = Wallet::create(external_desc_wallet_2, internal_desc_wallet_2)
            .network(NETWORK)
            .create_wallet_async(&mut store_2)
            .await?;
        let deposit_address = wallet_2.reveal_next_address(KeychainKind::External);
        let change_address = wallet_2.reveal_next_address(KeychainKind::Internal);
        dbg!(deposit_address.address);
        dbg!(change_address.address);

        assert!(wallet_2.persist_async(&mut store_1).await?);
        wallet_2.spk_index().clone()
    };

    {
        // Recover the wallet_1
        let mut store_1 = Store::new_with_url(url.clone(), Some(wallet_1_name.clone())).await?;
        let wallet_1 = Wallet::load()
            .descriptor(KeychainKind::External, Some(external_desc_wallet_1))
            .descriptor(KeychainKind::Internal, Some(internal_desc_wallet_1))
            .load_wallet_async(&mut store_1)
            .await?
            .expect("wallet_1 must exist");
        assert_eq!(wallet_1.network(), NETWORK);
        assert_eq!(
            wallet_1.spk_index().keychains().collect::<Vec<_>>(),
            wallet_1_spk_index.keychains().collect::<Vec<_>>()
        );
        assert_eq!(
            wallet_1.spk_index().last_revealed_indices(),
            wallet_1_spk_index.last_revealed_indices()
        );
    }

    {
        // Recover the wallet_2
        let mut store_2 = Store::new_with_url(url.clone(), Some(wallet_2_name.clone())).await?;
        let wallet_2 = Wallet::load()
            .descriptor(KeychainKind::External, Some(external_desc_wallet_2))
            .descriptor(KeychainKind::Internal, Some(internal_desc_wallet_2))
            .load_wallet_async(&mut store_2)
            .await?
            .expect("wallet_2 must exist");
        assert_eq!(wallet_2.network(), NETWORK);
        assert_eq!(
            wallet_2.spk_index().keychains().collect::<Vec<_>>(),
            wallet_2_spk_index.keychains().collect::<Vec<_>>()
        );
        assert_eq!(
            wallet_2.spk_index().last_revealed_indices(),
            wallet_2_spk_index.last_revealed_indices()
        );
    }

    // Clean up (optional, depending on your test database strategy)
    // You might want to delete the test wallet from the database here
    let db = PgPool::connect(&url).await?;
    drop_all(db).await.expect("hope its not mainet");
    Ok(())
}

#[tracing::instrument]
#[tokio::test]
async fn test_wallet_sync_with_electrum() -> anyhow::Result<()> {
    Settings::debug()
        .most_recent_first(false)
        .lineno_suffix(true)
        .install();

    let env = TestEnv::new()?;
    let electrum_client = electrum_client::Client::new(env.electrsd.electrum_url.as_str())?;
    let client = BdkElectrumClient::new(electrum_client);

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
        NETWORK,
        &Secp256k1::new(),
    )?;

    let mut store = Store::new_with_url(url.clone(), Some(wallet_name.clone())).await?;
    let mut wallet = Wallet::create(external_desc, internal_desc)
        .network(NETWORK)
        .create_wallet_async(&mut store)
        .await?;
    let _ = wallet.reveal_next_address(KeychainKind::External);
    assert!(wallet.persist_async(&mut store).await?);

    // Populate the electrum client's transaction cache so it doesn't redownload transaction we
    // already have.
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

    let update = client.full_scan(request, STOP_GAP, BATCH_SIZE, false)?;
    wallet.apply_update(update)?;
    let latest_checkpoint_height = wallet.latest_checkpoint().height();
    assert!(wallet.persist_async(&mut store).await?);

    {
        // Recover the wallet
        let mut store = Store::new_with_url(url.clone(), Some(wallet_name.clone())).await?;
        let wallet = Wallet::load()
            .descriptor(KeychainKind::External, Some(external_desc))
            .descriptor(KeychainKind::Internal, Some(internal_desc))
            .load_wallet_async(&mut store)
            .await?
            .expect("wallet must exist");
        assert_eq!(
            latest_checkpoint_height,
            wallet.latest_checkpoint().height()
        )
    }

    Ok(())
}
