use crate::{drop_all, Store};
use bdk_chain::bitcoin::secp256k1::Secp256k1;
use bdk_chain::bitcoin::Network;
use bdk_wallet::{
    wallet_name_from_descriptor,
    KeychainKind::{self, *},
    Wallet,
};
use better_panic::Settings;
use sqlx::PgPool;
use std::env;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

pub fn get_test_tr_single_sig_xprv_with_change_desc() -> (&'static str, &'static str) {
    ("tr(tprv8ZgxMBicQKsPdDArR4xSAECuVxeX1jwwSXR4ApKbkYgZiziDc4LdBy2WvJeGDfUSE4UT4hHhbgEwbdq8ajjUHiKDegkwrNU6V55CxcxonVN/0/*)",
        "tr(tprv8ZgxMBicQKsPdDArR4xSAECuVxeX1jwwSXR4ApKbkYgZiziDc4LdBy2WvJeGDfUSE4UT4hHhbgEwbdq8ajjUHiKDegkwrNU6V55CxcxonVN/1/*)")
}

const NETWORK: Network = Network::Signet;

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
    for keychain in [External, Internal] {
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
