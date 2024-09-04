#![allow(unused)]

use bdk_electrum::{electrum_client, BdkElectrumClient};
use bdk_sqlx::Store;
use bdk_wallet::bitcoin::secp256k1::Secp256k1;
use bdk_wallet::bitcoin::Network;
use bdk_wallet::descriptor::ExtendedDescriptor;
use bdk_wallet::{KeychainKind, PersistedWallet, Wallet};
use better_panic::Settings;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io::Write;
// Create and persist a BDK wallet to an async storage backend.
use rustls::crypto::ring::default_provider;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

const DESC: &str = "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84'/1'/0'/0/*)";
const NAME: &str = "au7pq8ux";

const VAULT_DESC: &str =
  "wsh(andor(multi(2,[a0d3c79c/48'/1'/79'/2']tpubDEsGdqFaKUVnVNZZw8AixJ8C3yD8o6nN7hsdLfbtVRDTk3PNrQ2pcWNWNbxhdcNSgQP25pUpgRQ7qiVtN3YvSzACKizrvzSwH9SQ2Bjbbwt/0/*,[ea2484f9/48'/1'/79'/2']tpubDFjkswBXoRHKkvmHsxv4xdDqbjg1peX9zJytLeSLbXuwVgYhXgbABzC2r5MAWxqWoaUr7hWGW5TPjA9sNvxa3mX6DrNBdynDsEvwDoXGFpm/0/*,[93f245d7/48'/1'/79'/2']tpubDEVnR72gRgTsqaPFMacV6fCfaSEe56gcDomuGhk9MFeUdEi18riJCokgsZr2x1KKGRM59TJ4AQ6FuNun3khh95ceoH2ytN13nVD7yDLP5LJ/0/*),or_i(and_v(v:pkh([61cdf766/48'/1'/79'/2']tpubDEXETCw2WurhazfW5gW1z4njP6yLXDQmCGfjWGP5k3BuTQ5iZqovMr1zz1zWPhDMRn11hXGpZHodus1LysXnwREsD1ig96M24JhQCpPPpf6/0/*),after(1753228800)),thresh(2,pk([39bf48a9/48'/1'/0'/2']tpubDEr9rVFQbT1keErwxb6GuGy3RM6TEACSkFxBgziUvrDprYuM1Wm7wi6jb1gcaLrSgk6MSkGx84dS2kQQwJKxGRJ59rAvmuKTU7E3saHJLf5/0/*),s:pk([9467fdb3/48'/1'/0'/2']tpubDFEjX5BY88AbWpshPwGscwgKLtcCjeVodMbmhS6D6cbz1eGNUs3546ephbVmbHpxEhbCDrezGmFBArLxBKzPEfBcBdzQuncPm8ww2xa6UUQ/0/*),s:pk([01adf45e/48'/1'/0'/2']tpubDFPYZPeShApyWndvDUtpLSjDHGYK4tTT4BkMyTukGqbP9AXQeQhiWsbwEzyZhxgud9ZPew1FPsoLbWjfnE3veSXLeU4ViofrhVAHNXtjQWE/0/*),snl:after(1739836800))),and_v(v:thresh(2,pkh([39bf48a9/48'/1'/0'/2']tpubDEr9rVFQbT1keErwxb6GuGy3RM6TEACSkFxBgziUvrDprYuM1Wm7wi6jb1gcaLrSgk6MSkGx84dS2kQQwJKxGRJ59rAvmuKTU7E3saHJLf5/2/*),a:pkh([9467fdb3/48'/1'/0'/2']tpubDFEjX5BY88AbWpshPwGscwgKLtcCjeVodMbmhS6D6cbz1eGNUs3546ephbVmbHpxEhbCDrezGmFBArLxBKzPEfBcBdzQuncPm8ww2xa6UUQ/2/*),a:pkh([01adf45e/48'/1'/0'/2']tpubDFPYZPeShApyWndvDUtpLSjDHGYK4tTT4BkMyTukGqbP9AXQeQhiWsbwEzyZhxgud9ZPew1FPsoLbWjfnE3veSXLeU4ViofrhVAHNXtjQWE/2/*)),after(1757116800))))";
const CHANGE_DESC: &str =
  "wsh(andor(multi(2,[a0d3c79c/48'/1'/79'/2']tpubDEsGdqFaKUVnVNZZw8AixJ8C3yD8o6nN7hsdLfbtVRDTk3PNrQ2pcWNWNbxhdcNSgQP25pUpgRQ7qiVtN3YvSzACKizrvzSwH9SQ2Bjbbwt/1/*,[ea2484f9/48'/1'/79'/2']tpubDFjkswBXoRHKkvmHsxv4xdDqbjg1peX9zJytLeSLbXuwVgYhXgbABzC2r5MAWxqWoaUr7hWGW5TPjA9sNvxa3mX6DrNBdynDsEvwDoXGFpm/1/*,[93f245d7/48'/1'/79'/2']tpubDEVnR72gRgTsqaPFMacV6fCfaSEe56gcDomuGhk9MFeUdEi18riJCokgsZr2x1KKGRM59TJ4AQ6FuNun3khh95ceoH2ytN13nVD7yDLP5LJ/1/*),or_i(and_v(v:pkh([61cdf766/48'/1'/79'/2']tpubDEXETCw2WurhazfW5gW1z4njP6yLXDQmCGfjWGP5k3BuTQ5iZqovMr1zz1zWPhDMRn11hXGpZHodus1LysXnwREsD1ig96M24JhQCpPPpf6/1/*),after(1753228800)),thresh(2,pk([39bf48a9/48'/1'/0'/2']tpubDEr9rVFQbT1keErwxb6GuGy3RM6TEACSkFxBgziUvrDprYuM1Wm7wi6jb1gcaLrSgk6MSkGx84dS2kQQwJKxGRJ59rAvmuKTU7E3saHJLf5/1/*),s:pk([9467fdb3/48'/1'/0'/2']tpubDFEjX5BY88AbWpshPwGscwgKLtcCjeVodMbmhS6D6cbz1eGNUs3546ephbVmbHpxEhbCDrezGmFBArLxBKzPEfBcBdzQuncPm8ww2xa6UUQ/1/*),s:pk([01adf45e/48'/1'/0'/2']tpubDFPYZPeShApyWndvDUtpLSjDHGYK4tTT4BkMyTukGqbP9AXQeQhiWsbwEzyZhxgud9ZPew1FPsoLbWjfnE3veSXLeU4ViofrhVAHNXtjQWE/1/*),snl:after(1739836800))),and_v(v:thresh(2,pkh([39bf48a9/48'/1'/0'/2']tpubDEr9rVFQbT1keErwxb6GuGy3RM6TEACSkFxBgziUvrDprYuM1Wm7wi6jb1gcaLrSgk6MSkGx84dS2kQQwJKxGRJ59rAvmuKTU7E3saHJLf5/3/*),a:pkh([9467fdb3/48'/1'/0'/2']tpubDFEjX5BY88AbWpshPwGscwgKLtcCjeVodMbmhS6D6cbz1eGNUs3546ephbVmbHpxEhbCDrezGmFBArLxBKzPEfBcBdzQuncPm8ww2xa6UUQ/3/*),a:pkh([01adf45e/48'/1'/0'/2']tpubDFPYZPeShApyWndvDUtpLSjDHGYK4tTT4BkMyTukGqbP9AXQeQhiWsbwEzyZhxgud9ZPew1FPsoLbWjfnE3veSXLeU4ViofrhVAHNXtjQWE/3/*)),after(1757116800))))";
const ELECTRUM_URL: &str = "ssl://mempool.space:60602";
const STOP_GAP: usize = 50;
const BATCH_SIZE: usize = 5;

type Result<T, E = Box<dyn std::error::Error>> = core::result::Result<T, E>;

#[tokio::main]
async fn main() -> Result<()> {
    default_provider()
        .install_default()
        .expect("Failed to install rustls default crypto provider");
    Settings::debug()
        .most_recent_first(false)
        .lineno_suffix(true)
        .install();
    tracing_subscriber::registry()
        .with(EnvFilter::new(std::env::var("RUST_LOG").unwrap_or_else(
            |_| {
                "sqlx=warn,\
                    bdk_sqlx=info"
                    .into()
            },
        )))
        .with(tracing_subscriber::fmt::layer())
        .try_init()?;

    let url = std::env::var("DATABASE_URL").expect("must set DATABASE_URL");

    let mut store = bdk_sqlx::Store::new_with_url(url.clone(), Some(NAME.to_string()))
        .await
        .unwrap();

    let mut wallet = match Wallet::load().load_wallet_async(&mut store).await.unwrap() {
        Some(wallet) => wallet,
        None => {
            let wallet = Wallet::create_single(DESC)
                .network(Network::Signet)
                .create_wallet_async(&mut store)
                .await
                .unwrap();
            println!(
                "Descriptor: {}",
                wallet.public_descriptor(KeychainKind::External)
            );
            wallet
        }
    };

    print!("Syncing...");
    electrum(&mut wallet);
    let addr = wallet.reveal_next_address(KeychainKind::External);
    assert!(wallet.persist_async(&mut store).await?);

    println!(
        "Address ({:?} {}) {}",
        addr.keychain, addr.index, addr.address,
    );

    // load second wallet
    let secp = Secp256k1::new();
    let wallet_name = bdk_wallet::wallet_name_from_descriptor(
        VAULT_DESC,
        Some(CHANGE_DESC),
        Network::Signet,
        &secp,
    )
    .unwrap();

    let mut store = bdk_sqlx::Store::new_with_url(url.clone(), Some(wallet_name))
        .await
        .unwrap();

    let mut wallet = match Wallet::load().load_wallet_async(&mut store).await.unwrap() {
        Some(wallet) => wallet,
        None => {
            let wallet = Wallet::create(VAULT_DESC, CHANGE_DESC)
                .network(Network::Signet)
                .create_wallet_async(&mut store)
                .await
                .unwrap();
            println!(
                "Descriptor: {}",
                wallet.public_descriptor(KeychainKind::External)
            );
            wallet
        }
    };

    let addr = wallet.reveal_next_address(KeychainKind::External);
    assert!(wallet.persist_async(&mut store).await?);

    println!(
        "2nd wallet address ({:?} {}) {}",
        addr.keychain, addr.index, addr.address,
    );

    Ok(())
}

fn electrum(mut wallet: &mut PersistedWallet<Store>) {
    let client = BdkElectrumClient::new(electrum_client::Client::new(ELECTRUM_URL).unwrap());

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

    let update = client
        .full_scan(request, STOP_GAP, BATCH_SIZE, true)
        .unwrap();

    println!();

    wallet.apply_update(update).unwrap();
}
