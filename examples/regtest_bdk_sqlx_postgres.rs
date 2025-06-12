#![allow(unused)]
use anyhow::{bail, Context};
use bdk_electrum::electrum_client::ElectrumApi;
use bdk_electrum::{electrum_client, BdkElectrumClient};
use bdk_sqlx::sqlx::Postgres;
use bdk_sqlx::{PgStoreBuilder, Store};
use bdk_wallet::bitcoin::consensus::Encodable;
use bdk_wallet::bitcoin::secp256k1::Secp256k1;
use bdk_wallet::bitcoin::{constants, Address, Amount, FeeRate, Network};
use bdk_wallet::chain::keychain_txout::{KeychainTxOutIndex, DEFAULT_LOOKAHEAD};
use bdk_wallet::chain::local_chain::LocalChain;
use bdk_wallet::chain::{keychain_txout, ChainPosition, IndexedTxGraph};
use bdk_wallet::{ChangeSet, KeychainKind, PersistedWallet, SignOptions, Update, Wallet};
use rustls::crypto::ring::default_provider;
use std::collections::HashSet;
use std::io::Write;
use std::time::Instant;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

// Create and persist a BDK wallet to postgres.

// wallet 1
pub const DESCRIPTOR: &str = "tr(tprv8ZgxMBicQKsPdDArR4xSAECuVxeX1jwwSXR4ApKbkYgZiziDc4LdBy2WvJeGDfUSE4UT4hHhbgEwbdq8ajjUHiKDegkwrNU6V55CxcxonVN/0/*)";
pub const CHANGE_DESCRIPTOR: &str = "tr(tprv8ZgxMBicQKsPdDArR4xSAECuVxeX1jwwSXR4ApKbkYgZiziDc4LdBy2WvJeGDfUSE4UT4hHhbgEwbdq8ajjUHiKDegkwrNU6V55CxcxonVN/1/*)";
pub const _FIRST_TR_ADDRESS: &str =
    "bcrt1prdfvfk2ddxe8y88qxhwkxn9cy0d2w6k98gj9smwz6tqjcnl4tdwsrf03aw";

// wallet 2
const VAULT_DESC: &str =
"wsh(andor(multi(2,[a0d3c79c/48'/1'/79'/2']tpubDEsGdqFaKUVnVNZZw8AixJ8C3yD8o6nN7hsdLfbtVRDTk3PNrQ2pcWNWNbxhdcNSgQP25pUpgRQ7qiVtN3YvSzACKizrvzSwH9SQ2Bjbbwt/0/*,[ea2484f9/48'/1'/79'/2']tpubDFjkswBXoRHKkvmHsxv4xdDqbjg1peX9zJytLeSLbXuwVgYhXgbABzC2r5MAWxqWoaUr7hWGW5TPjA9sNvxa3mX6DrNBdynDsEvwDoXGFpm/0/*,[93f245d7/48'/1'/79'/2']tpubDEVnR72gRgTsqaPFMacV6fCfaSEe56gcDomuGhk9MFeUdEi18riJCokgsZr2x1KKGRM59TJ4AQ6FuNun3khh95ceoH2ytN13nVD7yDLP5LJ/0/*),or_i(and_v(v:pkh([61cdf766/48'/1'/79'/2']tpubDEXETCw2WurhazfW5gW1z4njP6yLXDQmCGfjWGP5k3BuTQ5iZqovMr1zz1zWPhDMRn11hXGpZHodus1LysXnwREsD1ig96M24JhQCpPPpf6/0/*),after(1753228800)),thresh(2,pk([39bf48a9/48'/1'/0'/2']tpubDEr9rVFQbT1keErwxb6GuGy3RM6TEACSkFxBgziUvrDprYuM1Wm7wi6jb1gcaLrSgk6MSkGx84dS2kQQwJKxGRJ59rAvmuKTU7E3saHJLf5/0/*),s:pk([9467fdb3/48'/1'/0'/2']tpubDFEjX5BY88AbWpshPwGscwgKLtcCjeVodMbmhS6D6cbz1eGNUs3546ephbVmbHpxEhbCDrezGmFBArLxBKzPEfBcBdzQuncPm8ww2xa6UUQ/0/*),s:pk([01adf45e/48'/1'/0'/2']tpubDFPYZPeShApyWndvDUtpLSjDHGYK4tTT4BkMyTukGqbP9AXQeQhiWsbwEzyZhxgud9ZPew1FPsoLbWjfnE3veSXLeU4ViofrhVAHNXtjQWE/0/*),snl:after(1739836800))),and_v(v:thresh(2,pkh([39bf48a9/48'/1'/0'/2']tpubDEr9rVFQbT1keErwxb6GuGy3RM6TEACSkFxBgziUvrDprYuM1Wm7wi6jb1gcaLrSgk6MSkGx84dS2kQQwJKxGRJ59rAvmuKTU7E3saHJLf5/2/*),a:pkh([9467fdb3/48'/1'/0'/2']tpubDFEjX5BY88AbWpshPwGscwgKLtcCjeVodMbmhS6D6cbz1eGNUs3546ephbVmbHpxEhbCDrezGmFBArLxBKzPEfBcBdzQuncPm8ww2xa6UUQ/2/*),a:pkh([01adf45e/48'/1'/0'/2']tpubDFPYZPeShApyWndvDUtpLSjDHGYK4tTT4BkMyTukGqbP9AXQeQhiWsbwEzyZhxgud9ZPew1FPsoLbWjfnE3veSXLeU4ViofrhVAHNXtjQWE/2/*)),after(1757116800))))";
const CHANGE_DESC: &str =
"wsh(andor(multi(2,[a0d3c79c/48'/1'/79'/2']tpubDEsGdqFaKUVnVNZZw8AixJ8C3yD8o6nN7hsdLfbtVRDTk3PNrQ2pcWNWNbxhdcNSgQP25pUpgRQ7qiVtN3YvSzACKizrvzSwH9SQ2Bjbbwt/1/*,[ea2484f9/48'/1'/79'/2']tpubDFjkswBXoRHKkvmHsxv4xdDqbjg1peX9zJytLeSLbXuwVgYhXgbABzC2r5MAWxqWoaUr7hWGW5TPjA9sNvxa3mX6DrNBdynDsEvwDoXGFpm/1/*,[93f245d7/48'/1'/79'/2']tpubDEVnR72gRgTsqaPFMacV6fCfaSEe56gcDomuGhk9MFeUdEi18riJCokgsZr2x1KKGRM59TJ4AQ6FuNun3khh95ceoH2ytN13nVD7yDLP5LJ/1/*),or_i(and_v(v:pkh([61cdf766/48'/1'/79'/2']tpubDEXETCw2WurhazfW5gW1z4njP6yLXDQmCGfjWGP5k3BuTQ5iZqovMr1zz1zWPhDMRn11hXGpZHodus1LysXnwREsD1ig96M24JhQCpPPpf6/1/*),after(1753228800)),thresh(2,pk([39bf48a9/48'/1'/0'/2']tpubDEr9rVFQbT1keErwxb6GuGy3RM6TEACSkFxBgziUvrDprYuM1Wm7wi6jb1gcaLrSgk6MSkGx84dS2kQQwJKxGRJ59rAvmuKTU7E3saHJLf5/1/*),s:pk([9467fdb3/48'/1'/0'/2']tpubDFEjX5BY88AbWpshPwGscwgKLtcCjeVodMbmhS6D6cbz1eGNUs3546ephbVmbHpxEhbCDrezGmFBArLxBKzPEfBcBdzQuncPm8ww2xa6UUQ/1/*),s:pk([01adf45e/48'/1'/0'/2']tpubDFPYZPeShApyWndvDUtpLSjDHGYK4tTT4BkMyTukGqbP9AXQeQhiWsbwEzyZhxgud9ZPew1FPsoLbWjfnE3veSXLeU4ViofrhVAHNXtjQWE/1/*),snl:after(1739836800))),and_v(v:thresh(2,pkh([39bf48a9/48'/1'/0'/2']tpubDEr9rVFQbT1keErwxb6GuGy3RM6TEACSkFxBgziUvrDprYuM1Wm7wi6jb1gcaLrSgk6MSkGx84dS2kQQwJKxGRJ59rAvmuKTU7E3saHJLf5/3/*),a:pkh([9467fdb3/48'/1'/0'/2']tpubDFEjX5BY88AbWpshPwGscwgKLtcCjeVodMbmhS6D6cbz1eGNUs3546ephbVmbHpxEhbCDrezGmFBArLxBKzPEfBcBdzQuncPm8ww2xa6UUQ/3/*),a:pkh([01adf45e/48'/1'/0'/2']tpubDFPYZPeShApyWndvDUtpLSjDHGYK4tTT4BkMyTukGqbP9AXQeQhiWsbwEzyZhxgud9ZPew1FPsoLbWjfnE3veSXLeU4ViofrhVAHNXtjQWE/3/*)),after(1757116800))))";

const NETWORK: Network = Network::Regtest;
const STOP_GAP: usize = 50;
const BATCH_SIZE: usize = 5;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    default_provider()
        .install_default()
        .expect("Failed to install rustls default crypto provider");

    tracing_subscriber::registry()
        .with(EnvFilter::new(std::env::var("RUST_LOG").unwrap_or_else(
            |_| {
                "sqlx=warn,\
                    bdk_sqlx=debug,trace"
                    .into()
            },
        )))
        .with(tracing_subscriber::fmt::layer())
        .try_init()?;

    let url = std::env::var("DATABASE_URL").expect("must set DATABASE_URL");
    let electrum_url =
        std::env::var("ELECTRUM_URL").unwrap_or_else(|_| "localhost:50001".to_string());

    // Load wallet 1 + sync with electrum
    let secp = Secp256k1::new();
    let wallet_name = bdk_wallet::wallet_name_from_descriptor(
        DESCRIPTOR,
        Some(CHANGE_DESCRIPTOR),
        NETWORK,
        &secp,
    )?;

    let mut store = PgStoreBuilder::new(wallet_name.clone())
        .network(NETWORK)
        .migrate(true)
        .build_with_url(&url)
        .await?;

    let mut wallet = match Wallet::load().load_wallet_async(&mut store).await? {
        Some(wallet) => wallet,
        None => {
            let mut wallet = Wallet::create(DESCRIPTOR, CHANGE_DESCRIPTOR)
                .network(Network::Regtest)
                .create_wallet_async(&mut store)
                .await?;
            println!(
                "Descriptor: {}",
                wallet.public_descriptor(KeychainKind::External)
            );
            wallet
        }
    };

    print!("Syncing...");
    electrum(&mut wallet, &electrum_url)?;
    let _ = wallet.persist_async(&mut store).await?;

    println!("Balance {}", wallet.balance().total().display_dynamic());

    // Transaction demonstration
    println!("\n=== Transaction Demonstration ===");

    // List existing transactions
    list_transactions(&wallet);

    // Create and sign a transaction with RBF if we have funds
    let balance = wallet.balance();
    if balance.total() > Amount::from_sat(10_000) {
        match create_rbf_transaction(&mut wallet, &electrum_url).await {
            Ok(txid) => {
                println!("\nCreated transaction: {}", txid);
                // Persist wallet state after creating transaction
                wallet.persist_async(&mut store).await?;

                // Sync again to see the new transaction
                println!("\nSyncing to see new transaction...");
                electrum(&mut wallet, &electrum_url)?;
                wallet.persist_async(&mut store).await?;

                // List transactions again to show the new one
                list_transactions(&wallet);

                // Verify persistence by loading a new wallet instance
                println!("\n=== Verifying Persistence ===");
                verify_transaction_persisted(&url, &wallet_name, txid).await?;

                // List UTXOs and demonstrate coin control
                println!("\n=== UTXO Management ===");
                let utxos_before = wallet.list_unspent().count();
                println!("Total UTXOs before second transaction: {}", utxos_before);

                if let Some(selected_utxo) = list_and_select_utxos(&wallet) {
                    // Create a valid transaction using coin control
                    println!("\n=== Coin Control Transaction ===");
                    match create_coincontrol_transaction(&mut wallet, selected_utxo, &electrum_url)
                        .await
                    {
                        Ok(txid2) => {
                            println!("\nSuccessfully created second transaction: {}", txid2);
                            wallet.persist_async(&mut store).await?;

                            // Sync and show the result
                            println!("\nSyncing after second transaction...");
                            electrum(&mut wallet, &electrum_url)?;
                            wallet.persist_async(&mut store).await?;

                            let utxos_after = wallet.list_unspent().count();
                            println!("\nTotal UTXOs after second transaction: {}", utxos_after);
                            println!(
                                "UTXO count changed from {} to {}",
                                utxos_before, utxos_after
                            );

                            // Now demonstrate double-spend attempt
                            println!("\n=== Double-Spend Attempt ===");
                            println!(
                                "Attempting to spend the same UTXO again (this should fail)..."
                            );

                            match create_double_spend_transaction(
                                &mut wallet,
                                selected_utxo,
                                &electrum_url,
                            )
                            .await
                            {
                                Ok(_) => {
                                    println!("Double-spend succeeded!");
                                }
                                Err(e) => {
                                    println!("✓ Double-spend correctly failed: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            bail!("Failed to create second transaction: {}", e);
                        }
                    }
                }
            }
            Err(e) => bail!("Failed to create transaction: {}", e),
        }
    } else {
        println!("\nInsufficient balance to create a transaction. Need at least 10,000 sats.");
        bail!("Current balance: {} sats", balance.total().to_sat());
    }

    // Load wallet 2
    let wallet_name =
        bdk_wallet::wallet_name_from_descriptor(VAULT_DESC, Some(CHANGE_DESC), NETWORK, &secp)?;

    let mut store = PgStoreBuilder::new(wallet_name.clone())
        .network(NETWORK)
        .migrate(true)
        .build_with_url(&url)
        .await?;

    let mut wallet = match Wallet::load().load_wallet_async(&mut store).await? {
        Some(wallet) => wallet,
        None => {
            let wallet = Wallet::create(VAULT_DESC, CHANGE_DESC)
                .network(Network::Regtest)
                .create_wallet_async(&mut store)
                .await?;
            println!(
                "Descriptor: {}",
                wallet.public_descriptor(KeychainKind::External)
            );
            wallet
        }
    };

    let addr = wallet.reveal_next_address(KeychainKind::External);
    wallet.persist_async(&mut store).await?;

    println!(
        "2nd wallet address ({:?} {}) {}",
        addr.keychain, addr.index, addr.address,
    );

    // Run SPK cache performance test
    test_spk_cache_performance(&url).await?;

    Ok(())
}

fn electrum(
    wallet: &mut PersistedWallet<Store<Postgres>>,
    electrum_url: &str,
) -> anyhow::Result<()> {
    let client = BdkElectrumClient::new(electrum_client::Client::new(electrum_url)?);
    let request = wallet.start_full_scan().build();
    let res = client.full_scan::<_>(request, STOP_GAP, BATCH_SIZE, true)?;
    wallet.apply_update(res)?;
    Ok(())
}

fn list_transactions(wallet: &PersistedWallet<Store<Postgres>>) {
    println!("\n--- Wallet Transactions ---");

    let transactions = wallet.transactions();
    let mut tx_count = 0;
    let mut displayed_count = 0;

    for tx in transactions {
        tx_count += 1;

        // Skip the first 100 transactions (mining transactions)
        if tx_count <= 100 {
            continue;
        }

        displayed_count += 1;
        let txid = tx.tx_node.txid;
        let tx_ref = tx.tx_node.tx.as_ref();

        // Get sent and received amounts
        let (sent, received) = wallet.sent_and_received(tx_ref);
        let fee = wallet.calculate_fee(tx_ref);

        // Check confirmation status
        match tx.chain_position {
            ChainPosition::Confirmed { ref anchor, .. } => {
                println!("\nTransaction: {}", txid);
                println!("  Status: Confirmed at height {}", anchor.block_id.height);
                println!("  Sent: {} sats", sent.to_sat());
                println!("  Received: {} sats", received.to_sat());
                if let Ok(fee_amount) = &fee {
                    println!("  Fee: {} sats", fee_amount.to_sat());
                }
            }
            ChainPosition::Unconfirmed { last_seen, .. } => {
                println!("\nTransaction: {}", txid);
                println!("  Status: Unconfirmed");
                println!("  Sent: {} sats", sent.to_sat());
                println!("  Received: {} sats", received.to_sat());
                if let Ok(fee_amount) = &fee {
                    println!("  Fee: {} sats", fee_amount.to_sat());
                }
            }
        }
    }

    if displayed_count == 0 {
        if tx_count > 100 {
            println!("No non-mining transactions found.");
        } else {
            println!(
                "No transactions found beyond the initial {} mining transactions.",
                tx_count
            );
        }
    } else {
        println!(
            "\nTotal non-mining transactions: {} (skipped first 100 mining transactions)",
            displayed_count
        );
    }
}

async fn create_rbf_transaction(
    wallet: &mut PersistedWallet<Store<Postgres>>,
    electrum_url: &str,
) -> anyhow::Result<bdk_wallet::bitcoin::Txid> {
    println!("\n--- Creating RBF Transaction ---");

    // Get a fresh address to send to (for demo purposes, sending to ourselves)
    let recipient_address = wallet.reveal_next_address(KeychainKind::External);
    println!("Recipient address: {}", recipient_address.address);

    // Build the transaction
    let amount_to_send = Amount::from_sat(5_000); // Send 5000 sats
    let fee_rate = FeeRate::from_sat_per_vb(2).expect("valid fee rate"); // 2 sat/vbyte

    let mut tx_builder = wallet.build_tx();
    tx_builder
        .include_output_redeem_witness_script()
        .add_recipient(recipient_address.address.script_pubkey(), amount_to_send)
        .fee_rate(fee_rate);
    //.enable_rbf(); //  Replace-By-Fee enabled by default

    println!("Building transaction with RBF enabled...");
    println!("  Amount: {} sats", amount_to_send.to_sat());
    println!("  Fee rate: {} sat/vbyte", fee_rate.to_sat_per_vb_ceil());

    // Finish building and get the PSBT
    let mut psbt = tx_builder.finish()?;

    // Sign the transaction
    println!("\nSigning transaction...");
    let finalized = wallet.sign(&mut psbt, SignOptions::default())?;

    let tx = psbt.clone().extract_tx()?;
    let txid = tx.clone().compute_txid();

    if !finalized {
        bail!("Failed to finalize transaction");
    }

    // Extract the signed transaction
    // let tx = psbt.extract_tx()?;
    // let txid = tx.compute_txid();

    println!("Transaction signed successfully!");
    println!("Transaction ID: {}", txid);

    // Broadcast the transaction
    println!("\nBroadcasting transaction...");
    let client = electrum_client::Client::new(electrum_url)?;
    let mut tx_raw = Vec::new();
    tx.consensus_encode(&mut tx_raw).expect("can encode tx");
    match client.transaction_broadcast_raw(&tx_raw) {
        Ok(_) => {
            println!("Transaction broadcast successfully!");
            Ok(txid)
        }
        Err(e) => {
            println!("Failed to broadcast: {}", e);
            bail!("Broadcast failed: {}", e)
        }
    }
}

async fn verify_transaction_persisted(
    url: &str,
    wallet_name: &str,
    txid: bdk_wallet::bitcoin::Txid,
) -> anyhow::Result<()> {
    println!("Loading a new wallet instance from persistence...");

    // Create a new store connection
    let mut store = PgStoreBuilder::new(wallet_name.to_string())
        .network(NETWORK)
        .migrate(false) // Don't migrate, just connect
        .build_with_url(url)
        .await?;

    // Load the wallet from persistence
    let wallet = match Wallet::load().load_wallet_async(&mut store).await? {
        Some(wallet) => wallet,
        None => {
            bail!("Failed to load wallet from persistence");
        }
    };

    println!("Wallet loaded successfully from persistence!");

    // Check if the transaction exists in the loaded wallet
    if let Some(tx_details) = wallet.get_tx(txid) {
        println!("\n✓ Transaction found in persisted wallet!");
        println!("  Transaction ID: {}", txid);
        println!("  Chain position: {:?}", tx_details.chain_position);

        let (sent, received) = wallet.sent_and_received(&tx_details.tx_node.tx);
        println!("  Sent: {} sats", sent.to_sat());
        println!("  Received: {} sats", received.to_sat());

        if let Ok(fee) = wallet.calculate_fee(&tx_details.tx_node.tx) {
            println!("  Fee: {} sats", fee.to_sat());
        }
    } else {
        println!("\n✗ Transaction NOT found in persisted wallet!");
        bail!("Transaction not found after persistence");
    }

    Ok(())
}

fn list_and_select_utxos(
    wallet: &PersistedWallet<Store<Postgres>>,
) -> Option<bdk_wallet::bitcoin::OutPoint> {
    println!("Listing available UTXOs...");

    let mut utxos: Vec<_> = wallet.list_unspent().collect();

    if utxos.is_empty() {
        println!("No UTXOs available");
        return None;
    }

    // Sort UTXOs by confirmation height (oldest first)
    utxos.sort_by(|a, b| {
        match (&a.chain_position, &b.chain_position) {
            (
                ChainPosition::Confirmed {
                    anchor: a_anchor, ..
                },
                ChainPosition::Confirmed {
                    anchor: b_anchor, ..
                },
            ) => a_anchor.block_id.height.cmp(&b_anchor.block_id.height),
            (ChainPosition::Confirmed { .. }, ChainPosition::Unconfirmed { .. }) => {
                std::cmp::Ordering::Less // Confirmed comes before unconfirmed
            }
            (ChainPosition::Unconfirmed { .. }, ChainPosition::Confirmed { .. }) => {
                std::cmp::Ordering::Greater // Unconfirmed comes after confirmed
            }
            (ChainPosition::Unconfirmed { .. }, ChainPosition::Unconfirmed { .. }) => {
                std::cmp::Ordering::Equal // Both unconfirmed, treat as equal
            }
        }
    });

    println!(
        "\nFound {} UTXOs (sorted by age, oldest first):",
        utxos.len()
    );

    for (index, utxo) in utxos.iter().enumerate() {
        println!("\nUTXO #{}:", index + 1);
        println!("  Outpoint: {}", utxo.outpoint);
        println!("  Value: {} sats", utxo.txout.value.to_sat());
        println!("  Keychain: {:?}", utxo.keychain);
        println!("  Derivation index: {}", utxo.derivation_index);
        println!("  Confirmed: {}", utxo.chain_position.is_confirmed());

        if let ChainPosition::Confirmed { anchor, .. } = &utxo.chain_position {
            println!("  Block height: {}", anchor.block_id.height);
        }
    }

    // Select the oldest UTXO (first after sorting)
    let selected = utxos.first().map(|utxo| utxo.outpoint);

    if let Some(outpoint) = selected {
        println!("\n→ Selected oldest UTXO: {}", outpoint);
    }

    selected
}

async fn create_coincontrol_transaction(
    wallet: &mut PersistedWallet<Store<Postgres>>,
    utxo_to_spend: bdk_wallet::bitcoin::OutPoint,
    electrum_url: &str,
) -> anyhow::Result<bdk_wallet::bitcoin::Txid> {
    println!("Creating transaction with coin control...");
    println!("Attempting to spend UTXO: {}", utxo_to_spend);

    // Get a fresh address
    let recipient_address = wallet.reveal_next_address(KeychainKind::External);
    println!("Recipient address: {}", recipient_address.address);

    // Build transaction using only the selected UTXO
    let amount_to_send = Amount::from_sat(1_000); // Send 1000 sats
    let fee_rate = FeeRate::from_sat_per_vb(2).expect("valid fee rate");

    let mut tx_builder = wallet.build_tx();
    tx_builder
        .add_utxo(utxo_to_spend)? // Add specific UTXO
        .manually_selected_only() // ONLY use manually selected UTXOs
        .add_recipient(recipient_address.address.script_pubkey(), amount_to_send)
        .fee_rate(fee_rate);

    println!("Building transaction with coin control...");
    println!("  Selected UTXO: {}", utxo_to_spend);
    println!("  Amount: {} sats", amount_to_send.to_sat());
    println!("  Fee rate: {} sat/vbyte", fee_rate.to_sat_per_vb_ceil());

    // Try to finish building
    let mut psbt = tx_builder.finish()?;

    // Sign the transaction
    println!("\nSigning transaction...");
    let finalized = wallet.sign(&mut psbt, SignOptions::default())?;

    if !finalized {
        bail!("Failed to finalize transaction");
    }

    let tx = psbt.extract_tx().expect("valid tx");
    let txid = tx.compute_txid();

    println!("Transaction signed successfully!");
    println!("Transaction ID: {}", txid);

    // Try to broadcast (this should fail if spending already spent coins)
    println!("\nBroadcasting transaction...");
    let client = electrum_client::Client::new(electrum_url)?;
    let mut tx_raw = Vec::new();
    tx.consensus_encode(&mut tx_raw).expect("can encode tx");

    match client.transaction_broadcast_raw(&tx_raw) {
        Ok(_) => {
            println!("Transaction broadcast successfully!");
            Ok(txid)
        }
        Err(e) => {
            println!("Broadcast failed (expected for double-spend): {}", e);
            bail!("Broadcast failed: {}", e)
        }
    }
}

async fn create_double_spend_transaction(
    wallet: &mut PersistedWallet<Store<Postgres>>,
    utxo_to_spend: bdk_wallet::bitcoin::OutPoint,
    electrum_url: &str,
) -> anyhow::Result<bdk_wallet::bitcoin::Txid> {
    println!("Attempting to create a double-spend transaction...");
    println!(
        "Trying to spend UTXO: {} (which was already spent)",
        utxo_to_spend
    );

    // Get a fresh address
    let recipient_address = wallet.reveal_next_address(KeychainKind::External);

    // Try to build transaction using the already-spent UTXO
    let amount_to_send = Amount::from_sat(500); // Different amount
    let fee_rate = FeeRate::from_sat_per_vb(5).expect("valid fee rate"); // Higher fee

    let mut tx_builder = wallet.build_tx();
    tx_builder
        .add_utxo(utxo_to_spend)? // Try to add the already-spent UTXO
        .manually_selected_only()
        .add_recipient(recipient_address.address.script_pubkey(), amount_to_send)
        .fee_rate(fee_rate);

    // This should fail because the UTXO is already spent
    match tx_builder.finish() {
        Ok(mut psbt) => {
            // If we somehow got here, try to sign and broadcast
            println!("WARNING: Transaction building succeeded when it should have failed!");

            let finalized = wallet.sign(&mut psbt, SignOptions::default())?;
            if !finalized {
                bail!("Failed to finalize double-spend transaction");
            }

            let tx = psbt.extract_tx().expect("valid tx");
            let txid = tx.compute_txid();

            // Try to broadcast
            let client = electrum_client::Client::new(electrum_url)?;
            let mut tx_raw = Vec::new();
            tx.consensus_encode(&mut tx_raw).expect("can encode tx");

            match client.transaction_broadcast_raw(&tx_raw) {
                Ok(_) => Ok(txid),
                Err(e) => bail!("Broadcast failed: {}", e),
            }
        }
        Err(e) => {
            // This is the expected path
            bail!("Transaction building failed (expected): {}", e)
        }
    }
}

async fn test_spk_cache_performance(url: &str) -> anyhow::Result<()> {
    println!("\n\n=== SPK Cache Performance Test ===");
    println!("Testing performance with 3000 derived addresses...\n");

    let secp = Secp256k1::new();
    let wallet_name = "spk_cache_test_wallet";

    // Create a fresh store for this test
    let mut store = PgStoreBuilder::new(wallet_name.to_string())
        .network(NETWORK)
        .migrate(true)
        .build_with_url(url)
        .await?;

    // Step 1: Create wallet and derive 3000 addresses
    println!("1. Creating wallet and deriving 3000 addresses for each keychain...");
    let start = Instant::now();

    let mut wallet = Wallet::create(DESCRIPTOR, CHANGE_DESCRIPTOR)
        .network(NETWORK)
        .use_spk_cache(true)
        .create_wallet_async(&mut store)
        .await?;

    // Derive 3000 addresses for external keychain
    let external_addresses: Vec<_> = wallet
        .reveal_addresses_to(KeychainKind::External, 2999)
        .collect();
    println!(
        "   Generated {} external addresses",
        external_addresses.len()
    );

    // Derive 3000 addresses for internal keychain
    let internal_addresses: Vec<_> = wallet
        .reveal_addresses_to(KeychainKind::Internal, 2999)
        .collect();
    println!(
        "   Generated {} internal addresses",
        internal_addresses.len()
    );

    let derivation_time = start.elapsed();
    println!("   Address derivation took: {:?}", derivation_time);

    // Step 2: Persist the wallet with all derived addresses
    println!("\n2. Persisting wallet to database...");
    let persist_start = Instant::now();
    wallet.persist_async(&mut store).await?;
    let persist_time = persist_start.elapsed();
    println!("   Persistence took: {:?}", persist_time);

    // Step 3: Drop the wallet and reload from database
    println!("\n3. Loading wallet from database (this regenerates all SPKs)...");
    drop(wallet);
    drop(store);

    // Create a new store instance
    let mut store = PgStoreBuilder::new(wallet_name.to_string())
        .network(NETWORK)
        .migrate(false) // Don't migrate, just connect
        .build_with_url(url)
        .await?;

    // Measure loading time
    let load_start = Instant::now();
    let loaded_wallet = match Wallet::load()
        .use_spk_cache(true)
        .load_wallet_async(&mut store)
        .await?
    {
        Some(wallet) => wallet,
        None => {
            bail!("Failed to load wallet from persistence");
        }
    };
    let load_time = load_start.elapsed();
    println!("   Loading took: {:?}", load_time);

    // Verify the addresses were loaded correctly
    let last_revealed_external = loaded_wallet
        .derivation_index(KeychainKind::External)
        .expect("external keychain should exist");
    let last_revealed_internal = loaded_wallet
        .derivation_index(KeychainKind::Internal)
        .expect("internal keychain should exist");

    println!("\n4. Verification:");
    println!(
        "   Last revealed external index: {}",
        last_revealed_external
    );
    println!(
        "   Last revealed internal index: {}",
        last_revealed_internal
    );

    // Summary
    println!("\n=== Performance Summary ===");
    println!("Address derivation time: {:?}", derivation_time);
    println!("Database persistence time: {:?}", persist_time);
    println!(
        "Wallet loading time (with SPK regeneration): {:?}",
        load_time
    );
    println!(
        "Total addresses regenerated on load: {}",
        (last_revealed_external + 1) + (last_revealed_internal + 1)
    );

    Ok(())
}
