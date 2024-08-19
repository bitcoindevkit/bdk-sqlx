use bdk_wallet::bitcoin::secp256k1::Secp256k1;
use bdk_wallet::bitcoin::Network;
use bdk_wallet::{KeychainKind, Wallet};
use better_panic::Settings;
// Create and persist a BDK wallet to an async storage backend.

const DESC: &str = "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84'/1'/0'/0/*)";

type Result<T, E = Box<dyn std::error::Error>> = core::result::Result<T, E>;

#[tokio::main]
async fn main() -> Result<()> {
    Settings::debug()
        .most_recent_first(false)
        .lineno_suffix(true)
        .install();

    let url = std::env::var("DATABASE_URL").expect("must set DATABASE_URL");

    let mut store = bdk_sqlx::Store::new(&url, Network::Signet).await.unwrap();

    let wallet_name =
        bdk_wallet::wallet_name_from_descriptor(DESC, None, Network::Signet, &Secp256k1::new())
            .unwrap();
    let mut wallet = match Wallet::load()
        .load_wallet_async(&mut store, wallet_name.clone())
        .await
        .unwrap()
    {
        Some(wallet) => wallet,
        None => {
            let wallet = Wallet::create_single(DESC)
                .network(Network::Signet)
                .create_wallet_async(&mut store, wallet_name.clone())
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
    assert!(wallet.persist_async(&mut store, wallet_name).await?);

    println!(
        "Address ({:?} {}) {}",
        addr.keychain, addr.index, addr.address,
    );

    Ok(())
}
