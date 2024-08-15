use bdk_wallet::bitcoin::Network;
use bdk_wallet::{KeychainKind, Wallet};

// Create and persist a BDK wallet to an async storage backend.

const DESC: &str = "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84'/1'/0'/0/*)";

type Result<T, E = Box<dyn std::error::Error>> = core::result::Result<T, E>;

#[tokio::main]
async fn main() -> Result<()> {
    let mut store = bdk_async_persist::Store::new().await?;

    let mut wallet = match Wallet::load().load_wallet_async(&mut store).await? {
        Some(wallet) => wallet,
        None => {
            Wallet::create_single(DESC)
                .network(Network::Signet)
                .create_wallet_async(&mut store)
                .await?
        }
    };

    println!(
        "Descriptor: {}",
        wallet.public_descriptor(KeychainKind::External)
    );
    let addr = wallet.reveal_next_address(KeychainKind::External);
    println!(
        "Address ({:?} {}) {}",
        addr.keychain, addr.index, addr.address,
    );
    wallet.persist_async(&mut store).await?;

    Ok(())
}
