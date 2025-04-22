//! bdk-sqlx

#![warn(missing_docs)]

mod postgres;
mod sqlite;

/// Builder for Store
pub mod pg_store_builder;
#[cfg(test)]
mod test;

use bdk_wallet::bitcoin;
use bdk_wallet::bitcoin::Network;
use bdk_wallet::chain::miniscript;
pub use sqlx;
use sqlx::Database;
use sqlx::Pool;
use std::future::Future;
use std::pin::Pin;
use std::sync::OnceLock;
use tracing::warn;

/// Result type for bdk-sqlx
pub type Result<T> = core::result::Result<T, BdkSqlxError>;

/// Thread-safe storage for the network configuration that's shared across all Store instances.
/// This ensures consistent network validation across multiple threads.
static NETWORK: OnceLock<Network> = OnceLock::new();

/// Retrieves the current global network configuration for validation operations.
///
/// Returns the current network configuration or an error if not initialized.
fn get_network() -> Result<Network> {
    NETWORK
        .get()
        .copied()
        .ok_or_else(|| BdkSqlxError::GetNetworkFailure)
}

/// Sets the global network configuration to ensure consistent validation across threads.
///
/// Returns an error if the network is already initialized with a different network.
fn initialize_network(network: Network) -> Result<()> {
    match NETWORK.get() {
        Some(current) if *current == network => {
            warn!("initialize_network called more than once");
            Ok(())
        }
        Some(current) => Err(BdkSqlxError::DuplicateInitNetwork {
            current: *current,
            network,
        }),
        None => NETWORK
            .set(network)
            .map_err(BdkSqlxError::SetNetworkFailure),
    }
}

/// Crate error
#[derive(Debug, thiserror::Error)]
pub enum BdkSqlxError {
    /// bitcoin parse hex error
    #[error("bitoin parse hex error: {0}")]
    HexToArray(#[from] bitcoin::hex::HexToArrayError),
    /// miniscript error
    #[error("miniscript error: {0}")]
    Miniscript(#[from] miniscript::Error),
    /// serde_json error
    #[error("serde_json error: {0}")]
    SerdeJson(#[from] serde_json::error::Error),
    /// sqlx error
    #[error("sqlx error: {0}")]
    Sqlx(#[from] sqlx::Error),
    /// Network confusion
    #[error("Invalid Network expected {expected}, got {got}")]
    InvalidNetwork {
        /// Expected network
        expected: String,
        /// Got network
        got: String,
    },
    /// Network is already set to a different network
    #[error("Network already set to {current}, but was tried to be initialize with {network}")]
    DuplicateInitNetwork {
        /// Current network
        current: Network,
        /// New network
        network: Network,
    },
    /// Init failure
    #[error("Cant initialize network correctly with: {0}")]
    NetworkInitFailure(Network),
    /// Config error
    #[error("Network Missing")]
    MissingNetwork,
    /// Config error
    #[error("Cant initialize Postgres connection")]
    MissingPool,
    /// Config error
    #[error("Network Failed to set")]
    SetNetworkFailure(Network),
    /// Config error
    #[error("Cant get network because its not set")]
    GetNetworkFailure,
    /// Query execution error
    #[error("Failed to execute query on {table}: {source}")]
    QueryError {
        /// action and table name associated with error
        table: String,
        /// source error
        source: sqlx::Error,
    },
}

/// Manages a pool of database connections.
#[derive(Debug, Clone)]
pub struct Store<DB: Database> {
    pub(crate) pool: Pool<DB>,
    wallet_name: String,
}

type FutureResult<'a, T, E> = Pin<Box<dyn Future<Output = std::result::Result<T, E>> + Send + 'a>>;
