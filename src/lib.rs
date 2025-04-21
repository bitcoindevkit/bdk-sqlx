//! bdk-sqlx

#![warn(missing_docs)]

mod postgres;
mod sqlite;

#[cfg(test)]
mod test;

use std::future::Future;
use std::pin::Pin;

use bdk_wallet::bitcoin;
use bdk_wallet::bitcoin::Network;
use bdk_wallet::chain::miniscript;
pub use sqlx;
use sqlx::Pool;
use sqlx::{Database, PgPool};

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
    /// migrate error
    #[error("migrate error: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    #[error("Invalid Network expected {expected}, got {got}")]
    InvalidNetwork { expected: String, got: String },
    #[error("Could not initialize network correctly with: {0}")]
    NetworkInitFailure(String),
    #[error("Network Missing")]
    MissingNetwork,
    #[error("Could not initialize Postgres connection")]
    MissingPool,
}

/// Manages a pool of database connections.
#[derive(Debug, Clone)]
pub struct Store<DB: Database> {
    pub(crate) pool: Pool<DB>,
    wallet_name: String,
}

// Add a new struct
pub struct PgStoreBuilder {
    wallet_name: String,
    pool: Option<PgPool>,
    migrate: bool,
    network: Option<Network>,
}

type FutureResult<'a, T, E> = Pin<Box<dyn Future<Output = Result<T, E>> + Send + 'a>>;
