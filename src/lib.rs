//! bdk-sqlx

#![warn(missing_docs)]
#![forbid(unsafe_code)]

mod postgres;
mod sqlite;

#[cfg(test)]
mod test;

use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::OnceLock;

use bdk_wallet::bitcoin;
use bdk_wallet::bitcoin::{BlockHash, Network, Txid};
use bdk_wallet::chain::miniscript;
use bdk_wallet::chain::DescriptorExt;
use bdk_wallet::descriptor::{Descriptor, DescriptorPublicKey};
use bdk_wallet::ChangeSet;
/// Re-export of the [`sqlx`] crate this library is built on.
///
/// Consumers that construct pools themselves should import sqlx types through this
/// re-export so their sqlx version always matches the one this crate links against.
/// Note this couples the crate's public API to sqlx's major version: a sqlx major
/// bump is a breaking change for this crate as well.
pub use sqlx;
use sqlx::Pool;
use sqlx::{Database, PgPool};

/// Crate error
#[derive(Debug, thiserror::Error)]
pub enum BdkSqlxError {
    /// bitcoin parse hex error
    #[error("bitcoin parse hex error: {0}")]
    HexToArray(#[from] bitcoin::hex::HexToArrayError),
    /// bitcoin consensus decode error
    #[error("bitcoin consensus decode error: {0}")]
    Consensus(#[from] bitcoin::consensus::encode::Error),
    /// stored transaction bytes decode to a different txid than the stored txid
    #[error("decoded transaction txid {computed} does not match stored txid {stored}")]
    TxidMismatch {
        /// txid stored alongside the transaction bytes
        stored: Txid,
        /// txid computed from the decoded transaction
        computed: Txid,
    },
    /// stored anchor references a different block hash than the stored block_hash
    #[error("anchor block hash {computed} does not match stored block_hash {stored}")]
    AnchorBlockHashMismatch {
        /// block hash stored in the block_hash column
        stored: BlockHash,
        /// block hash contained in the anchor payload
        computed: BlockHash,
    },
    /// a changeset maps the same block hash to more than one height, which the
    /// block table cannot represent (its key is the hash itself)
    #[error(
        "changeset maps block hash {hash} to both height {first_height} and height {second_height}"
    )]
    DuplicateBlockHash {
        /// offending block hash
        hash: BlockHash,
        /// first height the hash was mapped to
        first_height: u32,
        /// second, conflicting height
        second_height: u32,
    },
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
    /// a stored keychainkind is neither of the two kinds this store writes
    /// ('External'/'Internal'); the row is corrupt and must not be silently
    /// skipped, or a keychain would vanish from the loaded wallet
    #[error("stored keychain kind '{got}' is not 'External' or 'Internal'")]
    InvalidKeychainKind {
        /// offending keychainkind value
        got: String,
    },
    /// Config error
    #[error("Network Missing")]
    MissingNetwork,
    /// Config error
    #[error("No database connection pool provided to the builder")]
    MissingPool,
    /// Config error
    #[error("Network Failed to set")]
    SetNetworkFailure(Network),
    /// Config error
    #[error("Cant get network because its not set")]
    GetNetworkFailure,
    /// integer value outside the range representable for its destination
    #[error("integer value out of range for {context}: {value}")]
    IntOutOfRange {
        /// column or field the value belongs to
        context: &'static str,
        /// offending value
        value: i128,
    },
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
#[derive(Debug)]
pub struct Store<DB: Database> {
    pub(crate) pool: Pool<DB>,
    wallet_name: String,
}

// Manual impl: deriving Clone would bound `DB: Clone`, which sqlx's `Postgres`
// and `Sqlite` marker types do not satisfy, making the derived impl unusable
// for the actual backends. Cloning a store shares the connection pool.
impl<DB: Database> Clone for Store<DB> {
    fn clone(&self) -> Self {
        Self {
            pool: self.pool.clone(),
            wallet_name: self.wallet_name.clone(),
        }
    }
}

/// Build a new instance of the PgStoreBuilder
pub struct PgStoreBuilder {
    wallet_name: String,
    pool: Option<PgPool>,
    migrate: bool,
    network: Option<Network>,
}

/// Build a new instance of the SqliteStoreBuilder
pub struct SqliteStoreBuilder {
    wallet_name: String,
    pool: Option<Pool<sqlx::Sqlite>>,
    migrate: bool,
    network: Option<Network>,
}

type FutureResult<'a, T, E> = Pin<Box<dyn Future<Output = Result<T, E>> + Send + 'a>>;

/// Converts an integer crossing the database boundary, erroring instead of wrapping
/// when the value does not fit the destination type (e.g. a negative amount or height).
pub(crate) fn checked_conv<T, U>(value: T, context: &'static str) -> Result<U, BdkSqlxError>
where
    T: Copy + Into<i128>,
    U: TryFrom<T>,
{
    U::try_from(value).map_err(|_| BdkSqlxError::IntOutOfRange {
        context,
        value: value.into(),
    })
}

/// Process-global network configuration, shared by every store in the process
/// regardless of backend. Persisting data for the wrong network wedges a
/// wallet store, so the first store built fixes the network for the whole
/// process and all stores validate against it.
static NETWORK: OnceLock<Network> = OnceLock::new();

/// Returns the process-global network, or an error if no store has set it yet.
pub(crate) fn get_network() -> Result<Network, BdkSqlxError> {
    NETWORK
        .get()
        .copied()
        .ok_or(BdkSqlxError::GetNetworkFailure)
}

/// Fixes the process-global network on first call. Later calls with the same
/// network are no-ops; a different network is rejected.
pub(crate) fn initialize_network(network: Network) -> Result<(), BdkSqlxError> {
    if NETWORK.get().is_none() {
        // A racing `set` is fine: the winner's value is validated below, so
        // concurrent same-network builds can no longer fail spuriously.
        let _ = NETWORK.set(network);
    }
    match NETWORK.get() {
        Some(current) if *current == network => Ok(()),
        Some(current) => Err(BdkSqlxError::DuplicateInitNetwork {
            current: *current,
            network,
        }),
        // Unreachable in practice: either our `set` won or a racer's did.
        None => Err(BdkSqlxError::SetNetworkFailure(network)),
    }
}

/// Rejects `network` when this process was configured for a different one.
///
/// Applied on the write path (a changeset's network) and the read path (the
/// stored network) of every backend. When the process-global network is not
/// set there is nothing to validate against and the check passes; stores
/// built through the public constructors always set it.
pub(crate) fn validate_network_matches_configured(network: Network) -> Result<(), BdkSqlxError> {
    if let Ok(configured) = get_network() {
        if configured != network {
            return Err(BdkSqlxError::InvalidNetwork {
                expected: configured.to_string(),
                got: network.to_string(),
            });
        }
    }
    Ok(())
}

/// Parses a network name read back from the database, rejecting both
/// unparseable names and networks this process was not configured for.
pub(crate) fn parse_and_validate_network(stored: &str) -> Result<Network, BdkSqlxError> {
    let network = Network::from_str(stored).map_err(|_| BdkSqlxError::InvalidNetwork {
        expected: get_network()
            .map(|n| n.to_string())
            .unwrap_or_else(|_| "a known network".to_string()),
        got: stored.to_string(),
    })?;
    validate_network_matches_configured(network)?;
    Ok(network)
}

/// Applies one stored keychain row to `changeset`.
///
/// Shared by both backends so the parse and validation rules cannot drift
/// apart. `keychainkind` comes from a free-text column; anything other than
/// the two kinds this store writes is corrupt data and must fail the load
/// loudly rather than silently drop a keychain.
pub(crate) fn keychain_changeset_from_parts(
    changeset: &mut ChangeSet,
    keychainkind: &str,
    descriptor_str: &str,
    last_revealed: Option<i32>,
) -> Result<(), BdkSqlxError> {
    let descriptor: Descriptor<DescriptorPublicKey> = descriptor_str.parse()?;
    let did = descriptor.descriptor_id();
    match keychainkind {
        "External" => changeset.descriptor = Some(descriptor),
        "Internal" => changeset.change_descriptor = Some(descriptor),
        other => {
            return Err(BdkSqlxError::InvalidKeychainKind {
                got: other.to_string(),
            })
        }
    }
    if let Some(last_rev) = last_revealed {
        changeset
            .indexer
            .last_revealed
            .insert(did, checked_conv(last_rev, "keychain.last_revealed")?);
    }
    Ok(())
}
