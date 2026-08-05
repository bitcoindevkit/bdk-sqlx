//! Tests for the process-global network configuration of `PgStoreBuilder`.
//!
//! The configured network is held in a process-wide `OnceLock`, so these tests
//! live in their own integration-test binary: in-process unit tests share the
//! global with every other test and could not exercise it deterministically.
//!
//! The pools are lazy, so no database server is needed: `build()` with
//! `migrate(false)` never touches the pool.

use bdk_sqlx::sqlx::postgres::PgPoolOptions;
use bdk_sqlx::sqlx::PgPool;
use bdk_sqlx::{BdkSqlxError, PgStoreBuilder};
use bdk_wallet::bitcoin::Network;

fn lazy_pool() -> PgPool {
    PgPoolOptions::new()
        .connect_lazy("postgres://127.0.0.1:1/bdk_sqlx_offline")
        .expect("lazy pool creation does not connect")
}

/// All scenarios in one test so ordering inside this process is deterministic:
/// the first build fixes the global network for the rest of the process.
#[tokio::test]
async fn network_config_is_process_global() {
    // first build initializes the global network
    PgStoreBuilder::new("wallet_a".into())
        .network(Network::Regtest)
        .pool(lazy_pool())
        .build()
        .await
        .expect("first build must succeed");

    // re-initializing with the same network is tolerated
    PgStoreBuilder::new("wallet_b".into())
        .network(Network::Regtest)
        .pool(lazy_pool())
        .build()
        .await
        .expect("re-init with the same network must succeed");

    // a different network in the same process is rejected
    let result = PgStoreBuilder::new("wallet_c".into())
        .network(Network::Bitcoin)
        .pool(lazy_pool())
        .build()
        .await;
    assert!(
        matches!(
            result,
            Err(BdkSqlxError::DuplicateInitNetwork {
                current: Network::Regtest,
                network: Network::Bitcoin,
            })
        ),
        "expected DuplicateInitNetwork, got {result:?}"
    );
}

/// Regression test: `initialize_network` used to read the `OnceLock` and then
/// set it, so two threads racing the first initialization with the SAME
/// network could produce a spurious `SetNetworkFailure` for the loser.
/// Same-network initialization must be idempotent under concurrency.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_same_network_init_never_fails() {
    let mut handles = Vec::new();
    for i in 0..16 {
        handles.push(tokio::spawn(async move {
            PgStoreBuilder::new(format!("race_{i}"))
                .network(Network::Regtest)
                .pool(lazy_pool())
                .build()
                .await
        }));
    }
    for handle in handles {
        handle
            .await
            .expect("task panicked")
            .expect("same-network initialization must never fail");
    }
}
