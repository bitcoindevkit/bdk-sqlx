//! Shared generators and helpers for the `bdk-sqlx` fuzz targets.
//!
//! The targets only exercise the SQLite backend. They deliberately treat all
//! bytes as untrusted, and only assert invariants that must hold for every
//! input (no panic, successful reads are idempotent, valid anchors round-trip).

#![allow(clippy::needless_range_loop)]

use std::str::FromStr;
use std::sync::Arc;

use bdk_sqlx::sqlx::sqlite::SqlitePoolOptions;
use bdk_sqlx::sqlx::{Pool, Sqlite};
use bdk_sqlx::{BdkSqlxError, Store};
use bdk_wallet::bitcoin::absolute::LockTime;
use bdk_wallet::bitcoin::hashes::Hash;
use bdk_wallet::bitcoin::transaction;
use bdk_wallet::bitcoin::{
    Amount, BlockHash, Network, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid,
};
use bdk_wallet::chain::{BlockId, ConfirmationBlockTime, DescriptorExt};
use bdk_wallet::miniscript::{Descriptor, DescriptorPublicKey};
use bdk_wallet::{AsyncWalletPersister, ChangeSet};

pub const FIXED_EXTERNAL: &str = "wpkh(tpubD6NzVbkrYhZ4XHndKkuB8FifXm8r5FQHwrN6oZuWCz13qb93rtgKvD4PQsqC4HP4yhV3tA2fqr2RbY5mNXfM7RxXUoeABoDtsFUq2zJq6YK/0/*)";
pub const FIXED_INTERNAL: &str = "wpkh(tpubD6NzVbkrYhZ4XHndKkuB8FifXm8r5FQHwrN6oZuWCz13qb93rtgKvD4PQsqC4HP4yhV3tA2fqr2RbY5mNXfM7RxXUoeABoDtsFUq2zJq6YK/1/*)";

const TPUB: &str = "tpubD6NzVbkrYhZ4XHndKkuB8FifXm8r5FQHwrN6oZuWCz13qb93rtgKvD4PQsqC4HP4yhV3tA2fqr2RbY5mNXfM7RxXUoeABoDtsFUq2zJq6YK";

/// A deterministic byte reader. Missing bytes read as zero.
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn u8(&mut self) -> u8 {
        let byte = self.data.get(self.pos).copied().unwrap_or(0);
        if self.pos < self.data.len() {
            self.pos += 1;
        }
        byte
    }

    pub fn u16(&mut self) -> u16 {
        u16::from_le_bytes(self.array())
    }

    pub fn u32(&mut self) -> u32 {
        u32::from_le_bytes(self.array())
    }

    pub fn u64(&mut self) -> u64 {
        u64::from_le_bytes(self.array())
    }

    pub fn i64(&mut self) -> i64 {
        self.u64() as i64
    }

    pub fn bool(&mut self) -> bool {
        self.u8() & 1 == 1
    }

    fn array<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        for byte in &mut out {
            *byte = self.u8();
        }
        out
    }

    pub fn array32(&mut self) -> [u8; 32] {
        self.array()
    }

    /// Consume at most `max` bytes, bounded by the remaining input.
    pub fn bytes(&mut self, max: usize) -> &'a [u8] {
        let data = self.data;
        let pos = self.pos.min(data.len());
        let remaining = data.len() - pos;
        let len = (self.u8() as usize).min(max).min(remaining);
        let out = &data[pos..pos + len];
        self.pos = pos + len;
        out
    }

    pub fn text(&mut self, max: usize) -> String {
        String::from_utf8_lossy(self.bytes(max)).into_owned()
    }

    pub fn wallet_name(&mut self) -> String {
        let name = self.text(48);
        if name.is_empty() {
            "fuzz_wallet".to_string()
        } else {
            format!("fuzz_{name}")
        }
    }
}

pub fn fixed_descriptors() -> (
    Descriptor<DescriptorPublicKey>,
    Descriptor<DescriptorPublicKey>,
) {
    (
        Descriptor::from_str(FIXED_EXTERNAL).expect("fixed external descriptor"),
        Descriptor::from_str(FIXED_INTERNAL).expect("fixed internal descriptor"),
    )
}

/// A changeset containing only the fixed descriptors and network.
pub fn descriptor_changeset() -> ChangeSet {
    let (external, internal) = fixed_descriptors();
    ChangeSet {
        network: Some(Network::Regtest),
        descriptor: Some(external),
        change_descriptor: Some(internal),
        ..Default::default()
    }
}

/// Descriptors that parse successfully but cannot derive index 0.
pub fn unsupported_descriptors() -> [String; 3] {
    [
        format!("wpkh({TPUB}/<0;1>/*)"),
        format!("wpkh({TPUB}/0/*')"),
        format!("wpkh({TPUB}/0'/1/*)"),
    ]
}

pub async fn new_store(wallet_name: String) -> Store<Sqlite> {
    Store::<Sqlite>::new_with_url(None, wallet_name, Network::Regtest, true)
        .await
        .expect("in-memory sqlite store must build")
}

/// Builds a store over a caller-owned pool so fuzz targets can inject corrupt
/// rows directly.
pub async fn new_store_with_pool(wallet_name: String) -> (Store<Sqlite>, Pool<Sqlite>) {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .min_connections(1)
        .idle_timeout(None)
        .max_lifetime(None)
        .connect(":memory:")
        .await
        .expect("in-memory sqlite pool");
    let store = Store::<Sqlite>::new(pool.clone(), wallet_name, Network::Regtest, true)
        .await
        .expect("in-memory sqlite store must build");
    (store, pool)
}

pub async fn persist(store: &mut Store<Sqlite>, changeset: &ChangeSet) -> Result<(), BdkSqlxError> {
    AsyncWalletPersister::persist(store, changeset).await
}

pub async fn load(store: &mut Store<Sqlite>) -> Result<ChangeSet, BdkSqlxError> {
    AsyncWalletPersister::initialize(store).await
}

pub fn random_tx(reader: &mut Reader<'_>) -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: LockTime::from_consensus(reader.u32()),
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array(reader.array32()),
                vout: reader.u32(),
            },
            ..Default::default()
        }],
        output: vec![TxOut {
            value: Amount::from_sat(reader.u64() >> 1),
            script_pubkey: ScriptBuf::from(reader.bytes(64).to_vec()),
        }],
    }
}

pub fn random_anchor(reader: &mut Reader<'_>) -> ConfirmationBlockTime {
    ConfirmationBlockTime {
        block_id: BlockId {
            height: reader.u32() % 1_000_000,
            hash: BlockHash::from_byte_array(reader.array32()),
        },
        confirmation_time: reader.u64() >> 1,
    }
}

/// A changeset that exercises every persisted table, including an anchor whose
/// transaction row exists. Used as the starting point for corruption fuzzing.
pub fn baseline_changeset(reader: &mut Reader<'_>) -> ChangeSet {
    let (external, internal) = fixed_descriptors();
    let tx = random_tx(reader);
    let txid = tx.compute_txid();
    let height = 100 + reader.u32() % 1_000;
    let hash = BlockHash::from_byte_array(reader.array32());
    let anchor = ConfirmationBlockTime {
        block_id: BlockId { height, hash },
        confirmation_time: reader.u64() >> 1,
    };

    let mut changeset = ChangeSet {
        network: Some(Network::Regtest),
        descriptor: Some(external.clone()),
        change_descriptor: Some(internal.clone()),
        ..Default::default()
    };
    changeset.local_chain.blocks.insert(height, Some(hash));
    changeset.tx_graph.txs.insert(Arc::new(tx));
    changeset.tx_graph.txouts.insert(
        OutPoint { txid, vout: 0 },
        TxOut {
            value: Amount::from_sat(reader.u64() >> 1),
            script_pubkey: ScriptBuf::from(reader.bytes(32).to_vec()),
        },
    );
    changeset.tx_graph.last_seen.insert(txid, reader.u64() >> 1);
    changeset.tx_graph.anchors.insert((anchor, txid));
    changeset
        .indexer
        .last_revealed
        .insert(external.descriptor_id(), reader.u32() & 0x7fff_ffff);
    changeset
        .indexer
        .last_revealed
        .insert(internal.descriptor_id(), reader.u32() & 0x7fff_ffff);
    changeset
}

/// Arbitrary, mostly-valid changeset. Values are masked into the schema's
/// representable range; structural invalidity (for example one hash at two
/// heights) is left to the fuzzer.
pub fn random_changeset(reader: &mut Reader<'_>) -> ChangeSet {
    let (external, internal) = fixed_descriptors();
    let mut changeset = ChangeSet {
        network: Some(Network::Regtest),
        descriptor: Some(external.clone()),
        change_descriptor: Some(internal.clone()),
        ..Default::default()
    };

    for _ in 0..(reader.u8() % 4) {
        let height = reader.u32() % 1_000_000;
        let hash = BlockHash::from_byte_array(reader.array32());
        let value = reader.bool().then_some(hash);
        changeset.local_chain.blocks.insert(height, value);
    }

    for _ in 0..(reader.u8() % 3) {
        changeset.tx_graph.txs.insert(Arc::new(random_tx(reader)));
    }

    for _ in 0..(reader.u8() % 4) {
        let outpoint = OutPoint {
            txid: Txid::from_byte_array(reader.array32()),
            vout: reader.u32() % 16,
        };
        changeset.tx_graph.txouts.insert(
            outpoint,
            TxOut {
                value: Amount::from_sat(reader.u64() >> 1),
                script_pubkey: ScriptBuf::from(reader.bytes(64).to_vec()),
            },
        );
    }

    for _ in 0..(reader.u8() % 4) {
        let txid = Txid::from_byte_array(reader.array32());
        changeset.tx_graph.last_seen.insert(txid, reader.u64() >> 1);
    }

    for _ in 0..(reader.u8() % 4) {
        let anchor = random_anchor(reader);
        let txid = Txid::from_byte_array(reader.array32());
        changeset.tx_graph.anchors.insert((anchor, txid));
    }

    changeset
        .indexer
        .last_revealed
        .insert(external.descriptor_id(), reader.u32() & 0x7fff_ffff);
    changeset
        .indexer
        .last_revealed
        .insert(internal.descriptor_id(), reader.u32() & 0x7fff_ffff);

    changeset
}
