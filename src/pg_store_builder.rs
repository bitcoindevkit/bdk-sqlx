use crate::{initialize_network, BdkSqlxError, Store};
use bdk_wallet::bitcoin::Network;
use sqlx::{PgPool, Postgres};

/// Builder for creating a Postgres-backed Store instance
pub struct PgStoreBuilder {
    wallet_name: String,
    pool: Option<PgPool>,
    network: Option<Network>,
    url: Option<String>,
}

impl PgStoreBuilder {
    /// Creates a new builder for a [`Store`] with the given wallet name.
    ///
    /// # Required fields
    /// Before building, you must set:
    /// - `network` - The Bitcoin network to use
    /// - Either provide a connection pool with `pool()` or a database URL with `url()`
    ///
    /// # Example
    /// ```
    ///
    ///
    ///  async fn example() -> Result<(), bdk_sqlx::BdkSqlxError> {
    /// use bdk_wallet::bitcoin::Network;
    /// use sqlx::PgPool;
    /// use bdk_sqlx::pg_store_builder::PgStoreBuilder;
    ///
    /// // Build with a URL
    /// let store = PgStoreBuilder::new("bdk_wallet_name".to_string())
    ///     .network(Network::Testnet)
    ///     .url("postgres://username:password@localhost/database".to_string())
    ///     .build()
    ///     .await?;
    ///     
    /// // Or build with an existing pool
    /// let pool = PgPool::connect("postgres://username:password@localhost/database").await?;
    /// let store = PgStoreBuilder::new("another_wallet".to_string())
    ///     .network(Network::Testnet)
    ///     .pool(pool)
    ///     .build()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument]
    pub fn new(wallet_name: String) -> Self {
        Self {
            wallet_name,
            pool: None,
            network: None,
            url: None,
        }
    }

    /// Sets the database connection pool for the [`Store`].
    ///
    /// Either a pool or a URL must be provided before building.
    pub fn pool(mut self, pool: PgPool) -> Self {
        self.pool = Some(pool);
        self
    }

    /// Sets the Bitcoin network for the [`Store`].
    ///
    /// The network is required to build a valid [`Store`].
    pub fn network(mut self, network: Network) -> Self {
        self.network = Some(network);
        self
    }

    /// Sets the Postgres connection URL for the [`Store`].
    ///
    /// Either a URL or a pool must be provided before building.
    ///
    /// # Example
    /// ```
    /// # use bdk_sqlx::pg_store_builder::PgStoreBuilder;
    /// let builder = PgStoreBuilder::new("wallet".to_string())
    ///     .url("postgres://username:password@localhost/database".to_string());
    /// ```
    pub fn url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }

    /// Builds the [`Store`] with the configured options.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No network has been specified (`MissingNetwork`)
    /// - Neither pool nor URL has been specified (`MissingPool`)
    /// - Database connection fails
    /// - Network initialization fails
    pub async fn build(self) -> crate::Result<Store<Postgres>> {
        if self
            .network
            .and_then(|n| initialize_network(n).ok())
            .is_none()
        {
            return Err(BdkSqlxError::MissingNetwork);
        }

        // Get or create the connection pool
        let pool = match (self.pool, self.url) {
            (Some(pool), _) => pool,
            (_, Some(url)) => PgPool::connect(&url).await?,
            (None, None) => return Err(BdkSqlxError::MissingPool),
        };

        Ok(Store {
            pool,
            wallet_name: self.wallet_name,
        })
    }
}
