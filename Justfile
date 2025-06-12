# Default task: Show available commands
default:
    just --list

# Set environment variables for all commands
export DATABASE_URL := "postgres://postgres:password@localhost:5432/mydatabase"
export ELECTRUM_URL := "localhost:50001"
export NODE_URL := "http://localhost:18443"
export NODE_USERNAME := "custom_user"
export NODE_PASSWORD := "custom_pass"
export RUST_BACKTRACE := "1"

# Setup network
setup-network:
    # Check if the network exists first
    docker network inspect bitcoin-network >/dev/null 2>&1 || docker network create bitcoin-network
    # Verify network was created
    docker network inspect bitcoin-network >/dev/null 2>&1 && echo "Bitcoin network is ready" || (echo "Failed to create bitcoin-network" && exit 1)

# PostgreSQL commands
start-postgres:
    docker run -d --name postgres \
        -p 5432:5432 \
        -e POSTGRES_USER=postgres \
        -e POSTGRES_PASSWORD=password \
        -e POSTGRES_DB=mydatabase \
        postgres:15

test-postgres:
    PGPASSWORD=password psql -h localhost -p 5432 -U postgres -d mydatabase -c "SELECT 1"

# Bitcoin Core commands
build-bitcoin:
    docker build -t bitcoin-nix \
        --build-arg NODE_USERNAME=custom_user \
        --build-arg NODE_PASSWORD=custom_pass \
        -f bitcoin.Dockerfile .

start-bitcoin: setup-network
    docker run -d --name bitcoin-node \
        --network bitcoin-network \
        -p 18443:18443 \
        bitcoin-nix
    # Add a delay or check to ensure bitcoin is ready
    echo "Waiting for Bitcoin node to start..."
    for i in {1..30}; do \
        if just test-bitcoin >/dev/null 2>&1; then \
            echo "Bitcoin node is ready!"; \
            break; \
        fi; \
        echo "Waiting... ($i/30)"; \
        sleep 1; \
        if [ $i -eq 30 ]; then \
            echo "Timed out waiting for Bitcoin node to start"; \
            exit 1; \
        fi; \
    done

test-bitcoin:
    curl --silent --user custom_user:custom_pass \
        --data-binary '{"jsonrpc": "1.0", "id":"bitcointest", "method": "getblockchaininfo", "params": []}' \
        -H 'content-type: text/plain;' http://localhost:18443

generate-blocks:
    curl --silent --user custom_user:custom_pass \
        --data-binary '{"jsonrpc": "1.0", "id":"bitcointest", "method": "generatetoaddress", "params": [101, "bcrt1prdfvfk2ddxe8y88qxhwkxn9cy0d2w6k98gj9smwz6tqjcnl4tdwsrf03aw"]}' \
        -H 'content-type: text/plain;' http://localhost:18443

# Electrs commands
build-electrs:
    docker build -t electrs-nix \
        -f electrs.Dockerfile .

start-electrs: setup-network
    docker run -d --name electrs \
        --network bitcoin-network \
        -p 50001:50001 \
        electrs-nix
    echo "Electrs started"

check-electrs:
    docker logs electrs



# Kill any services that might be using the ports
kill-services:
    # Kill any process using PostgreSQL port
    lsof -ti:5432 | xargs kill -9 || true
    # Kill any process using Bitcoin RPC port
    lsof -ti:18443 | xargs kill -9 || true
    # Kill any process using Electrs port
    lsof -ti:50001 | xargs kill -9 || true

# Stop and remove Docker containers
stop-containers:
    docker stop postgres bitcoin-node electrs || true
    docker rm postgres bitcoin-node electrs || true

# Clean everything
clean-all:
    just kill-services
    just stop-containers
    docker network rm bitcoin-network || true
    # Make sure all orphaned networks are also removed
    docker network prune -f
    echo "Environment cleaned successfully"

# Run the regtest example with all required services
run-example-regtest:
    # Clean up any existing containers first
    just stop-containers
    # Start all required services
    just start-postgres
    just build-bitcoin
    just start-bitcoin
    just build-electrs
    just start-electrs
    # Generate initial blocks
    just generate-blocks
    # Run the regtest example
    cargo run -r --example regtest_bdk_sqlx_postgres
