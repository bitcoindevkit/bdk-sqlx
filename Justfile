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

stop-postgres:
    docker stop postgres && docker rm postgres

#   DATABASE_URL: postgres://postgres:password@localhost:5432/mydatabase
example:
    cargo run --example bdk_sqlx_postgres

# Database migration
run-migrations:
    sqlx migrate run --source migrations/postgres
