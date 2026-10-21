# Fuzz targets

These targets exercise the SQLite backend with arbitrary change sets and
corrupt database rows. They complement the deterministic regression tests in
`src/test.rs`.

```sh
cd fuzz
cargo +nightly fuzz run changeset_roundtrip
cargo +nightly fuzz run corrupt_rows
cargo +nightly fuzz run anchor_identity
cargo +nightly fuzz run descriptor_validation
```

The `fuzz` crate is intentionally outside the main package. CI runs a short
smoke pass of every target on pull requests and a longer pass on the weekly
schedule (see `.github/workflows/fuzz.yml`).
