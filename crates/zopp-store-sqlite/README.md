# zopp-store-sqlite

SQLite implementation of the `zopp-storage::Store` trait.

## Features

- Compile-time SQL validation using sqlx macros
- Offline compilation (no database required for builds)
- In-memory databases for testing
- Automatic migrations on connection

## Development

### Prerequisites for SQL changes

- SQLite 3
- `cargo install sqlx-cli --no-default-features --features sqlite`

### Modifying queries or migrations

1. Set up development database:
   ```bash
   cargo xtask setup-db sqlite
   ```

2. Make your changes to `migrations/` or `src/lib.rs`

3. Regenerate metadata:
   ```bash
   cargo xtask sqlx-prepare sqlite
   ```

4. Commit the updated `.sqlx/` directory

### Testing

```bash
cargo test -p zopp-store-sqlite
```

Tests use in-memory SQLite databases, no setup required.
