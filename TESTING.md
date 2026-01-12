# Testing Standards

## Philosophy

1. **E2E tests** verify features work across all backend combinations
2. **Unit tests** target 100% coverage with real implementations

## E2E Tests

Location: `apps/e2e-tests/`

### Requirements

- Every user-facing feature must have an E2E test
- Tests run against all backend combinations:
  | Storage    | Events     |
  |------------|------------|
  | SQLite     | Memory     |
  | SQLite     | PostgreSQL |
  | PostgreSQL | Memory     |
  | PostgreSQL | PostgreSQL |
- Tests use real binaries (`zopp`, `zopp-server`, `zopp-operator`)

### Running

```bash
cargo build --bins
cargo test --package e2e-tests
```

## Unit Tests

Location: alongside code in `crates/` and `apps/`

### Requirements

- 100% line coverage target for all crates and apps
- Both `crates/` (libraries) and `apps/` (binaries) must have unit tests
- Apps have testable pure functions (crypto, config parsing, request signing, etc.)
- Use real implementations when testing trait implementations
- Only mock to reproduce specific error conditions

### Running

```bash
# Run all unit tests (excludes e2e-tests)
cargo test --workspace --exclude e2e-tests

# Generate coverage report
./scripts/unit-coverage.sh
```

## Mocking Policy

**When testing a trait implementation** (e.g., `zopp-store-sqlite` implementing `Store`):
- Use real dependencies (real SQLite, real PostgreSQL)
- No mocks

**When testing code that consumes an abstraction** (e.g., code that takes `impl Store`):
- Mock implementations are acceptable
- Useful for testing error handling, edge cases

**Example:**
```rust
// Testing zopp-store-sqlite → use real SQLite
let store = SqliteStore::open_in_memory().await?;

// Testing business logic that uses Store → mock is OK
struct MockStore { ... }
impl Store for MockStore { ... }
```

Mocking is also acceptable for:
- Simulating network failures
- Reproducing race conditions
- Forcing specific error paths
