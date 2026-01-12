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

## Coverage Strategy

### Crates (Unit Test Coverage Target: 100%)

| Crate | Coverage | Notes |
|-------|----------|-------|
| `zopp-audit` | 100% | All action types, result types, filter builders |
| `zopp-crypto` | 100% | All cryptographic operations |
| `zopp-config` | 95%+ | File I/O, key parsing, error handling |
| `zopp-secrets` | 97%+ | Secret encryption/decryption context |
| `zopp-events-memory` | 95%+ | In-memory event bus |
| `zopp-events-postgres` | 93%+ | PostgreSQL event bus |
| `zopp-storage` | 46% | Trait definitions (no impl to test), ID types |
| `zopp-store-sqlite` | 58% | Tested via in-memory SQLite |
| `zopp-store-postgres` | 12% | Requires running PostgreSQL instance |

### Apps (Integration-Heavy Code)

Apps contain integration code that is primarily tested via E2E tests. Unit tests target:

| App | Unit Tests Cover |
|-----|------------------|
| `zopp-cli` | Config parsing, env file parsing/formatting, request signing, auth metadata |
| `zopp-server` | Server invite flow, replay protection, role comparison logic |
| `zopp-operator` | CRD type definitions |

**Why not 100% unit test coverage for apps?**

1. **CLI commands** are thin wrappers around gRPC calls. The actual logic (crypto, config) lives in crates.
2. **Server handlers** require authenticated requests. Authentication is unit tested; handler logic is tested via E2E.
3. **Operator** requires Kubernetes APIs. K8s integration is tested via E2E with kind clusters.

### PostgreSQL Testing

For `zopp-store-postgres` coverage:
```bash
# Start PostgreSQL
docker run --name zopp-postgres -e POSTGRES_PASSWORD=postgres -p 5432:5432 -d postgres:16

# Run tests with PostgreSQL
DATABASE_URL=postgres://postgres:postgres@localhost/postgres cargo test --package zopp-store-postgres
```

CI uses PostgreSQL services for E2E tests across all backend combinations.
