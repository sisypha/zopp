use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::Command;
use thiserror::Error;

#[derive(Error, Debug)]
enum XtaskError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Environment variable not set: {0}")]
    VarError(#[from] std::env::VarError),
    #[error("Unknown backend: {0}. Supported: sqlite, postgres")]
    UnknownBackend(String),
    #[error("Failed to read migrations directory: {0}")]
    ReadMigrations(String),
    #[error("No migration files found in {0}")]
    NoMigrations(String),
    #[error("Failed to read migration {0}: {1}")]
    ReadMigration(String, std::io::Error),
    #[error("Failed to run sqlite3. Is it installed?")]
    Sqlite3NotFound,
    #[error("Migration failed: {0}")]
    MigrationFailed(String),
    #[error("Failed to get parent directory")]
    NoParentDir,
    #[error("Failed to run cargo sqlx prepare")]
    SqlxPrepareCommand,
    #[error("sqlx prepare failed for {0}")]
    SqlxPrepareFailed(String),
}

type Result<T> = std::result::Result<T, XtaskError>;

#[derive(Parser)]
#[command(name = "xtask")]
#[command(about = "Development tasks for zopp workspace")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Set up development database for compile-time SQL checks
    SetupDb {
        /// Storage backend to set up (sqlite, postgres)
        #[arg(default_value = "sqlite")]
        backend: String,
    },
    /// Prepare sqlx offline metadata (run after changing queries)
    SqlxPrepare {
        /// Storage backend to prepare (sqlite, postgres, or "all")
        #[arg(default_value = "all")]
        backend: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::SetupDb { backend } => setup_db(&backend),
        Commands::SqlxPrepare { backend } => sqlx_prepare(&backend),
    }
}

fn setup_db(backend: &str) -> Result<()> {
    match backend {
        "sqlite" => setup_sqlite(),
        _ => Err(XtaskError::UnknownBackend(backend.to_string())),
    }
}

fn setup_sqlite() -> Result<()> {
    println!("🔧 Setting up SQLite development database...");

    let project_root = project_root()?;
    let db_path = project_root.join("crates/zopp-store-sqlite/dev.db");
    let migration_dir = project_root.join("crates/zopp-store-sqlite/migrations");

    // Remove old database if it exists
    if db_path.exists() {
        std::fs::remove_file(&db_path)?;
    }

    // Find migration files
    let mut migrations: Vec<_> = std::fs::read_dir(&migration_dir)
        .map_err(|e| XtaskError::ReadMigrations(e.to_string()))?
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|ext| ext == "sql")
                .unwrap_or(false)
        })
        .collect();
    migrations.sort_by_key(|e| e.file_name());

    if migrations.is_empty() {
        return Err(XtaskError::NoMigrations(
            migration_dir.display().to_string(),
        ));
    }

    // Create database and apply migrations
    for migration in migrations {
        let path = migration.path();
        println!(
            "  Applying: {}",
            path.file_name().unwrap().to_string_lossy()
        );

        let sql = std::fs::read_to_string(&path)
            .map_err(|e| XtaskError::ReadMigration(path.display().to_string(), e))?;

        let status = Command::new("sqlite3")
            .arg(&db_path)
            .arg(&sql)
            .status()
            .map_err(|_| XtaskError::Sqlite3NotFound)?;

        if !status.success() {
            return Err(XtaskError::MigrationFailed(path.display().to_string()));
        }
    }

    println!("✓ SQLite database created at: {}", db_path.display());
    println!();
    println!("Next steps:");
    println!("  1. After changing queries: cargo xtask sqlx-prepare sqlite");
    println!("  2. Commit the crates/zopp-store-sqlite/.sqlx/ directory");

    Ok(())
}

fn sqlx_prepare(backend: &str) -> Result<()> {
    println!("🔧 Preparing sqlx offline metadata...");

    let backends = if backend == "all" {
        vec!["sqlite"] // Add "postgres" when it exists
    } else {
        vec![backend]
    };

    let project_root = project_root()?;

    for backend in backends {
        match backend {
            "sqlite" => {
                println!("  Preparing zopp-store-sqlite...");
                let crate_dir = project_root.join("crates/zopp-store-sqlite");
                let db_path = crate_dir.join("dev.db");
                let database_url = format!("sqlite:{}", db_path.display());

                let status = Command::new("cargo")
                    .current_dir(&crate_dir)
                    .env("DATABASE_URL", &database_url)
                    .env("SQLX_OFFLINE", "false") // Must connect to DB to prepare
                    .args(["sqlx", "prepare", "--", "--lib"])
                    .status()
                    .map_err(|_| XtaskError::SqlxPrepareCommand)?;

                if !status.success() {
                    return Err(XtaskError::SqlxPrepareFailed("sqlite".to_string()));
                }

                println!("  ✓ Metadata written to crates/zopp-store-sqlite/.sqlx/");
            }
            "postgres" => {
                println!("  Skipping postgres (not yet implemented)");
            }
            _ => return Err(XtaskError::UnknownBackend(backend.to_string())),
        }
    }

    println!();
    println!("✓ All metadata prepared");
    println!("Don't forget to commit the updated .sqlx/ directories in each backend crate!");

    Ok(())
}

fn project_root() -> Result<PathBuf> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")?;
    let xtask_dir = PathBuf::from(manifest_dir);
    let parent = xtask_dir.parent().ok_or(XtaskError::NoParentDir)?;
    Ok(parent.to_path_buf())
}
