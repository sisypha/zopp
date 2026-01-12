//! Shared utilities for E2E tests.

use std::path::PathBuf;

/// Get binary paths (zopp-server, zopp, zopp-operator)
/// Works with both regular and llvm-cov target directories
pub fn get_binary_paths() -> Result<(PathBuf, PathBuf, PathBuf), Box<dyn std::error::Error>> {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();

    // Check for llvm-cov target directory first, then regular target
    // CARGO_LLVM_COV_TARGET_DIR points directly to the target dir (e.g., /path/to/target)
    let bin_dir = if let Ok(llvm_cov_target) = std::env::var("CARGO_LLVM_COV_TARGET_DIR") {
        PathBuf::from(llvm_cov_target).join("debug")
    } else if let Ok(cargo_target) = std::env::var("CARGO_TARGET_DIR") {
        PathBuf::from(cargo_target).join("debug")
    } else {
        workspace_root.join("target").join("debug")
    };

    let zopp_server_bin = bin_dir.join(if cfg!(windows) {
        "zopp-server.exe"
    } else {
        "zopp-server"
    });
    let zopp_bin = bin_dir.join(if cfg!(windows) { "zopp.exe" } else { "zopp" });
    let operator_bin = bin_dir.join(if cfg!(windows) {
        "zopp-operator.exe"
    } else {
        "zopp-operator"
    });

    if !zopp_server_bin.exists() || !zopp_bin.exists() {
        return Err(format!(
            "Binaries not found. Please run 'cargo build --bins' first.\n  Expected: {}\n  Expected: {}",
            zopp_server_bin.display(),
            zopp_bin.display()
        ).into());
    }

    Ok((zopp_server_bin, zopp_bin, operator_bin))
}

/// Gracefully shutdown a child process for coverage data collection.
/// Sends SIGTERM first, waits briefly, then falls back to SIGKILL.
#[cfg(unix)]
pub fn graceful_shutdown(child: &mut std::process::Child) {
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;
    use std::time::Duration;

    let pid = Pid::from_raw(child.id() as i32);
    let _ = kill(pid, Signal::SIGTERM);

    // Wait up to 2 seconds for graceful shutdown
    for _ in 0..20 {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => std::thread::sleep(Duration::from_millis(100)),
            Err(_) => break,
        }
    }

    // Force kill if still running
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(not(unix))]
pub fn graceful_shutdown(child: &mut std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Extract principal ID from CLI output.
/// Parses output like "Created principal: ci-bot (ID: abc-123-def)"
#[allow(dead_code)] // Used by principals.rs and k8s.rs, but not all test modules
pub fn parse_principal_id(output: &str) -> Option<String> {
    output
        .lines()
        .find(|line| line.contains("(ID:"))
        .and_then(|line| {
            let start = line.find("(ID: ")? + 5;
            let end = line.find(')')?;
            Some(line[start..end].to_string())
        })
}
