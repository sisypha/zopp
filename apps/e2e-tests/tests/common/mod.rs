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
