//! Daemonization support: logger staging, fork, stdio redirection,
//! session detach, and working directory change.

use std::{fs::File, os::unix::io::AsRawFd};

use log::info;

use crate::cli::BpfAgentArgs;
use crate::config;

/// Initialize logger based on execution mode (daemon vs foreground) before daemonizing
pub fn init_logger_initial(args: &BpfAgentArgs) {
    if args.daemon && !args.verbose {
        // In daemon mode, we'll initialize after daemonize to redirect to log file
        // Don't initialize logger yet
    } else {
        // In foreground/verbose mode, initialize logger to stderr
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    }
}

/// Detach the process from the terminal and run as a daemon if configured.
///
/// This function forks the process and sets up file descriptors to run in the background.
/// It must be called before the async runtime is created.
pub fn daemonize(
    args: &BpfAgentArgs,
    daemon_config: &config::DaemonConfig,
) -> anyhow::Result<Option<File>> {
    if !args.daemon || args.verbose {
        return Ok(None);
    }

    // Create log file before daemonize
    let log_file_path = &daemon_config.log_file;
    let file = File::create(log_file_path)
        .map_err(|e| anyhow::anyhow!("failed to create log file {}: {}", log_file_path, e))?;

    // Write to PID file
    std::fs::write(&daemon_config.pid_file, std::process::id().to_string()).map_err(|e| {
        anyhow::anyhow!("failed to write PID file {}: {}", daemon_config.pid_file, e)
    })?;

    // Fork and detach from terminal
    fork_and_detach(&file, &daemon_config.working_directory)?;

    Ok(Some(file))
}

/// Fork the process and set up file descriptors for daemon mode.
///
/// # Safety
/// This function uses unsafe libc calls to fork and manage file descriptors.
/// It must only be called from the main thread before creating any child threads.
fn fork_and_detach(log_file: &File, working_dir: &str) -> anyhow::Result<()> {
    // SAFETY: fork() is unsafe but safe to call here before tokio runtime
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(anyhow::anyhow!("fork() failed: cannot daemonize process"));
    }
    if pid > 0 {
        // Parent process - exit
        std::process::exit(0);
    }

    // Child process continues here
    redirect_stdio(log_file)?;
    create_new_session()?;
    change_working_directory(working_dir)?;

    Ok(())
}

/// Redirect stdin, stdout, and stderr for daemon mode.
///
/// # Safety
/// Uses unsafe libc dup2 calls. Must be called only in child process after fork.
fn redirect_stdio(log_file: &File) -> anyhow::Result<()> {
    let dev_null =
        File::open("/dev/null").map_err(|e| anyhow::anyhow!("failed to open /dev/null: {}", e))?;

    let dev_null_fd = dev_null.as_raw_fd();
    let log_fd = log_file.as_raw_fd();

    // Close stdin
    if unsafe { libc::dup2(dev_null_fd, libc::STDIN_FILENO) } < 0 {
        return Err(anyhow::anyhow!(
            "dup2() failed for stdin: cannot redirect file descriptors"
        ));
    }

    // Redirect stdout to log file
    if unsafe { libc::dup2(log_fd, libc::STDOUT_FILENO) } < 0 {
        return Err(anyhow::anyhow!(
            "dup2() failed for stdout: cannot redirect file descriptors"
        ));
    }

    // Redirect stderr to log file
    if unsafe { libc::dup2(log_fd, libc::STDERR_FILENO) } < 0 {
        return Err(anyhow::anyhow!(
            "dup2() failed for stderr: cannot redirect file descriptors"
        ));
    }

    Ok(())
}

/// Create a new session to fully detach from terminal.
///
/// # Safety
/// Uses unsafe libc setsid call. Must be called only in child process after fork.
fn create_new_session() -> anyhow::Result<()> {
    // SAFETY: setsid() is unsafe but must be called in child process to detach
    if unsafe { libc::setsid() } < 0 {
        return Err(anyhow::anyhow!(
            "setsid() failed: cannot create new session for daemon"
        ));
    }
    Ok(())
}

/// Change to the working directory specified in config.
fn change_working_directory(working_dir: &str) -> anyhow::Result<()> {
    std::env::set_current_dir(working_dir).map_err(|e| {
        anyhow::anyhow!(
            "failed to change working directory to {}: {}",
            working_dir,
            e
        )
    })
}

/// Re-initialize logger after daemonize to redirect logs to the new stdout/stderr log file
pub fn init_logger_after_daemonize(args: &BpfAgentArgs) {
    if args.daemon && !args.verbose {
        let _ = env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Debug)
            .try_init();

        info!("Logger initialized in daemon mode");
    } else if args.daemon && args.verbose {
        info!("Verbose mode overrides daemon mode - running in foreground");
    } else {
        info!("Running in foreground mode");
    }
}
