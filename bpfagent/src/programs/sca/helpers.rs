//! SCA hop discovery helpers: `ss -xpH` output parsing and process lookup.

use log::warn;

/// One established Unix stream socket parsed from `ss -xpH` output.
pub struct UnixSockRec {
    pub pid: u32,
    pub fd: u32,
    pub inode: u64,
    pub peer_inode: u64,
    /// Bound path if the socket has one; the connected (client) side has none
    pub path: Option<String>,
}

/// Parse the users:((...)) column of ss output into (pid, fd) pairs.
/// Format: users:(("NAME",pid=123,fd=4),("NAME2",pid=456,fd=7))
pub fn parse_ss_users(users: &str) -> Vec<(u32, u32)> {
    let mut out = Vec::new();
    let mut rest = users;
    while let Some(pos) = rest.find("pid=") {
        rest = &rest[pos + 4..];
        let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        let Ok(pid) = digits.parse::<u32>() else {
            break;
        };
        let Some(fd_pos) = rest.find("fd=") else {
            break;
        };
        rest = &rest[fd_pos + 3..];
        let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        let Ok(fd) = digits.parse::<u32>() else {
            break;
        };
        out.push((pid, fd));
    }
    out
}

/// Parse `ss -xpH` output into established Unix stream socket records.
///
/// Line format (9+ whitespace-separated fields):
/// u_str ESTAB Recv-Q Send-Q <path|*> <inode> * <peer-inode> users:((...))
pub fn parse_ss_unix_stream(output: &str) -> Vec<UnixSockRec> {
    let mut recs = Vec::new();
    for line in output.lines() {
        let t: Vec<&str> = line.split_whitespace().collect();
        if t.len() < 9 || t[0] != "u_str" || t[1] != "ESTAB" {
            continue;
        }
        let (Ok(inode), Ok(peer_inode)) = (t[5].parse::<u64>(), t[7].parse::<u64>()) else {
            continue;
        };
        let path = if t[4] == "*" {
            None
        } else {
            Some(t[4].to_string())
        };
        for (pid, fd) in parse_ss_users(&t[8..].join(" ")) {
            recs.push(UnixSockRec {
                pid,
                fd,
                inode,
                peer_inode,
                path: path.clone(),
            });
        }
    }
    recs
}

/// Build an inode -> path index, used to resolve the peer of path-less
/// client sockets.
pub fn paths_by_inode(sockets: &[UnixSockRec]) -> std::collections::HashMap<u64, &str> {
    sockets
        .iter()
        .filter_map(|s| s.path.as_deref().map(|p| (s.inode, p)))
        .collect()
}

/// Run `ss -xpH` and parse the established Unix stream sockets.
pub(super) fn query_established_unix_sockets() -> anyhow::Result<Vec<UnixSockRec>> {
    let output = std::process::Command::new("ss")
        .arg("-xpH")
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to run ss -xpH: {}", e))?;
    if !output.status.success() {
        warn!(
            "ss -xpH failed, stderr: {:?} — SCA hop discovery may be incomplete",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(parse_ss_unix_stream(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

/// Get PID from process name by reading /proc/*/comm
pub(super) fn get_pid_by_process_name(process_name: &str) -> Option<u32> {
    for entry in std::fs::read_dir("/proc").ok()? {
        // Skip unreadable entries instead of aborting the whole scan
        let Ok(entry) = entry else {
            continue;
        };
        let dir_name = entry.file_name();
        let pid_str = dir_name.to_string_lossy();

        // Skip non-numeric directories
        if pid_str.parse::<u32>().is_err() {
            continue;
        }

        // Read comm file to get process name
        let comm_path = entry.path().join("comm");
        if let Ok(comm) = std::fs::read_to_string(&comm_path) {
            // comm file contains process name with newline
            let comm = comm.trim();
            if comm == process_name {
                return pid_str.parse::<u32>().ok();
            }
        }
    }
    None
}
