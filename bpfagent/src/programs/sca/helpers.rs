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

/// Extract the host (initial namespace) PID from the content of
/// /proc/<pid>/status. The `NSpid:` field lists the process's PID in every
/// PID namespace from the host down to its own, so the first number is the
/// PID the kernel reports to eBPF via bpf_get_current_pid_tgid().
pub fn parse_nspid(status: &str) -> Option<u32> {
    let line = status.lines().find(|l| l.starts_with("NSpid:"))?;
    line.strip_prefix("NSpid:")?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// Translate a PID from the PID namespace of our /proc view to the host
/// (initial) PID namespace, which is what the eBPF program keys its maps by.
/// On the host, or in a container sharing the host PID namespace, this is
/// the identity. A vanished process or a missing NSpid field (kernel without
/// PID namespace support) falls back to the PID unchanged.
pub fn to_host_pid(pid: u32) -> u32 {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()
        .and_then(|status| parse_nspid(&status))
        .unwrap_or(pid)
}

/// Validate that the process owning a discovered socket has the expected
/// name. An unreadable comm (the process exited between the ss snapshot and
/// this check) is accepted: the kernel-reported socket owner is authoritative
/// and a stale entry is evicted on the next rediscovery.
pub(super) fn comm_matches(pid: u32, expected: &str) -> bool {
    match std::fs::read_to_string(format!("/proc/{pid}/comm")) {
        Ok(comm) => {
            let matches = comm.trim() == expected;
            if !matches {
                warn!(
                    "socket owner pid {} is {:?}, expected {:?} — skipping endpoint",
                    pid,
                    comm.trim(),
                    expected
                );
            }
            matches
        }
        Err(_) => true,
    }
}
