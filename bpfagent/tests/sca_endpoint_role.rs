//! Tests for SCA hop endpoint classification (the core of hop discovery).
//!
//! Matching is by socket path only; the owning process is validated against
//! DATA_FLOW by the caller (a /proc/<pid>/comm check), so these tests never
//! key on PIDs.

use bpfagent::programs::sca::{endpoint_role, paths_by_inode, UnixSockRec};

fn sock(pid: u32, fd: u32, inode: u64, peer_inode: u64, path: Option<&str>) -> UnixSockRec {
    UnixSockRec {
        pid,
        fd,
        inode,
        peer_inode,
        path: path.map(str::to_string),
    }
}

/// Hop under test: DATA_SOURCE (100) -> INTERNAL_ROUTER (200) on this path.
const PATH: &str = "/tmp/DATA_L3_TO_INTERNAL_ROUTER";

/// The two sockets of the hop under test: the receiver's accepted socket
/// (carries the path) and the sender's connected socket (path-less, paired
/// with the accepted one via peer inodes).
fn discovery_socks() -> Vec<UnixSockRec> {
    vec![
        sock(200, 5, 5000, 6000, Some(PATH)),
        sock(100, 3, 6000, 5000, None),
    ]
}

#[test]
fn receiver_accepted_socket_is_receiver_endpoint() {
    let socks = discovery_socks();
    let by_inode = paths_by_inode(&socks);
    assert_eq!(endpoint_role(&socks[0], PATH, &by_inode), Some(0));
}

#[test]
fn sender_client_socket_is_resolved_via_peer_inode() {
    let socks = discovery_socks();
    let by_inode = paths_by_inode(&socks);
    assert_eq!(endpoint_role(&socks[1], PATH, &by_inode), Some(1));
}

#[test]
fn client_socket_with_unrelated_peer_does_not_match() {
    // A path-less socket whose peer has no known path is not an endpoint.
    let socks = discovery_socks();
    let by_inode = paths_by_inode(&socks);
    let stray = sock(100, 7, 9000, 9001, None);
    assert_eq!(endpoint_role(&stray, PATH, &by_inode), None);
}

#[test]
fn accepted_socket_of_another_hop_does_not_match() {
    // A socket carrying a different hop's path is not this hop's endpoint.
    let socks = discovery_socks();
    let by_inode = paths_by_inode(&socks);
    let foreign = sock(300, 4, 3000, 3001, Some("/tmp/DATA_L3_TO_WF_L"));
    assert_eq!(endpoint_role(&foreign, PATH, &by_inode), None);
}

#[test]
fn matching_ignores_the_owning_pid() {
    // The same hop endpoints owned by different PIDs (e.g. another simulator
    // instance's PIDs seen through a shared /proc) still classify by path;
    // telling instances apart is the network namespace's and the comm
    // check's job, not the matcher's.
    let socks = vec![
        sock(4200, 5, 5000, 6000, Some(PATH)),
        sock(4100, 3, 6000, 5000, None),
    ];
    let by_inode = paths_by_inode(&socks);
    assert_eq!(endpoint_role(&socks[0], PATH, &by_inode), Some(0));
    assert_eq!(endpoint_role(&socks[1], PATH, &by_inode), Some(1));
}
