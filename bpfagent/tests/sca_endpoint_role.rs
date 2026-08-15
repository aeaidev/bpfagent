//! Tests for SCA hop endpoint classification (the core of hop discovery).

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
const S_PID: u32 = 100;
const R_PID: u32 = 200;

/// The two sockets of the hop under test: the receiver's accepted socket
/// (carries the path) and the sender's connected socket (path-less, paired
/// with the accepted one via peer inodes).
fn discovery_socks() -> Vec<UnixSockRec> {
    vec![
        sock(R_PID, 5, 5000, 6000, Some(PATH)),
        sock(S_PID, 3, 6000, 5000, None),
    ]
}

#[test]
fn receiver_accepted_socket_is_receiver_endpoint() {
    let socks = discovery_socks();
    let by_inode = paths_by_inode(&socks);
    assert_eq!(
        endpoint_role(&socks[0], S_PID, R_PID, PATH, &by_inode),
        Some(0)
    );
}

#[test]
fn sender_client_socket_is_resolved_via_peer_inode() {
    let socks = discovery_socks();
    let by_inode = paths_by_inode(&socks);
    assert_eq!(
        endpoint_role(&socks[1], S_PID, R_PID, PATH, &by_inode),
        Some(1)
    );
}

#[test]
fn same_fd_number_in_other_process_is_not_confused() {
    // A different process holding fd 5 for an unrelated socket must not match,
    // even though the receiver's accepted fd is also 5.
    let socks = discovery_socks();
    let by_inode = paths_by_inode(&socks);
    let unrelated = sock(999, 5, 7000, 8000, None);
    assert_eq!(
        endpoint_role(&unrelated, S_PID, R_PID, PATH, &by_inode),
        None
    );
}

#[test]
fn client_socket_with_unrelated_peer_does_not_match() {
    // Sender's socket, but its peer has no known path.
    let socks = discovery_socks();
    let by_inode = paths_by_inode(&socks);
    let stray = sock(S_PID, 7, 9000, 9001, None);
    assert_eq!(endpoint_role(&stray, S_PID, R_PID, PATH, &by_inode), None);
}

#[test]
fn path_on_wrong_process_does_not_match() {
    // The hop path on a socket owned by a third process is not an endpoint.
    let socks = discovery_socks();
    let by_inode = paths_by_inode(&socks);
    let foreign = sock(999, 4, 3000, 3001, Some(PATH));
    assert_eq!(endpoint_role(&foreign, S_PID, R_PID, PATH, &by_inode), None);
}
