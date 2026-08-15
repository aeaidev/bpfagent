//! Tests for the SCA `ss -xpH` output parsing used for hop discovery.

use bpfagent::programs::sca::{parse_ss_unix_stream, parse_ss_users};

const SAMPLE: &str = r#"
u_str ESTAB 0 0 /tmp/DATA_L3_TO_WF_L 1763138 * 1903128 users:(("RED_WF_COMM_L",pid=81593,fd=7))
u_str ESTAB 0 0 * 2371351 * 1887281 users:(("FRAGMENTER",pid=81594,fd=5))
u_str LISTEN 0 128 /tmp/DATA_L3_TO_WF_L 1763137 * 0 users:(("RED_WF_COMM_L",pid=81593,fd=3))
u_dgr ESTAB 0 0 /tmp/other 111 * 222 users:(("someone",pid=1,fd=2))
garbage line that should be skipped
"#;

#[test]
fn parses_users_column() {
    let pairs = parse_ss_users(r#"users:(("A",pid=123,fd=4),("B",pid=456,fd=7))"#);
    assert_eq!(pairs, vec![(123, 4), (456, 7)]);
}

#[test]
fn parses_users_column_single() {
    let pairs = parse_ss_users(r#"users:(("DATA_SINK",pid=76041,fd=4))"#);
    assert_eq!(pairs, vec![(76041, 4)]);
}

#[test]
fn parses_established_stream_with_path() {
    let recs = parse_ss_unix_stream(SAMPLE);
    let server = recs
        .iter()
        .find(|r| r.path.as_deref() == Some("/tmp/DATA_L3_TO_WF_L"))
        .expect("accepted socket with path should be parsed");
    assert_eq!(server.pid, 81593);
    assert_eq!(server.fd, 7);
    assert_eq!(server.inode, 1763138);
    assert_eq!(server.peer_inode, 1903128);
}

#[test]
fn parses_client_socket_without_path() {
    let recs = parse_ss_unix_stream(SAMPLE);
    let client = recs
        .iter()
        .find(|r| r.pid == 81594 && r.fd == 5)
        .expect("client socket should be parsed");
    assert_eq!(client.path, None);
    assert_eq!(client.inode, 2371351);
    assert_eq!(client.peer_inode, 1887281);
}

#[test]
fn skips_non_established_and_malformed_lines() {
    let recs = parse_ss_unix_stream(SAMPLE);
    // LISTEN and u_dgr lines and the garbage line must be skipped:
    // only the two u_str ESTAB records survive.
    assert_eq!(recs.len(), 2);
}

#[test]
fn empty_output_yields_nothing() {
    assert!(parse_ss_unix_stream("").is_empty());
}
