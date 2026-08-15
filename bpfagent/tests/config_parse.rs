//! Tests for TOML daemon configuration parsing.

use bpfagent::config::DaemonConfig;

const FULL_TOML: &str = r#"
pid_file = "/tmp/test.pid"
working_directory = "/"
log_file = "/tmp/test.log"

[[ebpf_programs]]
name = "kfree_skb"
enabled = true

[[ebpf_programs]]
name = "sca"
enabled = false
"#;

#[test]
fn full_config_parses() {
    let cfg: DaemonConfig = toml::from_str(FULL_TOML).expect("full config should parse");
    assert_eq!(cfg.pid_file, "/tmp/test.pid");
    assert_eq!(cfg.working_directory, "/");
    assert_eq!(cfg.log_file, "/tmp/test.log");
    assert_eq!(cfg.ebpf_programs.len(), 2);
    assert_eq!(cfg.ebpf_programs[0].name, "kfree_skb");
    assert!(cfg.ebpf_programs[0].enabled);
    assert!(!cfg.ebpf_programs[1].enabled);
}

#[test]
fn program_enabled_defaults_to_true() {
    let cfg: DaemonConfig = toml::from_str(
        r#"
pid_file = "/p"
working_directory = "/"
log_file = "/l"

[[ebpf_programs]]
name = "sca"
"#,
    )
    .expect("config should parse");
    assert!(cfg.ebpf_programs[0].enabled);
}

#[test]
fn missing_daemon_keys_are_an_error() {
    // Documents current behavior: pid_file, working_directory and log_file
    // are mandatory in the config file.
    let result = toml::from_str::<DaemonConfig>(
        r#"
[[ebpf_programs]]
name = "sca"
"#,
    );
    assert!(result.is_err());
}

#[test]
fn missing_programs_table_means_empty_list() {
    let cfg: DaemonConfig = toml::from_str(
        r#"
pid_file = "/p"
working_directory = "/"
log_file = "/l"
"#,
    )
    .expect("config should parse");
    assert!(cfg.ebpf_programs.is_empty());
}

#[test]
fn invalid_toml_is_an_error() {
    assert!(toml::from_str::<DaemonConfig>("this is not [toml").is_err());
}
