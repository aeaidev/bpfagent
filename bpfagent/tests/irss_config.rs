//! Tests for the IRSS raw_dest and listen_port configuration parsing.

use bpfagent::{
    config::EbpfProgramConfig,
    programs::irss::{parse_listen_port, parse_raw_dest},
};
use irss_common::{LISTEN_PORT, RAW_DEST};

fn config_with(settings: Option<toml::Table>) -> EbpfProgramConfig {
    EbpfProgramConfig {
        name: "irss".to_string(),
        enabled: true,
        settings,
    }
}

fn settings_with(key: &str, value: toml::Value) -> Option<toml::Table> {
    let mut table = toml::Table::new();
    table.insert(key.to_string(), value);
    Some(table)
}

#[test]
fn missing_settings_use_default() {
    assert_eq!(parse_raw_dest(&config_with(None)), RAW_DEST);
    assert_eq!(parse_listen_port(&config_with(None)), LISTEN_PORT);
}

#[test]
fn missing_keys_use_default() {
    let config = config_with(Some(toml::Table::new()));
    assert_eq!(parse_raw_dest(&config), RAW_DEST);
    assert_eq!(parse_listen_port(&config), LISTEN_PORT);
}

#[test]
fn non_string_raw_dest_uses_default() {
    let config = config_with(settings_with("raw_dest", toml::Value::Integer(42)));
    assert_eq!(parse_raw_dest(&config), RAW_DEST);
}

#[test]
fn valid_ipv4_raw_dest_is_used() {
    let config = config_with(settings_with(
        "raw_dest",
        toml::Value::String("192.0.2.1".to_string()),
    ));
    assert_eq!(parse_raw_dest(&config), [192, 0, 2, 1]);
}

#[test]
fn invalid_ipv4_raw_dest_uses_default() {
    let config = config_with(settings_with(
        "raw_dest",
        toml::Value::String("999.1.1.1".to_string()),
    ));
    assert_eq!(parse_raw_dest(&config), RAW_DEST);
}

#[test]
fn non_integer_listen_port_uses_default() {
    let config = config_with(settings_with(
        "listen_port",
        toml::Value::String("5020".to_string()),
    ));
    assert_eq!(parse_listen_port(&config), LISTEN_PORT);
}

#[test]
fn valid_listen_port_is_used() {
    let config = config_with(settings_with("listen_port", toml::Value::Integer(5051)));
    assert_eq!(parse_listen_port(&config), 5051);
}

#[test]
fn zero_listen_port_uses_default() {
    let config = config_with(settings_with("listen_port", toml::Value::Integer(0)));
    assert_eq!(parse_listen_port(&config), LISTEN_PORT);
}

#[test]
fn out_of_range_listen_port_uses_default() {
    let config = config_with(settings_with("listen_port", toml::Value::Integer(70_000)));
    assert_eq!(parse_listen_port(&config), LISTEN_PORT);
}
