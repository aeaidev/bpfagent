//! Tests for the IFLAT_UPROBE interface, attach-target and tag-location
//! settings parsing.

use bpfagent::{
    config::EbpfProgramConfig,
    programs::iflat_uprobe::{
        parse_arg_index, parse_iface_setting, parse_offset, parse_payload_ptr_offset, parse_pid,
        parse_tag_offset,
    },
};
use iflat_uprobe_common::{MAX_ARGS, PAYLOAD_PTR_DIRECT};

fn config_with(settings: Option<toml::Table>) -> EbpfProgramConfig {
    EbpfProgramConfig {
        name: "iflat_uprobe".to_string(),
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
fn missing_settings_use_defaults() {
    let config = config_with(None);
    assert_eq!(parse_offset(&config), 0);
    assert_eq!(parse_pid(&config), -1);
    // Documented defaults: register 3 (rdx), direct payload pointer, tag at
    // the first payload byte.
    assert_eq!(parse_arg_index(&config), 3);
    assert_eq!(parse_payload_ptr_offset(&config), PAYLOAD_PTR_DIRECT);
    assert_eq!(parse_tag_offset(&config), 0);
    assert_eq!(parse_iface_setting(&config, "rx1_iface").unwrap(), None);
    assert_eq!(parse_iface_setting(&config, "rx2_iface").unwrap(), None);
}

#[test]
fn missing_keys_use_defaults() {
    let config = config_with(Some(toml::Table::new()));
    assert_eq!(parse_arg_index(&config), 3);
    assert_eq!(parse_payload_ptr_offset(&config), PAYLOAD_PTR_DIRECT);
    assert_eq!(parse_tag_offset(&config), 0);
}

#[test]
fn valid_arg_index_is_used() {
    for index in 1..=MAX_ARGS as i64 {
        let config = config_with(settings_with("arg_index", toml::Value::Integer(index)));
        assert_eq!(parse_arg_index(&config), index as u32);
    }
}

#[test]
fn out_of_range_arg_index_uses_default() {
    for bad in [0i64, (MAX_ARGS + 1) as i64, -1] {
        let config = config_with(settings_with("arg_index", toml::Value::Integer(bad)));
        assert_eq!(parse_arg_index(&config), 3);
    }
}

#[test]
fn valid_payload_ptr_offset_is_used() {
    // Struct mode: offsetof(TxSlot, payload) from docs/IFLAT_UPROBE.md.
    let config = config_with(settings_with(
        "payload_ptr_offset",
        toml::Value::Integer(296),
    ));
    assert_eq!(parse_payload_ptr_offset(&config), 296);

    // Zero is a valid offset (payload pointer is the first member).
    let config = config_with(settings_with("payload_ptr_offset", toml::Value::Integer(0)));
    assert_eq!(parse_payload_ptr_offset(&config), 0);
}

#[test]
fn minus_one_payload_ptr_offset_means_direct() {
    let config = config_with(settings_with(
        "payload_ptr_offset",
        toml::Value::Integer(-1),
    ));
    assert_eq!(parse_payload_ptr_offset(&config), PAYLOAD_PTR_DIRECT);
}

#[test]
fn other_negative_payload_ptr_offset_uses_default() {
    let config = config_with(settings_with(
        "payload_ptr_offset",
        toml::Value::Integer(-296),
    ));
    assert_eq!(parse_payload_ptr_offset(&config), PAYLOAD_PTR_DIRECT);
}

#[test]
fn valid_tag_offset_is_used() {
    let config = config_with(settings_with("tag_offset", toml::Value::Integer(8)));
    assert_eq!(parse_tag_offset(&config), 8);
}

#[test]
fn negative_tag_offset_uses_default() {
    let config = config_with(settings_with("tag_offset", toml::Value::Integer(-1)));
    assert_eq!(parse_tag_offset(&config), 0);
}

#[test]
fn negative_offset_and_pid_use_defaults() {
    let config = config_with(settings_with("offset", toml::Value::Integer(-8)));
    assert_eq!(parse_offset(&config), 0);
    let config = config_with(settings_with("pid", toml::Value::Integer(4242)));
    assert_eq!(parse_pid(&config), 4242);
}

#[test]
fn valid_iface_names_are_used() {
    let config = config_with(settings_with(
        "rx1_iface",
        toml::Value::String("veth-iu0".to_string()),
    ));
    assert_eq!(
        parse_iface_setting(&config, "rx1_iface").unwrap(),
        Some("veth-iu0".to_string())
    );
}

#[test]
fn invalid_iface_names_are_errors() {
    // Not a string
    let config = config_with(settings_with("rx1_iface", toml::Value::Integer(1)));
    assert!(parse_iface_setting(&config, "rx1_iface").is_err());
    // Empty
    let config = config_with(settings_with(
        "rx1_iface",
        toml::Value::String(String::new()),
    ));
    assert!(parse_iface_setting(&config, "rx1_iface").is_err());
    // Longer than IFNAMSIZ allows
    let config = config_with(settings_with(
        "rx1_iface",
        toml::Value::String("a".repeat(16)),
    ));
    assert!(parse_iface_setting(&config, "rx1_iface").is_err());
}
