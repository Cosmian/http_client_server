use serde::Deserialize;
use serde::Serialize;

use super::*;
use std::env;
use std::fs;
use std::path::PathBuf;

#[cfg(unix)]
const TEST_FILE: &str = "/bin/cat";
#[cfg(windows)]
const TEST_FILE: &str = "C:\\Windows\\System32\\cmd.exe";

#[test]
fn test_location() {
    // Test with CLI argument
    let conf_path = PathBuf::from(TEST_FILE);
    let result = location(
        Some(conf_path.clone()),
        "TEST_CONF",
        "config/default.toml",
        "/etc/default.toml",
    );
    assert_eq!(result.unwrap(), conf_path);

    // Test with environment variable
    env::set_var("TEST_CONF", TEST_FILE);
    let result = location(
        None,
        "TEST_CONF",
        "config/default.toml",
        "/etc/default.toml",
    );
    assert_eq!(result.unwrap(), PathBuf::from(TEST_FILE));

    // Test with default path
    env::remove_var("TEST_CONF");
    env::set_var("HOME", "/fake/home");
    let result = location(
        None,
        "TEST_CONF",
        "config/default.toml",
        "/etc/default.toml",
    );
    assert_eq!(
        result.unwrap(),
        PathBuf::from("/fake/home/config/default.toml")
    );
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct TestConfig {
    key: String,
}

impl ConfigUtils for TestConfig {}

#[test]
fn test_config_utils_save_and_load() {
    let conf_path = "test_config.toml";
    let config = TestConfig {
        key: "value".to_string(),
    };

    // Test saving to TOML
    config.to_toml(conf_path).unwrap();
    let loaded_config = TestConfig::from_toml(conf_path).unwrap();
    assert_eq!(config.key, loaded_config.key);

    // Test saving to JSON
    config.to_json(conf_path).unwrap();
    let loaded_config = TestConfig::from_json(conf_path).unwrap();
    assert_eq!(config.key, loaded_config.key);

    // Clean up
    fs::remove_file(conf_path).unwrap();
}
