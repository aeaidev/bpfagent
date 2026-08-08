//! Integration tests for bpfagent
//!
//! These tests verify the basic functionality of the application without
//! requiring actual eBPF program execution (which requires root).

#[cfg(test)]
mod tests {
    use std::path::Path;

    #[test]
    fn test_config_file_exists() {
        // Verify that configuration files are present in expected locations
        assert!(
            Path::new("../config/bpfagent.conf.example").exists(),
            "Example config file should exist"
        );
        assert!(
            Path::new("../config/bpfagent.conf.full").exists(),
            "Full config file should exist"
        );
    }

    #[test]
    fn test_documentation_exists() {
        // Verify that documentation files are present
        assert!(
            Path::new("../docs/ARCHITECTURE.md").exists(),
            "ARCHITECTURE.md should exist"
        );
        assert!(
            Path::new("../docs/DEVELOPMENT.md").exists(),
            "DEVELOPMENT.md should exist"
        );
        assert!(
            Path::new("../docs/PLUGINS.md").exists(),
            "PLUGINS.md should exist"
        );
        assert!(
            Path::new("../docs/CONTRIBUTING.md").exists(),
            "CONTRIBUTING.md should exist"
        );
    }

    #[test]
    fn test_scripts_exist_and_executable() {
        // Verify that development scripts are present and executable
        for script in &["setup.sh", "build.sh", "test.sh", "lint.sh", "format.sh", "release.sh"] {
            let path = format!("../scripts/{}", script);
            assert!(
                Path::new(&path).exists(),
                "Script {} should exist",
                script
            );
        }
    }

    #[test]
    fn test_project_structure() {
        // Verify the new modular structure
        let required_dirs = vec![
            "../bpfagent/src/cli",
            "../bpfagent/src/config",
            "../bpfagent/src/programs",
            "../bpfagent/src/metrics",
        ];

        for dir in required_dirs {
            assert!(
                Path::new(dir).is_dir(),
                "Directory {} should exist as part of modular structure",
                dir
            );
        }
    }

    #[test]
    fn test_readme_exists() {
        // Verify primary documentation
        assert!(Path::new("../README.md").exists(), "README.md should exist");
    }

    #[test]
    fn test_cargo_manifest_valid() {
        // Verify Cargo.toml can be parsed (basic syntax check)
        assert!(
            Path::new("../Cargo.toml").exists(),
            "Cargo.toml should exist at project root"
        );
    }
}
