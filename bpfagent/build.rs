use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{anyhow, Context as _};
use aya_build::Toolchain;

fn main() -> anyhow::Result<()> {
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;

    // Build both kfree_skb and SCA eBPF packages
    let mut ebpf_packages = Vec::new();
    let mut names: Vec<String> = Vec::new();
    let mut root_dirs: Vec<String> = Vec::new();

    for package in packages {
        let name = package.name.clone();
        match name.as_str() {
            "kfree_skb-ebpf" | "sca-ebpf" => {
                names.push(name.to_string());
                let manifest_path = package.manifest_path.clone();
                let root_dir = manifest_path
                    .parent()
                    .ok_or_else(|| anyhow!("no parent for manifest"))?
                    .to_string();
                root_dirs.push(root_dir);
            }
            _ => {}
        }
    }

    for (name, root_dir) in names.iter().zip(root_dirs.iter()) {
        ebpf_packages.push(aya_build::Package {
            name: name.as_str(),
            root_dir: root_dir.as_str(),
            ..Default::default()
        });
    }

    if ebpf_packages.is_empty() {
        return Err(anyhow!("No eBPF packages found"));
    }
    aya_build::build_ebpf(ebpf_packages, Toolchain::default())?;

    build_c_ebpf_programs()
}

/// Compile any C eBPF programs with clang into OUT_DIR.
///
/// Discovery is transparent: every `ebpf/<plugin>/*.c` file in the workspace
/// is compiled to `OUT_DIR/<file-stem>`, no registration needed. That output
/// name is what the userspace handler loads via
/// `include_bytes_aligned!(concat!(env!("OUT_DIR"), "/<file-stem>"))`.
/// With no C sources present this is a no-op and clang is never invoked.
fn build_c_ebpf_programs() -> anyhow::Result<()> {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR")?;
    let ebpf_dir = Path::new(&manifest_dir)
        .parent()
        .ok_or_else(|| anyhow!("no parent for package manifest dir"))?
        .join("ebpf");

    let mut sources: Vec<PathBuf> = Vec::new();
    if ebpf_dir.is_dir() {
        for entry in fs::read_dir(&ebpf_dir)? {
            let plugin_dir = entry?.path();
            if !plugin_dir.is_dir() {
                continue;
            }
            for file in fs::read_dir(&plugin_dir)? {
                let path = file?.path();
                if path.extension().and_then(|ext| ext.to_str()) == Some("c") {
                    sources.push(path);
                }
            }
        }
    }
    if sources.is_empty() {
        return Ok(());
    }

    let out_dir = env::var("OUT_DIR")?;
    for src in sources {
        println!("cargo:rerun-if-changed={}", src.display());
        let stem = src
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| anyhow!("bad C eBPF file name: {}", src.display()))?;
        let status = Command::new("clang")
            .args(["-target", "bpfel", "-O2", "-g", "-c"])
            .arg(&src)
            .arg("-o")
            .arg(format!("{}/{}", out_dir, stem))
            .status()
            .with_context(|| format!("failed to run clang for {}", src.display()))?;
        if !status.success() {
            return Err(anyhow!("clang failed for {}", src.display()));
        }
    }
    Ok(())
}
