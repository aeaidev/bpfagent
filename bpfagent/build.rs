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
    aya_build::build_ebpf(ebpf_packages, Toolchain::default())
}
