use anyhow::{Context as _, anyhow};
use aya_build::Toolchain;

fn main() -> anyhow::Result<()> {
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "sentinel-ebpf")
        .ok_or_else(|| anyhow!("sentinel-ebpf package not found"))?;
    let cargo_metadata::Package {
        name,
        manifest_path,
        ..
    } = ebpf_package;
    let ebpf_package = aya_build::Package {
        name: name.as_str(),
        root_dir: manifest_path
            .parent()
            .ok_or_else(|| anyhow!("no parent for {manifest_path}"))?
            .as_str(),
        ..Default::default()
    };
    aya_build::build_ebpf([ebpf_package], Toolchain::default())?;

    // When AYA_BUILD_SKIP is set (e.g. `cargo check`/`cargo clippy` on hosts
    // without a nightly toolchain or bpf-linker), aya-build skips the eBPF
    // build. Drop a placeholder object into OUT_DIR so that
    // `include_bytes_aligned!` still compiles; the binary will refuse to load
    // it at runtime.
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").context("OUT_DIR")?);
    let artifact = out_dir.join("sentinel");
    if !artifact.exists() {
        std::fs::write(&artifact, b"").with_context(|| format!("{}", artifact.display()))?;
    }
    Ok(())
}
