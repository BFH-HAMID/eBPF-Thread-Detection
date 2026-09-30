use which::which;

/// Building this crate has an undeclared dependency on the `bpf-linker` binary. This would be
/// better expressed by [artifact-dependencies][bindeps] but issues such as
/// https://github.com/rust-lang/cargo/issues/12385 make their use impractical for the time being.
///
/// This file implements an imperfect solution: it causes cargo to rebuild the crate whenever the
/// mtime of `which bpf-linker` changes. Note that possibility that a new bpf-linker is added to
/// $PATH ahead of the one used as the cache key still exists. Solving this in the general case
/// would require rebuild-if-changed-env=PATH *and* rebuild-if-changed={every-directory-in-PATH}
/// which would likely mean far too much cache invalidation.
///
/// [bindeps]: https://doc.rust-lang.org/nightly/cargo/reference/unstable.html?highlight=feature#artifact-dependencies
fn main() {
    // Note: this is only a cache-invalidation aid. Degrade gracefully when
    // `bpf-linker` is not installed (e.g. host-side `cargo test`/`clippy` runs
    // with AYA_BUILD_SKIP=1 that never build the bpfel target).
    if let Ok(bpf_linker) = which("bpf-linker")
        && let Some(path) = bpf_linker.to_str()
    {
        println!("cargo:rerun-if-changed={path}");
    }
}
