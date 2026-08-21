// Builds the AF_XDP C shim and links the system libxdp/libbpf — but ONLY when the
// `afxdp` feature is enabled, so the default (portable) build needs no C toolchain
// or XDP libraries and `cargo test --workspace` stays cross-platform.

fn main() {
    if std::env::var_os("CARGO_FEATURE_AFXDP").is_none() {
        // Feature off: nothing to build. Still re-run if the shim changes.
        println!("cargo:rerun-if-changed=csrc/xsk_shim.c");
        return;
    }

    println!("cargo:rerun-if-changed=csrc/xsk_shim.c");

    // Compile the shim into a static lib and link it.
    cc::Build::new()
        .file("csrc/xsk_shim.c")
        .opt_level(2)
        .warnings(false)
        .compile("andro_xsk_shim");

    // Link the system AF_XDP stack. pkg-config emits the right search/link flags
    // and pulls in transitive deps (libbpf, elf, z); fall back to explicit -l.
    let xdp = pkg_config::Config::new().probe("libxdp");
    let bpf = pkg_config::Config::new().probe("libbpf");
    if xdp.is_err() || bpf.is_err() {
        println!("cargo:rustc-link-lib=xdp");
        println!("cargo:rustc-link-lib=bpf");
        println!("cargo:rustc-link-lib=elf");
        println!("cargo:rustc-link-lib=z");
    }
}
