# Contributing

Thanks for taking a look. This is a portfolio/learning project, but it's built to a
real bar — contributions and questions are welcome.

## Getting set up

The portable parts (everything except the live AF_XDP socket) build anywhere with a
recent stable Rust toolchain:

```bash
cargo test --workspace        # 41 tests
cargo run -p andromeda-cli -- bench
```

The AF_XDP datapath needs Linux, `libxdp-dev` + `libbpf-dev`, and a kernel with
`CONFIG_XDP_SOCKETS=y`:

```bash
# Debian/Ubuntu
sudo apt-get install -y libxdp-dev libbpf-dev libelf-dev zlib1g-dev clang m4 pkg-config
cargo build --release -p andromeda-cli --features afxdp
```

Or just use Docker — see the [README](README.md) quickstart.

## Before you open a PR

CI runs these; run them locally first:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy -p andromeda-cli --features afxdp --all-targets -- -D warnings
cargo test --workspace
```

## Ground rules

- **The hot path stays allocation-free.** No per-packet `Vec`/`Box`; operate on the
  caller's buffers.
- **`andromeda-core` stays `#![forbid(unsafe_code)]`** and dependency-free. `unsafe`
  is confined to the AF_XDP FFI layer, and it is documented where it lives.
- **New wire-format handling comes with a byte-level test** against a known-good
  vector, and any checksum change is proven bit-identical to a full recompute.
- **Benchmarks are honest.** If a change only helps a synthetic case (e.g. a
  single-flow cache), say so; don't present it as a general speedup.

## Good first issues

See the "Future work" section of [`docs/REPORT.md`](docs/REPORT.md): multi-VPC per
switch, IPv6/ND, MAC learning, shared-UMEM zero-copy on the two-interface switch,
and native-mode AF_XDP throughput on a real NIC.
