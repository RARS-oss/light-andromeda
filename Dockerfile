# Build + run Light-Andromeda in one command:
#
#   docker build -t andromeda .
#   docker run --rm andromeda bench        # performance table
#   docker run --rm andromeda inspect      # decode a synthesized overlay packet
#   docker run --rm andromeda selftest
#
# The live AF_XDP switch needs host networking + capabilities and a kernel with
# CONFIG_XDP_SOCKETS (the binary is built with the afxdp feature and is present):
#
#   docker run --rm --network host --cap-add NET_ADMIN --cap-add SYS_ADMIN \
#     andromeda run <iface> --mode dump --skb

FROM rust:1-slim-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang m4 pkg-config libxdp-dev libbpf-dev libelf-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cargo build --release -p andromeda-cli --features afxdp \
    && cargo test --workspace --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    libxdp1 libbpf1 iproute2 tcpdump ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/andromeda /usr/local/bin/andromeda
COPY --from=build /src/scripts /opt/andromeda/scripts
COPY --from=build /src/configs /opt/andromeda/configs
WORKDIR /opt/andromeda
ENTRYPOINT ["andromeda"]
CMD ["bench"]
