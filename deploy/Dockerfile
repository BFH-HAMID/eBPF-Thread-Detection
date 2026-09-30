# Sentinel agent image: build the Rust workspace (agent + eBPF) and ship a
# minimal runtime. The image needs CAP_BPF/CAP_PERFMON (or SYS_ADMIN) at run
# time; see deploy/daemonset.yaml.

FROM rust:bookworm AS builder

# Nightly + rust-src for the bpfel-unknown-none target, bpf-linker for the
# final eBPF link step (see README "Prerequisites").
RUN rustup toolchain install nightly --component rust-src \
    && rustup default stable
RUN cargo install bpf-linker

WORKDIR /src
COPY Cargo.toml rustfmt.toml ./
COPY bpf ./bpf
COPY agent ./agent
COPY rules ./rules

RUN cargo build --release -p sentinel

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/sentinel /usr/local/bin/sentinel
COPY rules /etc/sentinel/rules

# Default: load rules from /etc/sentinel/rules, alert JSON on stdout for the
# cluster log pipeline.
ENTRYPOINT ["/usr/local/bin/sentinel"]
CMD ["--rules", "/etc/sentinel/rules"]
