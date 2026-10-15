FROM rust:1.91-bookworm@sha256:c1e5f19e773b7878c3f7a805dd00a495e747acbdc76fb2337a4ebf0418896b33

WORKDIR /opt/openmls-interop
COPY spec/pqc_mls_interop/Cargo.toml spec/pqc_mls_interop/Cargo.lock ./
COPY spec/pqc_mls_interop/src ./src
RUN cargo build --locked --release

CMD ["/opt/openmls-interop/target/release/mastodon-openmls-interop"]
