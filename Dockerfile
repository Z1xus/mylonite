FROM rust:1.98.1-bookworm@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
COPY server ./server
RUN cargo build --release --locked -p mylonite

FROM debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a
RUN useradd --system --create-home --home-dir /var/lib/mylonite mylonite
COPY --from=build /src/target/release/mylonite /usr/local/bin/mylonite
USER mylonite
WORKDIR /var/lib/mylonite
EXPOSE 9821
ENTRYPOINT ["/usr/local/bin/mylonite"]
CMD ["serve", "--config", "/etc/mylonite/config.toml"]
