FROM rust:trixie AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY server ./server
RUN cargo build --release -p mylonite

FROM debian:trixie-slim AS runtime
RUN useradd --system --create-home --home-dir /var/lib/mylonite mylonite
COPY --from=build /src/target/release/mylonite /usr/local/bin/mylonite
USER mylonite
WORKDIR /var/lib/mylonite
EXPOSE 9821
ENTRYPOINT ["/usr/local/bin/mylonite"]
CMD ["serve", "--config", "/etc/mylonite/config.toml"]
