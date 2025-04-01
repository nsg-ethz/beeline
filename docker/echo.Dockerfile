FROM rust:1.85.1-slim

# View app name in Cargo.toml
ARG APP_NAME=echo

WORKDIR /echo
COPY echo .
COPY Cargo.lock .
RUN cargo build --release

CMD ["target/release/echo", "-a", "0.0.0.0:8080"]
