# syntax=docker/dockerfile:1.7

FROM rust:1.81-bookworm AS builder

WORKDIR /workspace
COPY . .

RUN cargo build --locked --release -p quicnetd \
    && cargo build --locked --release -p quicnet \
    && cargo build --locked --release -p relayd --bin relay

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/*

ENV QUICNET_NETWORK=personalcloud-prod \
    QUICNET_STATE_PATH=/var/lib/quicnet/state.json

RUN useradd --system --home-dir /var/lib/quicnet --create-home --shell /usr/sbin/nologin quicnet
WORKDIR /var/lib/quicnet

COPY --from=builder /workspace/target/release/quicnetd /usr/local/bin/quicnetd
COPY --from=builder /workspace/target/release/quicnet /usr/local/bin/quicnet
COPY --from=builder /workspace/target/release/relay /usr/local/bin/relay

VOLUME ["/var/lib/quicnet"]
EXPOSE 4433/udp
USER quicnet

ENTRYPOINT ["/bin/sh", "-ec", "exec /usr/local/bin/quicnetd --network \"$QUICNET_NETWORK\" --state-path \"$QUICNET_STATE_PATH\""]
