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
    QUICNET_STATE_PATH=/var/lib/quicnet/state.json \
    QUICNET_IDENTITY_PATH=/var/lib/quicnet/identity.json \
    QUICNET_IDENTITY_PASSPHRASE_ENV=QUICNET_IDENTITY_PASSPHRASE \
    QUICNET_SYNC=true \
    QUICNET_REVOCATION_SYNC=true

RUN useradd --system --home-dir /var/lib/quicnet --create-home --shell /usr/sbin/nologin quicnet
WORKDIR /var/lib/quicnet

COPY --from=builder /workspace/target/release/quicnetd /usr/local/bin/quicnetd
COPY --from=builder /workspace/target/release/quicnet /usr/local/bin/quicnet
COPY --from=builder /workspace/target/release/relay /usr/local/bin/relay

VOLUME ["/var/lib/quicnet"]
EXPOSE 4433/udp
USER quicnet

ENTRYPOINT ["/bin/sh", "-ec", "set -- --network \"$QUICNET_NETWORK\" --state-path \"$QUICNET_STATE_PATH\" --identity-path \"$QUICNET_IDENTITY_PATH\" --identity-passphrase-env \"$QUICNET_IDENTITY_PASSPHRASE_ENV\"; if [ \"$QUICNET_SYNC\" = \"true\" ]; then set -- \"$@\" --sync; fi; if [ \"$QUICNET_REVOCATION_SYNC\" = \"true\" ]; then set -- \"$@\" --revocation-sync; fi; if [ -n \"${QUICNET_AUTHORITY_ORIGIN:-}\" ]; then set -- \"$@\" --authority-origin \"$QUICNET_AUTHORITY_ORIGIN\"; fi; if [ -n \"${QUICNET_AUTHORITY_SUBJECT:-}\" ]; then set -- \"$@\" --authority-subject \"$QUICNET_AUTHORITY_SUBJECT\"; fi; if [ -n \"${QUICNET_AUTHORITY_SNAPSHOT:-}\" ]; then set -- \"$@\" --authority-snapshot \"$QUICNET_AUTHORITY_SNAPSHOT\"; fi; exec /usr/local/bin/quicnetd \"$@\""]
