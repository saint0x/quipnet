# syntax=docker/dockerfile:1.7

FROM rust:1.81-bookworm AS builder
WORKDIR /workspace
COPY . .

RUN cargo build --locked --release -p quipd \
 && cargo build --locked --release -p quip \
 && cargo build --locked --release -p relayd --bin relay

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates tzdata \
 && rm -rf /var/lib/apt/lists/*

ENV QUIP_NETWORK=personalcloud-prod \
    QUIP_STATE_PATH=/home/quip/.quip/net/state.json \
    QUIP_IDENTITY_PATH=/home/quip/.quip/identity/node.json \
    QUIP_IDENTITY_PASSPHRASE_ENV=QUIP_IDENTITY_PASSPHRASE \
    QUIP_SYNC=true \
    QUIP_REVOCATION_SYNC=true

RUN useradd --system --home-dir /home/quip --create-home --shell /usr/sbin/nologin quip

WORKDIR /home/quip/.quip

COPY --from=builder /workspace/target/release/quipd /usr/local/bin/quipd
COPY --from=builder /workspace/target/release/quip /usr/local/bin/quip
COPY --from=builder /workspace/target/release/relay /usr/local/bin/relay

VOLUME ["/home/quip/.quip"]
EXPOSE 4433/udp

USER quip

ENTRYPOINT ["/bin/sh", "-ec", "set -- --network \"$QUIP_NETWORK\" --state-path \"$QUIP_STATE_PATH\" --identity-path \"$QUIP_IDENTITY_PATH\" --identity-passphrase-env \"$QUIP_IDENTITY_PASSPHRASE_ENV\"; if [ \"$QUIP_SYNC\" = \"true\" ]; then set -- \"$@\" --sync; fi; if [ \"$QUIP_REVOCATION_SYNC\" = \"true\" ]; then set -- \"$@\" --revocation-sync; fi; if [ -n \"${QUIP_AUTHORITY_ORIGIN:-}\" ]; then set -- \"$@\" --authority-origin \"$QUIP_AUTHORITY_ORIGIN\"; fi; if [ -n \"${QUIP_AUTHORITY_SUBJECT:-}\" ]; then set -- \"$@\" --authority-subject \"$QUIP_AUTHORITY_SUBJECT\"; fi; if [ -n \"${QUIP_AUTHORITY_SNAPSHOT:-}\" ]; then set -- \"$@\" --authority-snapshot \"$QUIP_AUTHORITY_SNAPSHOT\"; fi; exec /usr/local/bin/quipd \"$@\""]
