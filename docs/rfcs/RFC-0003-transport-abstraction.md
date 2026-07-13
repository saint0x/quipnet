# RFC-0003: Transport Abstraction and Delivery Semantics

## Decision

The public Quipnet interface is transport-neutral. QUIC is the initial engine, but the SDK and daemon API cannot leak engine-specific model.

## Required Primitives

- ordered streams
- reliable message channels
- unreliable datagrams
- deadline-aware messages
- resumable bulk transfer

## Constraints

- routing migration is a first-class concern;
- one logical peer relationship should multiplex protocols;
- transport implementations must expose diagnostics and negotiated version state.

