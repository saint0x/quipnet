# Protocol Commitments

The `proto/` directory holds canonical, implementation-independent protocol commitments for Quicnet.

Current Milestone 1 commitments:

- `PeerId` is derived from the canonical public identity key using `multicodec || multihash`.
- signed records use a deterministic JSON envelope for now, with a planned migration to a compact canonical binary encoding once the test vectors and compatibility harness are in place;
- session credentials bind `NetworkId`, `PeerId`, session public key, protocol versions, and key epoch;
- transport-facing APIs remain implementation-neutral and cannot expose QUIC-engine-specific model.

Follow-up work belongs in discrete schemas and test vectors colocated with their RFCs.

