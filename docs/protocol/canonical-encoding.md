# Canonical Encoding

Current Milestone 1 code uses deterministic JSON serialization for signed records and session credentials so canonical test vectors can be established immediately.

The production direction remains a compact canonical binary framing with:

- bounded varint lengths
- protocol identifiers
- message and schema versions
- optional deadlines and correlation IDs
- explicit size caps before allocation

Any future migration must preserve deterministic canonical bytes for signature verification and come with golden vectors plus interop tests.

