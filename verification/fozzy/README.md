# Fozzy Verification Assets

This directory contains machine-readable verification inputs for Quip production readiness.

These artifacts are intended to back:
- deterministic Fozzy scenario runs
- recorded trace requirements
- release-gate enforcement
- host-backed runtime validation

Current artifacts:
- `scenarios.json`
  - canonical scenario catalog for production verification
- `traces.json`
  - required recorded-trace set
- `release-gate.json`
  - machine-readable release verification expectations

These files should eventually drive real `fozzy doctor`, `fozzy test`, `fozzy run`, `fozzy replay`, `fozzy trace verify`, and `fozzy ci` invocations.
