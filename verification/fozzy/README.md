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
- `run-release-gate.sh`
  - local script that executes the concrete Fozzy release gate against the catalog and trace set

These files drive real `fozzy doctor`, `fozzy test`, `fozzy run`, `fozzy replay`, `fozzy trace verify`, and `fozzy ci` invocations.
