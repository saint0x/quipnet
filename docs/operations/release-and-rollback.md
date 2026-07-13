# Release and Rollback

Milestone 1 establishes release signing, SBOM generation, reproducible source bundles, and deployment scaffolding before public rollout.

## Release Gates

- RFC and threat-model alignment for changed trust boundaries
- workspace build and unit tests
- deploy manifest validation
- source bundle checksum generation

## Rollback Rule

Every release must document state compatibility, reversible migrations, and kill-switch controls before rollout beyond internal environments.
