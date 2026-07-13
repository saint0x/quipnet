#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCENARIOS_JSON="$ROOT/verification/fozzy/scenarios.json"
TRACES_JSON="$ROOT/verification/fozzy/traces.json"
DEFAULT_SEED="$(jq -r '.seed_policy.default_seed' "$SCENARIOS_JSON")"
DOCTOR_RUNS="$(jq -r '.doctor_defaults.runs' "$SCENARIOS_JSON")"

scenario_paths="$(
  jq -r '.scenarios[].scenario_path' "$SCENARIOS_JSON" | awk 'NF && !seen[$0]++'
)"

while IFS= read -r scenario_path; do
  [[ -n "$scenario_path" ]] || continue
  echo "== doctor $scenario_path"
  (cd "$ROOT" && fozzy doctor --deep --scenario "$scenario_path" --runs "$DOCTOR_RUNS" --seed "$DEFAULT_SEED" --strict --json)
  echo "== test $scenario_path"
  (cd "$ROOT" && fozzy test "$scenario_path" --det --strict-verify --json)
  echo "== host-run $scenario_path"
  (cd "$ROOT" && fozzy run "$scenario_path" --det --proc-backend host --fs-backend host --http-backend host --json)
done <<EOF
$scenario_paths
EOF

while IFS=$'\t' read -r trace_id scenario_path trace_path; do
  [[ -n "$trace_id" ]] || continue
  echo "== record $trace_id"
  rm -f "$ROOT/$trace_path"
  (cd "$ROOT" && fozzy run "$scenario_path" --det --record "$trace_path" --json)
  echo "== verify $trace_id"
  (cd "$ROOT" && fozzy trace verify "$trace_path" --strict --json)
  echo "== replay $trace_id"
  (cd "$ROOT" && fozzy replay "$trace_path" --json)
  echo "== ci $trace_id"
  (cd "$ROOT" && fozzy ci "$trace_path" --strict --json)
done < <(
  jq -r '.required_traces[] | [.id, .scenario_path, .trace_path] | @tsv' "$TRACES_JSON"
)
