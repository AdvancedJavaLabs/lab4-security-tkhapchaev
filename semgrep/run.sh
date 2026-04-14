#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SEMGREP="${SEMGREP:-/home/tkhapchaev/.local/bin/semgrep}"

RULES_DIR="$ROOT_DIR/semgrep/rules"
OUT_DIR="$ROOT_DIR/semgrep/results"
TARGET_DIR="$ROOT_DIR/src/main/java"
HASH_FILE="$OUT_DIR/rules.sha256"

CONFIGS=(
  "java:$RULES_DIR/p-java.yml"
  "owasp-top-ten:$RULES_DIR/p-owasp-top-ten.yml"
  "security-audit:$RULES_DIR/p-security-audit.yml"
  "secrets:$RULES_DIR/p-secrets.yml"
  "javalin:$RULES_DIR/p-javalin.yml"
)

if [[ ! -x "$SEMGREP" ]]; then
  echo "Semgrep not found or not executable: $SEMGREP"
  exit 1
fi

for config_entry in "${CONFIGS[@]}"; do
  rule_file="${config_entry#*:}"
  if [[ ! -f "$rule_file" ]]; then
    echo "Missing rule file: $rule_file"
    exit 1
  fi
done

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

for config_entry in "${CONFIGS[@]}"; do
  rule_file="${config_entry#*:}"
  sed -i 's/\r$//' "$rule_file"
done

sha256sum "$RULES_DIR"/*.yml | sort > "$HASH_FILE"

SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 "$SEMGREP" --version | tee "$OUT_DIR/version.txt"

count_findings() {
  local json_file="$1"
  python3 - "$json_file" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as f:
    data = json.load(f)
print(len(data.get("results", [])))
PY
}

run_scan() {
  local scan_name="$1"
  local config_file="$2"

  echo "== Running $scan_name scan =="
  SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 \
    "$SEMGREP" --config "$config_file" --verbose "$TARGET_DIR" 2>&1 | tee "$OUT_DIR/$scan_name.txt"

  SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 \
    "$SEMGREP" --config "$config_file" --json --output "$OUT_DIR/$scan_name.json" "$TARGET_DIR"

  SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 \
    "$SEMGREP" --config "$config_file" --sarif --output "$OUT_DIR/$scan_name.sarif" "$TARGET_DIR"

  local findings
  findings="$(count_findings "$OUT_DIR/$scan_name.json")"
  echo "$scan_name findings: $findings" | tee -a "$OUT_DIR/summary.txt"
}

for config_entry in "${CONFIGS[@]}"; do
  scan_name="${config_entry%%:*}"
  config_file="${config_entry#*:}"
  run_scan "$scan_name" "$config_file"
done

echo "== Output files =="
ls -lh "$OUT_DIR"
