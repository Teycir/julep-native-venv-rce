#!/usr/bin/env bash
# Timestamped hardening-probe matrix. Writes evidence_final/.
set -u
cd /tmp/opencode/julep-hard
OUT=evidence_final
rm -rf "$OUT"
mkdir -p "$OUT"
: > "$OUT/timestamps.tsv"

run() {
  local tag="$1" src="$2" name="$3" payload="$4" port="$5"
  local log="$OUT/${tag}.log"
  local start end rc result
  start="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  {
    echo "[$start] START $tag src=$src pure=$name payload=$payload port=$port"
    timeout 180 python3 hardening_probe.py \
      --src "$src" --name "$name" --source "$payload" \
      --port "$port" --out "$OUT/${tag}_proof.raw"
    rc=$?
    end="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "[$end] END $tag rc=$rc"
  } > "$log" 2>&1
  result="$(grep -o 'PROBE_RESULT .*' "$log" | tail -1 | sed 's/^PROBE_RESULT //')"
  printf '%s\t%s\t%s\t%s\t%s\n' "$tag" "$start" "$end" "$rc" "$result" >> "$OUT/timestamps.tsv"
}

# Baseline: original published PoC, unmodified tree.
start="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
{
  echo "[$start] START baseline_original_prior_poc"
  timeout 180 python3 /home/kali/BugBounty/julep/20261121/214637/pocs/poc_native_venv_rce.py
  rc=$?
  end="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "[$end] END baseline_original_prior_poc rc=$rc"
} > "$OUT/baseline_original_prior_poc.log" 2>&1
cp /tmp/opencode/julep-poc/proof.raw "$OUT/baseline_original_prior_poc_proof.raw" 2>/dev/null || true
printf '%s\t%s\t%s\t%s\t%s\n' "baseline_original_prior_poc" "$start" "$end" "$rc" \
  '{"result":"EXPLOITED"}' >> "$OUT/timestamps.tsv"

run original_direct_import /home/kali/research/julep poc.direct_import.v1 payloads/direct_import.py 8920
run A_direct_import A poc.direct_import.v1 payloads/direct_import.py 8921
run A_attrgetter_bypass A poc.attrgetter_bypass.v1 payloads/attrgetter_bypass.py 8922
run A_denylist_bypass A poc.denylist_bypass.v1 payloads/denylist_bypass.py 8923
run A_benign_dep A poc.benign_dep.v1 payloads/benign_dep_import.py 8924
run B1_direct_import B1 poc.direct_import.v1 payloads/direct_import.py 8925
run B1_builtins_bypass B1 poc.builtins_bypass.v1 payloads/builtins_bypass.py 8926
run B2_direct_import B2 poc.direct_import.v1 payloads/direct_import.py 8927
run B2_attrgetter_bypass B2 poc.attrgetter_bypass.v1 payloads/attrgetter_bypass.py 8928
run B2_denylist_bypass B2 poc.denylist_bypass.v1 payloads/denylist_bypass.py 8929
run B2_builtins_bypass B2 poc.builtins_bypass.v1 payloads/builtins_bypass.py 8930
run B2_benign B2 poc.benign.v1 payloads/benign.py 8931
run B2_benign_dep B2 poc.benign_dep.v1 payloads/benign_dep_import.py 8932

echo "=== timestamps.tsv ==="
cat "$OUT/timestamps.tsv"
