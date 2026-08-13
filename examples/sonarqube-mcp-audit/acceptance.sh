#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "$0")/../.." && pwd); work_dir=$(mktemp -d); port_base=18200; node_pid=""
cleanup(){ if [[ -n "$node_pid" ]]; then kill "$node_pid" 2>/dev/null || true; wait "$node_pid" 2>/dev/null || true; fi; rm -rf "$work_dir"; }; trap cleanup EXIT
start_node(){ "$repo_root/target/debug/trustchain-node" sidecar --name sonar-pilot --endpoint http://127.0.0.1:18080 --port-base "$port_base" --data-dir "$work_dir/data" --no-networking >"$work_dir/node.log" 2>&1 & node_pid=$!; for _ in $(seq 1 60); do curl -fsS "http://127.0.0.1:$((port_base+2))/healthz" >"$work_dir/health.json" && return; sleep 0.25; done; cat "$work_dir/node.log" >&2; exit 1; }
start_node
ss -ltn | grep -q "127.0.0.1:$((port_base+2))"
if ss -ltn | grep -Eq "(0\.0\.0\.0|\[::\]):$((port_base+2))"; then echo "audit API is not loopback-only" >&2; exit 1; fi
python3 "$repo_root/examples/sonarqube-mcp-audit/pilot.py"
curl -fsS "http://127.0.0.1:$((port_base+2))/audit-report" >"$work_dir/report.json"
python3 - "$work_dir/report.json" <<'PY'
import json,sys
r=json.load(open(sys.argv[1])); assert r["total_blocks"]==r["audit_blocks"]==r["chain_length"]==2; assert r["bilateral_blocks"]==0 and r["integrity_valid"] is True and r["integrity_score"]==1.0
PY
curl -fsS "http://127.0.0.1:$((port_base+2))/export-chain" >"$work_dir/export.json"; "$repo_root/target/debug/verify-export" "$work_dir/export.json"
public_key=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["public_key"])' "$work_dir/health.json")
kill "$node_pid"; wait "$node_pid" || true; node_pid=""; start_node
curl -fsS "http://127.0.0.1:$((port_base+2))/healthz" >"$work_dir/health-restart.json"; curl -fsS "http://127.0.0.1:$((port_base+2))/audit-report" >"$work_dir/report-restart.json"
python3 - "$work_dir/health-restart.json" "$work_dir/report-restart.json" "$public_key" <<'PY'
import json,sys
assert json.load(open(sys.argv[1]))["public_key"]==sys.argv[3]; assert json.load(open(sys.argv[2]))["chain_length"]==2
PY
python3 - "$work_dir/export.json" "$work_dir/tampered.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]));d["chain"][0]["transaction"]["user_id"]="mallory";json.dump(d,open(sys.argv[2],"w"))
PY
if "$repo_root/target/debug/verify-export" "$work_dir/tampered.json"; then echo "tampered export accepted" >&2; exit 1; fi
echo "SonarQube MCP local audit acceptance: PASS"
