#!/usr/bin/env bash
# kql.sh: run a KQL query against the lab's Sentinel workspace from the command line.
# Usage: bash build/scripts/kql.sh 'SecurityEvent | take 5'     (or pipe the query in on stdin)
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck disable=SC1091
source "$HERE/lib.sh"
QUERY="${1:-$(cat)}"
WS_CUSTOMER_ID=$("$AZ" monitor log-analytics workspace show -g "$RG" -n law-soclab --query customerId -o tsv)
"$AZ" rest --method post --url "https://api.loganalytics.io/v1/workspaces/$WS_CUSTOMER_ID/query" \
  --resource "https://api.loganalytics.io" \
  --body "$(python -I -c 'import json,sys; print(json.dumps({"query": sys.argv[1]}))' "$QUERY")" \
  --query "tables[0]" -o json | python -I -c '
import json, sys
t = json.load(sys.stdin)
cols = [c["name"] for c in t["columns"]]
print("\t".join(cols))
for r in t["rows"]:
    print("\t".join("" if v is None else str(v) for v in r))'
