#!/usr/bin/env bash
# check-ingestion.sh: shows what has reached the Sentinel workspace in the last hour.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck disable=SC1091
source "$HERE/lib.sh"
WS_CUSTOMER_ID=$("$AZ" monitor log-analytics workspace show -g "$RG" -n law-soclab --query customerId -o tsv)
QUERY='union withsource=Table SecurityEvent, Event, AzureActivity, Heartbeat
| where TimeGenerated > ago(1h)
| summarize Events = count(), Latest = max(TimeGenerated) by Table, Computer = iff(isempty(Computer), "-", Computer)
| order by Table asc, Computer asc'
"$AZ" rest --method post --url "https://api.loganalytics.io/v1/workspaces/$WS_CUSTOMER_ID/query" \
  --resource "https://api.loganalytics.io" \
  --body "$(python -I -c 'import json,sys; print(json.dumps({"query": sys.argv[1]}))' "$QUERY")" \
  --query "tables[0].rows" -o tsv
