#!/usr/bin/env bash
# deploy.sh: creates or updates the Sentinel scheduled analytics rule for privileged group changes.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC1091
source "$HERE/../../build/lib.sh"

RULE_ID="6f1c2a7e-3b8d-4c11-9e5a-0b7d2f4a9c01"   # fixed so re-running updates the same rule
WS_ID=$("$AZ" monitor log-analytics workspace show -g "$RG" -n law-soclab --query id -o tsv)
QUERY=$(cat "$HERE/query.kql")

BODY=$(python -I - "$QUERY" <<'EOF'
import json, sys
print(json.dumps({
  "kind": "Scheduled",
  "properties": {
    "displayName": "Member added to a privileged AD group",
    "description": "Fires when an account is added to Domain Admins or another high-privilege Active Directory group. Adding a foothold account to a privileged group is a common way for an intruder to gain and keep control of a domain (MITRE ATT&CK T1098). Every hit should be checked against an approved change.",
    "severity": "High",
    "enabled": True,
    "query": sys.argv[1],
    "queryFrequency": "PT5M",
    "queryPeriod": "PT10M",
    "triggerOperator": "GreaterThan",
    "triggerThreshold": 0,
    "suppressionEnabled": False,
    "suppressionDuration": "PT1H",
    "tactics": ["Persistence", "PrivilegeEscalation"],
    "techniques": ["T1098"],
    "eventGroupingSettings": {"aggregationKind": "AlertPerResult"},
    "alertDetailsOverride": {
      "alertDisplayNameFormat": "{{Member}} added to {{GroupName}} by {{ChangedBy}}",
      "alertDescriptionFormat": "{{ChangedBy}} added {{Member}} to the privileged group {{GroupName}}. Confirm there is an approved change for this."
    },
    "customDetails": {"GroupName": "GroupName", "Member": "Member", "ChangedBy": "ChangedBy"},
    "entityMappings": [
      {"entityType": "Account", "fieldMappings": [{"identifier": "Sid", "columnName": "MemberSid"}]},
      {"entityType": "Account", "fieldMappings": [{"identifier": "FullName", "columnName": "ChangedBy"}]},
      {"entityType": "Host", "fieldMappings": [{"identifier": "FullName", "columnName": "Computer"}]}
    ],
    # Tuned 26 Oct 2026 after the first test: the 10-minute look-back on a 5-minute schedule
    # catches each event in two runs, which opened two incidents for one change. Grouping
    # alerts with the same accounts and host for an hour folds the repeat into one incident,
    # while keeping the look-back wide enough for late-arriving logs.
    "incidentConfiguration": {
      "createIncident": True,
      "groupingConfiguration": {
        "enabled": True, "reopenClosedIncident": False,
        "lookbackDuration": "PT1H", "matchingMethod": "AllEntities"
      }
    }
  }
}))
EOF
)

"$AZ" rest --method put \
  --url "https://management.azure.com${WS_ID}/providers/Microsoft.SecurityInsights/alertRules/${RULE_ID}?api-version=2024-03-01" \
  --body "$BODY" \
  --query "{name:properties.displayName, enabled:properties.enabled, severity:properties.severity, every:properties.queryFrequency, lookback:properties.queryPeriod}" -o json
