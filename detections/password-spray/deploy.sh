#!/usr/bin/env bash
# deploy.sh: creates or updates the Sentinel scheduled analytics rule for password spraying.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC1091
source "$HERE/../../build/lib.sh"

RULE_ID="b4e9d2f1-7a63-4c28-9d15-3f8a0c6b1e22"   # fixed so re-running updates the same rule
WS_ID=$("$AZ" monitor log-analytics workspace show -g "$RG" -n law-soclab --query id -o tsv)
QUERY=$(cat "$HERE/query.kql")

BODY=$(python -I - "$QUERY" <<'EOF'
import json, sys
print(json.dumps({
  "kind": "Scheduled",
  "properties": {
    "displayName": "Password spray: one host failing logons against many accounts",
    "description": "Fires when a single source fails to log on against several different accounts in a short window (MITRE ATT&CK T1110.003). This is the signature of a password spray. Severity is Medium because the pattern alone does not confirm a break-in; the analyst checks whether any of the targeted accounts then logged on successfully (event 4624) and raises it to High if so, per the onboarding pack (account takeover = High, spray with no success = Medium).",
    "severity": "Medium",
    "enabled": True,
    "query": sys.argv[1],
    "queryFrequency": "PT15M",
    "queryPeriod": "PT1H",
    "triggerOperator": "GreaterThan",
    "triggerThreshold": 0,
    "suppressionEnabled": False,
    "suppressionDuration": "PT1H",
    "tactics": ["CredentialAccess"],
    "techniques": ["T1110"],
    "subTechniques": ["T1110.003"],
    "eventGroupingSettings": {"aggregationKind": "SingleAlert"},
    "alertDetailsOverride": {
      "alertDisplayNameFormat": "Possible password spray from {{SourceHost}} ({{DistinctAccounts}} accounts)",
      "alertDescriptionFormat": "{{SourceHost}} failed to log on against {{DistinctAccounts}} different accounts ({{FailedAttempts}} attempts). Check whether any of these accounts then logged on successfully and raise to High if so."
    },
    "customDetails": {
      "SourceHost": "SourceHost", "DistinctAccounts": "DistinctAccounts", "FailedAttempts": "FailedAttempts"
    },
    "entityMappings": [
      {"entityType": "Host", "fieldMappings": [{"identifier": "FullName", "columnName": "SourceHost"}]}
    ],
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
