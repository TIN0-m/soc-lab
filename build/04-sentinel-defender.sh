#!/usr/bin/env bash
# 04-sentinel-defender.sh
# Turns the lab into a monitored environment:
#   1. Log Analytics workspace with a daily ingestion cap
#   2. Microsoft Sentinel on that workspace (31-day free trial, 10 GB/day)
#   3. Azure Monitor Agent on DC01 and WS01 plus a data collection rule for
#      Security, Sysmon, PowerShell, service-install and Defender AV events
#   4. Subscription Activity log into the same workspace (who did what in Azure)
#   5. Microsoft Defender for Servers Plan 2 (30-day free trial), which onboards
#      Defender for Endpoint (EDR) on both VMs
# Safe to re-run.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC1091
source "$HERE/lib.sh"

WS_NAME="law-soclab"
DAILY_CAP_GB=3          # well under the 10 GB/day trial allowance; protects the credit if something gets noisy
RETENTION_DAYS=90       # included at no charge on a Sentinel-enabled workspace
DCR_NAME="dcr-soclab-windows"
SUB_ID=$("$AZ" account show --query id -o tsv)

# 1. Workspace
"$AZ" monitor log-analytics workspace create -g "$RG" -n "$WS_NAME" -l "$LOCATION" \
  --sku PerGB2018 --retention-time "$RETENTION_DAYS" --quota "$DAILY_CAP_GB" \
  --tags project=soc-lab --output none
WS_ID=$("$AZ" monitor log-analytics workspace show -g "$RG" -n "$WS_NAME" --query id -o tsv)
echo "Workspace $WS_NAME ready (cap ${DAILY_CAP_GB} GB/day, retention ${RETENTION_DAYS} days)"

# 2. Sentinel
"$AZ" rest --method put \
  --url "https://management.azure.com${WS_ID}/providers/Microsoft.SecurityInsights/onboardingStates/default?api-version=2024-03-01" \
  --body '{"properties":{}}' --output none
echo "Microsoft Sentinel enabled on $WS_NAME"

# 3a. Data collection rule: which Windows events go to the workspace.
cat > /tmp/dcr.json <<EOF
{
  "location": "$LOCATION",
  "kind": "Windows",
  "properties": {
    "description": "SOC lab: Security log, Sysmon, PowerShell, service installs, Defender AV detections",
    "dataSources": {
      "windowsEventLogs": [
        { "name": "securityLog", "streams": ["Microsoft-SecurityEvent"], "xPathQueries": ["Security!*"] },
        { "name": "endpointTelemetry", "streams": ["Microsoft-Event"], "xPathQueries": [
          "Microsoft-Windows-Sysmon/Operational!*",
          "Microsoft-Windows-PowerShell/Operational!*[System[(EventID=4103 or EventID=4104)]]",
          "System!*[System[(EventID=7045 or EventID=7040 or EventID=104)]]",
          "Microsoft-Windows-Windows Defender/Operational!*[System[(EventID=1116 or EventID=1117 or EventID=5001 or EventID=5007)]]"
        ] }
      ]
    },
    "destinations": { "logAnalytics": [ { "name": "law", "workspaceResourceId": "$WS_ID" } ] },
    "dataFlows": [
      { "streams": ["Microsoft-SecurityEvent"], "destinations": ["law"] },
      { "streams": ["Microsoft-Event"], "destinations": ["law"] }
    ]
  }
}
EOF
DCR_ID="/subscriptions/$SUB_ID/resourceGroups/$RG/providers/Microsoft.Insights/dataCollectionRules/$DCR_NAME"
"$AZ" rest --method put --url "https://management.azure.com${DCR_ID}?api-version=2022-06-01" --body "$(cat /tmp/dcr.json)" --output none
rm -f /tmp/dcr.json
echo "Data collection rule $DCR_NAME ready"

# 3b. Azure Monitor Agent on each VM (needs a system-assigned managed identity), then link the rule.
for vm in DC01 WS01; do
  "$AZ" vm identity assign -g "$RG" -n "$vm" --output none
  "$AZ" vm extension set -g "$RG" --vm-name "$vm" --name AzureMonitorWindowsAgent \
    --publisher Microsoft.Azure.Monitor --enable-auto-upgrade true --output none
  VM_ID=$("$AZ" vm show -g "$RG" -n "$vm" --query id -o tsv)
  "$AZ" rest --method put \
    --url "https://management.azure.com${VM_ID}/providers/Microsoft.Insights/dataCollectionRuleAssociations/dcra-soclab-windows?api-version=2022-06-01" \
    --body "{\"properties\":{\"dataCollectionRuleId\":\"$DCR_ID\"}}" --output none
  echo "$vm: Azure Monitor Agent installed and linked to $DCR_NAME"
done

# 4. Azure Activity log for the subscription (free to ingest into Sentinel).
if ! "$AZ" monitor diagnostic-settings subscription show --name activity-to-sentinel --output none 2>/dev/null; then
  "$AZ" monitor diagnostic-settings subscription create --name activity-to-sentinel --location "$LOCATION" \
    --workspace "$WS_ID" \
    --logs '[{"category":"Administrative","enabled":true},{"category":"Security","enabled":true},{"category":"Policy","enabled":true},{"category":"Alert","enabled":true},{"category":"ServiceHealth","enabled":true}]' \
    --output none
fi
echo "Subscription Activity log flowing to $WS_NAME"

# 5. Defender for Servers Plan 2 (free for 30 days, then about USD 15 per server per month).
"$AZ" security pricing create -n VirtualMachines --tier Standard --subplan P2 --output none
"$AZ" security pricing show -n VirtualMachines --query "{plan:name, tier:pricingTier, subPlan:subPlan, freeTrialRemaining:freeTrialRemainingTime}" -o json

echo "Sentinel and Defender setup complete. Logs take 10 to 20 minutes to start arriving."
