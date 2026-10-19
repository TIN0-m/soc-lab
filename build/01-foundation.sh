#!/usr/bin/env bash
# 01-foundation.sh
# Creates the base of the SOC lab in Azure: a cost budget with email alerts,
# a resource group, and a private network that blocks all inbound internet traffic.
# Safe to re-run: every command creates or updates to the same end state.

set -euo pipefail

AZ="${AZ:-az}"                      # path to the Azure CLI
LOCATION="southafricanorth"         # Johannesburg
RG="rg-soclab"
VNET="vnet-soclab"
VNET_RANGE="10.10.0.0/16"
SUBNET="snet-servers"
SUBNET_RANGE="10.10.1.0/24"
NSG="nsg-servers"
BUDGET="budget-soclab"
BUDGET_AMOUNT=200                   # USD, equal to the free trial credit
ALERT_EMAIL="${ALERT_EMAIL:?set ALERT_EMAIL to the address that should get budget alerts}"

SUB_ID=$("$AZ" account show --query id -o tsv)

# 1. Budget with alerts at 25%, 50% and 75% of actual spend ($50, $100, $150),
#    plus a warning if Azure forecasts we will reach 100%.
#    Annual time grain so the count runs across the whole trial, which crosses a month boundary.
cat > /tmp/budget.json <<EOF
{
  "properties": {
    "category": "Cost",
    "amount": $BUDGET_AMOUNT,
    "timeGrain": "Annually",
    "timePeriod": { "startDate": "2026-10-01T00:00:00Z", "endDate": "2027-09-30T00:00:00Z" },
    "notifications": {
      "actual_25":   { "enabled": true, "operator": "GreaterThan", "threshold": 25,  "thresholdType": "Actual",     "contactEmails": ["$ALERT_EMAIL"] },
      "actual_50":   { "enabled": true, "operator": "GreaterThan", "threshold": 50,  "thresholdType": "Actual",     "contactEmails": ["$ALERT_EMAIL"] },
      "actual_75":   { "enabled": true, "operator": "GreaterThan", "threshold": 75,  "thresholdType": "Actual",     "contactEmails": ["$ALERT_EMAIL"] },
      "forecast_100":{ "enabled": true, "operator": "GreaterThan", "threshold": 100, "thresholdType": "Forecasted", "contactEmails": ["$ALERT_EMAIL"] }
    }
  }
}
EOF
"$AZ" rest --method put \
  --url "https://management.azure.com/subscriptions/$SUB_ID/providers/Microsoft.Consumption/budgets/$BUDGET?api-version=2023-05-01" \
  --body @/tmp/budget.json --output none
rm -f /tmp/budget.json
echo "Budget $BUDGET set: \$$BUDGET_AMOUNT with alerts at 25/50/75% actual and 100% forecast"

# 2. Resource group: one container for everything in the lab, tagged so it is
#    obvious what it is, who owns it and when it should be gone.
"$AZ" group create --name "$RG" --location "$LOCATION" \
  --tags project=soc-lab owner=tinotenda env=lab delete-after=2026-11-14 \
  --output none
echo "Resource group $RG ready in $LOCATION"

# 3. Network security group: Azure already denies inbound internet traffic by default
#    (rule DenyAllInBound, priority 65500). We add an explicit deny so the intent is
#    visible and survives anyone adding a broad allow rule at a lower priority later.
"$AZ" network nsg create --resource-group "$RG" --name "$NSG" --location "$LOCATION" --output none
"$AZ" network nsg rule create --resource-group "$RG" --nsg-name "$NSG" \
  --name Deny-Internet-Inbound --priority 4000 --direction Inbound --access Deny \
  --protocol '*' --source-address-prefixes Internet --source-port-ranges '*' \
  --destination-address-prefixes '*' --destination-port-ranges '*' \
  --description "No inbound access from the internet. Admin access goes through Tailscale." \
  --output none
echo "NSG $NSG ready: all inbound internet traffic denied"

# 4. Virtual network and subnet. VMs get no public IPs.
#    Outbound internet (Windows Update, Tailscale, Sentinel agent) uses Azure default
#    outbound access. Microsoft recommends a NAT gateway for production, but it costs
#    about USD 33 a month, so for a 30-day lab we accept default outbound and record the trade-off.
"$AZ" network vnet create --resource-group "$RG" --name "$VNET" --location "$LOCATION" \
  --address-prefixes "$VNET_RANGE" --output none
"$AZ" network vnet subnet create --resource-group "$RG" --vnet-name "$VNET" --name "$SUBNET" \
  --address-prefixes "$SUBNET_RANGE" --network-security-group "$NSG" \
  --default-outbound-access true --output none
echo "Network $VNET ($VNET_RANGE) with subnet $SUBNET ($SUBNET_RANGE) ready"

echo "Foundation complete."
