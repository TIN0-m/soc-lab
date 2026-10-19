#!/usr/bin/env bash
# lib.sh: shared helpers for the build scripts. Source it, do not run it.

# Git Bash on Windows rewrites arguments that start with "/" into Windows paths, which breaks
# Azure resource IDs like /subscriptions/... Turn that conversion off.
export MSYS_NO_PATHCONV=1

AZ="${AZ:-az}"
RG="${RG:-rg-soclab}"
LOCATION="${LOCATION:-southafricanorth}"

# run_ps VM NAME SCRIPT_FILE [Param=value ...]
# Runs a PowerShell file on a VM as SYSTEM through Azure Run Command and prints the result.
# Param=value pairs are sent as protected parameters: Azure encrypts them and does not return them.
run_ps () {
  local vm=$1 cmdname=$2 file=$3; shift 3
  local args=()
  if [ $# -gt 0 ]; then args=(--protected-parameters "$@"); fi
  "$AZ" vm run-command create --resource-group "$RG" --vm-name "$vm" --name "$cmdname" \
    --location "$LOCATION" --script "$(cat "$file")" "${args[@]}" \
    --timeout-in-seconds 3600 --output none
  echo "== $vm: $cmdname"
  "$AZ" vm run-command show --resource-group "$RG" --vm-name "$vm" --name "$cmdname" \
    --instance-view --query "instanceView.{state:executionState, exit:exitCode, out:output, err:error}" -o json
  "$AZ" vm run-command delete --resource-group "$RG" --vm-name "$vm" --name "$cmdname" --yes --output none
}
