#!/usr/bin/env bash
# 03a-tailscale.sh
# Installs Tailscale on DC01 and WS01 so they can be reached over a private, encrypted
# network without any inbound port open in Azure. Each machine prints a one-time login URL;
# the lab owner opens it and approves the machine in their own Tailscale account.
# No auth keys are created or stored.

set -euo pipefail

AZ="${AZ:-az}"
RG="rg-soclab"
LOCATION="southafricanorth"

# Runs on the VM as SYSTEM through Azure Run Command.
INSTALL='param([string]$NodeName)
$ts = "C:\Program Files\Tailscale\tailscale.exe"
if (-not (Test-Path $ts)) {
  $msi = Join-Path $env:TEMP "tailscale-setup-latest-amd64.msi"
  Invoke-WebRequest -Uri "https://pkgs.tailscale.com/stable/tailscale-setup-latest-amd64.msi" -OutFile $msi -UseBasicParsing
  # Refuse to install anything that is not validly signed by Tailscale.
  $sig = Get-AuthenticodeSignature $msi
  if ($sig.Status -ne "Valid" -or $sig.SignerCertificate.Subject -notmatch "Tailscale") {
    throw "Installer signature check failed: $($sig.Status) / $($sig.SignerCertificate.Subject)"
  }
  "Installer signed by: $($sig.SignerCertificate.Subject)"
  # Unattended mode keeps Tailscale running as a service with nobody logged in.
  Start-Process msiexec.exe -Wait -ArgumentList "/i `"$msi`" /quiet /norestart TS_UNATTENDEDMODE=always TS_NOLAUNCH=true"
  Start-Sleep 10
}
$state = (& $ts status --json | ConvertFrom-Json)
if ($state.BackendState -eq "Running") { "Already connected as $($state.Self.DNSName)"; exit 0 }
# Start the login and return straight away; the URL stays valid while the service waits.
& $ts up --unattended --hostname=$NodeName --timeout=15s 2>&1 | Out-Null
Start-Sleep 5
$state = (& $ts status --json | ConvertFrom-Json)
"State: $($state.BackendState)"
"LOGIN_URL: $($state.AuthURL)"'

for vm in DC01 WS01; do
  "$AZ" vm wait -g "$RG" -n "$vm" --custom "instanceView.statuses[?code=='PowerState/running']" --interval 10 --timeout 600
  node=$(echo "$vm" | tr '[:upper:]' '[:lower:]')
  "$AZ" vm run-command create -g "$RG" --vm-name "$vm" --name install-tailscale --location "$LOCATION" \
    --script "$INSTALL" --parameters "NodeName=$node" --timeout-in-seconds 900 --output none
  echo "== $vm"
  "$AZ" vm run-command show -g "$RG" --vm-name "$vm" --name install-tailscale --instance-view \
    --query "instanceView.{state:executionState, exit:exitCode, out:output, err:error}" -o json
  "$AZ" vm run-command delete -g "$RG" --vm-name "$vm" --name install-tailscale --yes --output none
done
