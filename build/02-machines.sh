#!/usr/bin/env bash
# 02-machines.sh
# Builds the two lab machines and the Active Directory domain:
#   DC01  10.10.1.4  domain controller and DNS for soclab.internal
#   WS01  10.10.1.5  domain-joined workstation (the machine attacks run against)
# Neither machine has a public IP. Passwords come from a private env file outside the repo
# and are passed to the VMs as protected run-command parameters, never written to the repo.
# Safe to re-run: each stage checks whether it is already done.

set -euo pipefail

AZ="${AZ:-az}"
CREDS_FILE="${CREDS_FILE:?set CREDS_FILE to the private credentials env file}"
# shellcheck disable=SC1090
source "$CREDS_FILE"                 # provides VM_ADMIN_USER, VM_ADMIN_PASSWORD, DSRM_PASSWORD

LOCATION="southafricanorth"
RG="rg-soclab"
VNET="vnet-soclab"
SUBNET="snet-servers"
SIZE="${SIZE:-Standard_B2als_v2}"    # 2 vCPU, 4 GiB. Two of these use the full 4 vCPU regional quota.
# Small-disk image (30 GB) grown to 64 GB: a 64 GB Standard SSD (E6) costs USD 7.01 a month in
# South Africa North against USD 14.02 for the default 127 GB (E10). Enough room for a lab server.
IMAGE="MicrosoftWindowsServer:WindowsServer:2025-datacenter-smalldisk-g2:latest"
OS_DISK_GB=64
DOMAIN="soclab.internal"             # .internal is reserved by ICANN for private networks; .local clashes with mDNS
NETBIOS="SOCLAB"
DC_IP="10.10.1.4"
WS_IP="10.10.1.5"
SHUTDOWN_UTC="2100"                  # 23:00 South Africa time

create_vm () {
  local name=$1 ip=$2 role=$3
  if "$AZ" vm show -g "$RG" -n "$name" --output none 2>/dev/null; then
    echo "$name already exists, skipping create"; return
  fi
  "$AZ" vm create --resource-group "$RG" --name "$name" --computer-name "$name" \
    --location "$LOCATION" --image "$IMAGE" --size "$SIZE" \
    --admin-username "$VM_ADMIN_USER" --admin-password "$VM_ADMIN_PASSWORD" \
    --vnet-name "$VNET" --subnet "$SUBNET" --private-ip-address "$ip" \
    --public-ip-address "" --nsg "" \
    --os-disk-name "osdisk-${name,,}" --os-disk-size-gb "$OS_DISK_GB" --storage-sku StandardSSD_LRS \
    --security-type TrustedLaunch --enable-secure-boot true --enable-vtpm true \
    --patch-mode AutomaticByOS \
    --tags project=soc-lab role="$role" \
    --output none
  "$AZ" vm auto-shutdown --resource-group "$RG" --name "$name" --time "$SHUTDOWN_UTC" --output none
  echo "$name created at $ip, auto-shutdown 23:00 SAST"
}

# Runs a PowerShell script on a VM and prints its output.
# Extra arguments (Name=value) become protected parameters, which Azure encrypts and does not echo back.
run_ps () {
  local vm=$1 cmdname=$2 script=$3; shift 3
  local args=()
  if [ $# -gt 0 ]; then args=(--protected-parameters "$@"); fi
  "$AZ" vm run-command create --resource-group "$RG" --vm-name "$vm" --name "$cmdname" \
    --location "$LOCATION" --script "$script" "${args[@]}" \
    --timeout-in-seconds 3600 --output none
  "$AZ" vm run-command show --resource-group "$RG" --vm-name "$vm" --name "$cmdname" \
    --instance-view --query "instanceView.{state:executionState, exit:exitCode, out:output, err:error}" -o json
  "$AZ" vm run-command delete --resource-group "$RG" --vm-name "$vm" --name "$cmdname" --yes --output none
}

# 1. Machines, then grow the C: partition into the extra disk space.
create_vm DC01 "$DC_IP" domain-controller
create_vm WS01 "$WS_IP" workstation
EXTEND='$max = (Get-PartitionSupportedSize -DriveLetter C).SizeMax
if ((Get-Partition -DriveLetter C).Size -lt $max - 1MB) { Resize-Partition -DriveLetter C -Size $max }
"C: is now {0:N0} GB" -f ((Get-Partition -DriveLetter C).Size / 1GB)'
run_ps DC01 extend-disk "$EXTEND"
run_ps WS01 extend-disk "$EXTEND"

# 2. Promote DC01 to the first domain controller of a new forest.
PROMOTE='param([string]$DsrmPassword)
if ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4) { "DC01 is already a domain controller"; exit 0 }
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Null
Import-Module ADDSDeployment
Install-ADDSForest -DomainName "'"$DOMAIN"'" -DomainNetbiosName "'"$NETBIOS"'" `
  -SafeModeAdministratorPassword (ConvertTo-SecureString $DsrmPassword -AsPlainText -Force) `
  -InstallDns -NoRebootOnCompletion -Force | Out-Null
"Forest '"$DOMAIN"' created, reboot required"'
echo "Promoting DC01 (takes about 10 minutes)..."
run_ps DC01 promote-dc "$PROMOTE" "DsrmPassword=$DSRM_PASSWORD"
"$AZ" vm restart -g "$RG" -n DC01 --output none
echo "DC01 restarted"

# 3. After reboot: wait for AD to answer, then forward non-domain DNS lookups to Azure DNS.
POSTDC='$deadline = (Get-Date).AddMinutes(20)
do { try { $d = Get-ADDomain -ErrorAction Stop } catch { Start-Sleep 20 } } until ($d -or (Get-Date) -gt $deadline)
if (-not $d) { throw "AD did not come up within 20 minutes" }
if (-not (Get-DnsServerForwarder).IPAddress) { Add-DnsServerForwarder -IPAddress 168.63.129.16 }
"Domain: $($d.DNSRoot)  NetBIOS: $($d.NetBIOSName)  DC: $env:COMPUTERNAME"
"Forwarders: $((Get-DnsServerForwarder).IPAddress -join ", ")"'
run_ps DC01 post-dc "$POSTDC"

# 4. Point the whole network at DC01 for DNS, so WS01 can find the domain.
"$AZ" network vnet update -g "$RG" -n "$VNET" --dns-servers "$DC_IP" --output none
"$AZ" vm restart -g "$RG" -n WS01 --output none
echo "VNet DNS set to $DC_IP, WS01 restarted to pick it up"

# 5. Join WS01 to the domain.
JOIN='param([string]$JoinUser, [string]$JoinPassword)
if ((Get-CimInstance Win32_ComputerSystem).PartOfDomain) { "WS01 already joined to $((Get-CimInstance Win32_ComputerSystem).Domain)"; exit 0 }
$cred = New-Object System.Management.Automation.PSCredential($JoinUser, (ConvertTo-SecureString $JoinPassword -AsPlainText -Force))
Add-Computer -DomainName "'"$DOMAIN"'" -Credential $cred -Force
"WS01 joined '"$DOMAIN"', reboot required"'
run_ps WS01 join-domain "$JOIN" "JoinUser=$NETBIOS\\$VM_ADMIN_USER" "JoinPassword=$VM_ADMIN_PASSWORD"
"$AZ" vm restart -g "$RG" -n WS01 --output none

# 6. Check from the domain controller that WS01 is a member.
CHECK='Get-ADComputer -Filter * | Select-Object Name, DNSHostName, Enabled | Format-Table -AutoSize | Out-String'
run_ps DC01 check-members "$CHECK"

echo "Machines and domain complete."
