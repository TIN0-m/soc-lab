# dc-gpo-logging.ps1 (runs on DC01)
# Creates and links one Group Policy Object, "SOC - Security Logging Baseline", that turns on
# the Windows logging a SOC needs. Applies to every machine in the domain, DCs included.
$ErrorActionPreference = "Stop"
Import-Module GroupPolicy, ActiveDirectory

$domain = Get-ADDomain
$dn     = $domain.DistinguishedName
$name   = "SOC - Security Logging Baseline"

$gpo = Get-GPO -Name $name -ErrorAction SilentlyContinue
if (-not $gpo) {
  $gpo = New-GPO -Name $name -Comment "Advanced audit policy, PowerShell logging, command-line capture and larger event logs for SOC monitoring."
}
$id = "{$($gpo.Id.ToString().ToUpper())}"

# 1. Registry-based settings.
$reg = @(
  # PowerShell script block logging: records the code PowerShell actually runs, after de-obfuscation (event 4104).
  @{K="HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"; N="EnableScriptBlockLogging"; T="DWord"; V=1},
  # PowerShell module logging for every module (event 4103).
  @{K="HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging"; N="EnableModuleLogging"; T="DWord"; V=1},
  @{K="HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames"; N="*"; T="String"; V="*"},
  # Include the full command line in process creation events (4688).
  @{K="HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit"; N="ProcessCreationIncludeCmdLine_Enabled"; T="DWord"; V=1},
  # Make the advanced (subcategory) audit policy win over the legacy category policy.
  @{K="HKLM\System\CurrentControlSet\Control\Lsa"; N="SCENoApplyLegacyAuditPolicy"; T="DWord"; V=1},
  # Bigger logs so evidence is not overwritten within hours: Security 256 MB, System 64 MB.
  @{K="HKLM\Software\Policies\Microsoft\Windows\EventLog\Security"; N="MaxSize"; T="DWord"; V=262144},
  @{K="HKLM\Software\Policies\Microsoft\Windows\EventLog\System"; N="MaxSize"; T="DWord"; V=65536}
)
foreach ($r in $reg) { Set-GPRegistryValue -Guid $gpo.Id -Key $r.K -ValueName $r.N -Type $r.T -Value $r.V | Out-Null }

# 2. Advanced audit policy, written as audit.csv inside the GPO (what the Group Policy editor does).
$audit = [ordered]@{
  "Credential Validation"                = "Success and Failure"   # 4776 NTLM authentication
  "Kerberos Authentication Service"      = "Success and Failure"   # 4768/4771 TGT requests, failed pre-auth
  "Kerberos Service Ticket Operations"   = "Success and Failure"   # 4769 service tickets (Kerberoasting)
  "Computer Account Management"          = "Success"
  "Other Account Management Events"      = "Success"
  "Security Group Management"            = "Success"               # 4728/4732/4756 group membership changes
  "User Account Management"              = "Success and Failure"   # 4720 created, 4722 enabled, 4724 reset, 4740 lockout
  "Process Creation"                     = "Success"               # 4688
  "Directory Service Access"             = "Success and Failure"   # 4662 (DCSync detection)
  "Directory Service Changes"            = "Success"               # 5136
  "Account Lockout"                      = "Success and Failure"   # 4625 on locked accounts
  "Logon"                                = "Success and Failure"   # 4624/4625
  "Logoff"                               = "Success"               # 4634/4647
  "Special Logon"                        = "Success"               # 4672 admin-equivalent logon
  "Other Logon/Logoff Events"            = "Success and Failure"   # RDP reconnect/disconnect, screen lock
  "Group Membership"                     = "Success"               # 4627
  "File Share"                           = "Success and Failure"   # 5140
  "Other Object Access Events"           = "Success and Failure"   # 4698 scheduled task created
  "Removable Storage"                    = "Success and Failure"
  "Audit Policy Change"                  = "Success"               # 4719 someone changed auditing
  "Authentication Policy Change"         = "Success"
  "MPSSVC Rule-Level Policy Change"      = "Success"               # firewall rule changes
  "Sensitive Privilege Use"              = "Success and Failure"
  "Security State Change"                = "Success"
  "Security System Extension"            = "Success"               # 4697 service installed
  "System Integrity"                     = "Success and Failure"
  "Other System Events"                  = "Success and Failure"
  "Plug and Play Events"                 = "Success"
}
$guid = @{}
auditpol /list /subcategory:* /v | ForEach-Object {
  if ($_ -match '^\s+(.+?)\s+(\{[0-9A-Fa-f-]{36}\})\s*$') { $guid[$matches[1].Trim()] = $matches[2] }
}
$value = @{ "Success" = 1; "Failure" = 2; "Success and Failure" = 3 }
$lines = @("Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value")
foreach ($k in $audit.Keys) {
  if (-not $guid[$k]) { throw "Unknown audit subcategory: $k" }
  $lines += ",System,Audit $k,$($guid[$k]),$($audit[$k]),,$($value[$audit[$k]])"
}
$gpoPath  = "C:\Windows\SYSVOL\domain\Policies\$id"
$auditDir = Join-Path $gpoPath "Machine\Microsoft\Windows NT\Audit"
New-Item -ItemType Directory -Path $auditDir -Force | Out-Null
Set-Content -Path (Join-Path $auditDir "audit.csv") -Value $lines -Encoding ASCII

# Tell clients the GPO now carries audit settings (Advanced Audit client-side extension),
# then bump the computer version so every machine re-applies it.
$gpoDN = "CN=$id,CN=Policies,CN=System,$dn"
$obj = Get-ADObject $gpoDN -Properties gPCMachineExtensionNames, versionNumber
$auditCse = "[{F3CCC681-B74C-4060-9F26-CD84525DCA2A}{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}]"
$parts = [regex]::Matches("$($obj.gPCMachineExtensionNames)$auditCse", '\[[^\]]+\]') | ForEach-Object Value | Sort-Object -Unique
Set-ADObject $gpoDN -Replace @{ gPCMachineExtensionNames = ($parts -join "") }
$ver = [int]$obj.versionNumber + 1
Set-ADObject $gpoDN -Replace @{ versionNumber = $ver }
$ini = Join-Path $gpoPath "GPT.INI"
(Get-Content $ini) -replace '^Version=\d+', "Version=$ver" | Set-Content $ini -Encoding ASCII

# 3. Link at the domain root so it reaches DC01 and WS01.
$linked = (Get-GPInheritance -Target $dn).GpoLinks | Where-Object DisplayName -eq $name
if (-not $linked) { New-GPLink -Guid $gpo.Id -Target $dn -LinkEnabled Yes | Out-Null }

gpupdate /target:computer /force | Out-Null
"GPO: $name $id (version $ver), linked to $dn"
"Audit subcategories configured: $($audit.Count)"
"Effective on DC01:"
auditpol /get /subcategory:"Process Creation","Logon","Kerberos Service Ticket Operations","Directory Service Access"
