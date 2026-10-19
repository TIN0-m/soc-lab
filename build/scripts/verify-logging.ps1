# verify-logging.ps1 (runs on DC01 and WS01)
# Proves the logging baseline is actually in effect on this machine, not just configured on the DC.
gpupdate /target:computer /force | Out-Null
Start-Sleep 5
# Generate a little activity so there is something fresh to check.
Start-Process -FilePath "cmd.exe" -ArgumentList "/c whoami /all > nul" -Wait -WindowStyle Hidden
powershell.exe -NoProfile -Command "Get-Date | Out-Null" | Out-Null
Start-Sleep 5

$applied = (gpresult /scope computer /r) -match "SOC - Security Logging Baseline"
"Host: $env:COMPUTERNAME"
"Logging GPO applied: $([bool]$applied)"
"Script block logging: $((Get-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue).EnableScriptBlockLogging)"
"Command line in 4688: $((Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled)"
"Security log max size (MB): $([int]((Get-WinEvent -ListLog Security).MaximumSizeInBytes / 1MB))"
auditpol /get /subcategory:"Process Creation","Logon","Credential Validation","Other Object Access Events"

$p = Get-WinEvent -FilterHashtable @{LogName = "Security"; Id = 4688} -MaxEvents 1 -ErrorAction SilentlyContinue
if ($p) { "Latest 4688 at $($p.TimeCreated): $($p.Properties[5].Value) | cmdline: $($p.Properties[8].Value)" } else { "No 4688 yet" }
$sb = Get-WinEvent -FilterHashtable @{LogName = "Microsoft-Windows-PowerShell/Operational"; Id = 4104} -MaxEvents 1 -ErrorAction SilentlyContinue
"Latest 4104 (script block): $(if ($sb) { $sb.TimeCreated } else { 'none yet' })"
$sy = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 200 -ErrorAction SilentlyContinue
"Sysmon events in last batch: $($sy.Count), event IDs seen: $((($sy | Group-Object Id | Sort-Object Name).Name) -join ', ')"
