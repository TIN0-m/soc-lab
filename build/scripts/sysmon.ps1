# sysmon.ps1 (runs on DC01 and WS01)
# Installs Microsoft Sysmon with the sysmon-modular configuration by Olaf Hartong.
# Sysmon adds detail Windows does not log by default: process hashes and parent chains (1),
# network connections per process (3), process access such as LSASS reads (10),
# registry persistence (12-14), DNS queries per process (22) and more.
$ErrorActionPreference = "Stop"
$dir = "C:\ProgramData\Sysmon"
New-Item -ItemType Directory -Path $dir -Force | Out-Null

$zip = Join-Path $dir "Sysmon.zip"
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile $zip -UseBasicParsing
Expand-Archive -Path $zip -DestinationPath $dir -Force
$exe = Join-Path $dir "Sysmon64.exe"
$sig = Get-AuthenticodeSignature $exe
if ($sig.Status -ne "Valid" -or $sig.SignerCertificate.Subject -notmatch "Microsoft Corporation") {
  throw "Sysmon signature check failed: $($sig.Status) / $($sig.SignerCertificate.Subject)"
}

# Config: the "balanced" profile for Sysmon 15.21, pinned to one release instead of "latest"
# (the project's own advice for controlled rollouts), and checked against the release's SHA256SUMS.
$sysmonVersion = (Get-Item $exe).VersionInfo.FileVersion
if (-not $sysmonVersion.StartsWith("15.")) { throw "Expected Sysmon 15.x, got $sysmonVersion" }
$release = "https://github.com/olafhartong/sysmon-modular/releases/download/configs-a45dedb13a43"
$cfgName = "sysmonconfig-15.21.xml"
$cfg  = Join-Path $dir $cfgName
$sums = Join-Path $dir "SHA256SUMS"
Invoke-WebRequest -Uri "$release/$cfgName" -OutFile $cfg -UseBasicParsing
Invoke-WebRequest -Uri "$release/SHA256SUMS" -OutFile $sums -UseBasicParsing
$expected = (Get-Content $sums | Where-Object { $_ -match "\s\*?$([regex]::Escape($cfgName))$" }) -split '\s+' | Select-Object -First 1
$hash = (Get-FileHash $cfg -Algorithm SHA256).Hash
if (-not $expected -or $hash -ne $expected.ToUpper()) { throw "Config checksum mismatch: got $hash, expected $expected" }
[xml]$xml = Get-Content $cfg
if (-not $xml.Sysmon) { throw "Downloaded file is not a Sysmon configuration" }

# Sysmon prints its banner to stderr. In Windows PowerShell 5.1 that becomes a terminating
# error under "Stop", so relax it for the native call and judge success by the exit code.
$ErrorActionPreference = "Continue"
if (Get-Service Sysmon64 -ErrorAction SilentlyContinue) {
  $log = & $exe -c $cfg 2>&1; $action = "configuration updated"
} else {
  $log = & $exe -accepteula -i $cfg 2>&1; $action = "installed"
}
$code = $LASTEXITCODE
$ErrorActionPreference = "Stop"
if ($code -ne 0) { throw "Sysmon exited with code $code`n$($log -join "`n")" }
Start-Sleep 5
"Sysmon $action on $env:COMPUTERNAME"
"Binary version: $((Get-Item $exe).VersionInfo.FileVersion), signed by: $($sig.SignerCertificate.Subject.Split(',')[0])"
"Config: $cfgName from release configs-a45dedb13a43, schema $($xml.Sysmon.schemaversion), SHA256 $hash (matches SHA256SUMS)"
"Service: $((Get-Service Sysmon64).Status)"
