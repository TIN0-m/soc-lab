# dc-users.ps1 (runs on DC01)
# Builds a small fictional company, Lowveld Logistics, in Active Directory:
# OUs per department, security groups, 19 staff, one separate admin account,
# two service accounts and a disabled leaver. A few weaknesses are planted on purpose
# so later exercises have something real to detect. Each one is listed in 03-logging-users.md.
param(
  [string]$SprayPassword,   # shared weak seasonal password on two staff accounts (password-spray exercise)
  [string]$SvcSqlPassword,  # weak password on a service account with an SPN (Kerberoasting exercise)
  [string]$AsrepPassword,   # weak password on an account without Kerberos pre-authentication (AS-REP roasting exercise)
  [string]$StaffPassword    # known password for one normal user, used to simulate everyday logons
)
$ErrorActionPreference = "Stop"
Import-Module ActiveDirectory
Add-Type -AssemblyName System.Web

$domain   = Get-ADDomain
$domainDN = $domain.DistinguishedName
$dns      = $domain.DNSRoot
$company  = "Lowveld Logistics"

function Ensure-OU([string]$Name, [string]$Path) {
  $dn = "OU=$Name,$Path"
  if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$dn'")) {
    New-ADOrganizationalUnit -Name $Name -Path $Path -ProtectedFromAccidentalDeletion $true
  }
  return $dn
}
function New-RandomPassword { [System.Web.Security.Membership]::GeneratePassword(24, 4) }
function Ensure-Group([string]$Name, [string]$Description) {
  if (-not (Get-ADGroup -Filter "Name -eq '$Name'")) {
    New-ADGroup -Name $Name -GroupScope Global -GroupCategory Security -Path $groupsOU -Description $Description
  }
}

# OU structure
$corp     = Ensure-OU "Corp" $domainDN
$usersOU  = Ensure-OU "Users" $corp
$depts    = "Executive", "Finance", "HR", "IT", "Sales", "Operations"
$deptOU   = @{}
foreach ($d in $depts) { $deptOU[$d] = Ensure-OU $d $usersOU }
$groupsOU = Ensure-OU "Groups" $corp
$wsOU     = Ensure-OU "Workstations" $corp
$svcOU    = Ensure-OU "Service Accounts" $corp
$admOU    = Ensure-OU "Admin Accounts" $corp
$leftOU   = Ensure-OU "Disabled Users" $corp

# Groups
foreach ($d in $depts) { Ensure-Group "GG_$d" "All $d staff" }
Ensure-Group "GG_AllStaff" "Every employee"
Ensure-Group "GG_Helpdesk" "Service desk technicians"

# Staff. Pw: random | spray | asrep | staff
$staff = @(
  @{F="Grace";    L="Moloi";     D="Executive";  T="Chief Executive Officer"; Pw="random"},
  @{F="David";    L="Naidoo";    D="Executive";  T="Chief Financial Officer"; Pw="random"},
  @{F="Lerato";   L="Mokoena";   D="Finance";    T="Finance Manager";         Pw="staff"},
  @{F="Pieter";   L="vanWyk";    D="Finance";    T="Accountant";              Pw="random"},
  @{F="Ayanda";   L="Dlamini";   D="Finance";    T="Accounts Clerk";          Pw="random"},
  @{F="Nomsa";    L="Khumalo";   D="HR";         T="HR Manager";              Pw="random"},
  @{F="Fatima";   L="Patel";     D="HR";         T="HR Officer";              Pw="random"},
  @{F="Thabo";    L="Nkosi";     D="IT";         T="IT Manager";              Pw="random"},
  @{F="Kagiso";   L="Molefe";    D="IT";         T="Service Desk Technician"; Pw="random"},
  @{F="Sipho";    L="Ndlovu";    D="IT";         T="Systems Administrator";   Pw="random"},
  @{F="Johan";    L="Botha";     D="Sales";      T="Sales Manager";           Pw="random"},
  @{F="Zanele";   L="Mthembu";   D="Sales";      T="Sales Representative";    Pw="spray"},
  @{F="Naledi";   L="Sithole";   D="Sales";      T="Sales Representative";    Pw="random"},
  @{F="Ruan";     L="Pretorius"; D="Sales";      T="Sales Representative";    Pw="random"},
  @{F="Bongani";  L="Zulu";      D="Operations"; T="Operations Manager";      Pw="random"},
  @{F="Chantelle";L="Adams";     D="Operations"; T="Logistics Coordinator";   Pw="random"},
  @{F="Tshepo";   L="Maluleke";  D="Operations"; T="Dispatcher";              Pw="spray"},
  @{F="Anele";    L="Ngcobo";    D="Operations"; T="Warehouse Supervisor";    Pw="random"},
  @{F="Megan";    L="Smith";     D="Operations"; T="Fleet Coordinator";       Pw="asrep"}
)

$created = 0
foreach ($u in $staff) {
  $sam = ("{0}.{1}" -f $u.F, $u.L).ToLower()
  $pw = switch ($u.Pw) { "spray" { $SprayPassword } "asrep" { $AsrepPassword } "staff" { $StaffPassword } default { New-RandomPassword } }
  if (-not (Get-ADUser -Filter "SamAccountName -eq '$sam'")) {
    $display = if ($u.L -eq "vanWyk") { "$($u.F) van Wyk" } else { "$($u.F) $($u.L)" }
    New-ADUser -Name $display -DisplayName $display -GivenName $u.F -Surname $u.L `
      -SamAccountName $sam -UserPrincipalName "$sam@$dns" `
      -Department $u.D -Title $u.T -Company $company -Path $deptOU[$u.D] `
      -AccountPassword (ConvertTo-SecureString $pw -AsPlainText -Force) -Enabled $true
    $created++
  }
  Add-ADGroupMember "GG_$($u.D)" -Members $sam
  Add-ADGroupMember "GG_AllStaff" -Members $sam
}
Add-ADGroupMember "GG_Helpdesk" -Members "kagiso.molefe"

# Planted weakness: AS-REP roastable account (Kerberos pre-authentication disabled).
Set-ADAccountControl -Identity "megan.smith" -DoesNotRequirePreAuth $true

# Separate admin account for the IT manager: day-to-day and privileged identities kept apart.
if (-not (Get-ADUser -Filter "SamAccountName -eq 'a-thabo.nkosi'")) {
  New-ADUser -Name "Thabo Nkosi (Admin)" -DisplayName "Thabo Nkosi (Admin)" -SamAccountName "a-thabo.nkosi" `
    -UserPrincipalName "a-thabo.nkosi@$dns" -Department "IT" -Title "IT Manager (admin account)" -Company $company `
    -Path $admOU -AccountPassword (ConvertTo-SecureString (New-RandomPassword) -AsPlainText -Force) -Enabled $true
  $created++
}
Add-ADGroupMember "Domain Admins" -Members "a-thabo.nkosi"

# Service accounts.
# Planted weakness: svc_sql has a Service Principal Name and a weak password (Kerberoastable).
if (-not (Get-ADUser -Filter "SamAccountName -eq 'svc_sql'")) {
  New-ADUser -Name "svc_sql" -SamAccountName "svc_sql" -UserPrincipalName "svc_sql@$dns" `
    -Description "SQL Server service account" -Path $svcOU `
    -AccountPassword (ConvertTo-SecureString $SvcSqlPassword -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true
  $created++
}
Set-ADUser "svc_sql" -ServicePrincipalNames @{Add = "MSSQLSvc/ws01.$($dns):1433"}
# Planted weakness: a backup account in Backup Operators, which can read any file on a DC.
if (-not (Get-ADUser -Filter "SamAccountName -eq 'svc_backup'")) {
  New-ADUser -Name "svc_backup" -SamAccountName "svc_backup" -UserPrincipalName "svc_backup@$dns" `
    -Description "Nightly backup job" -Path $svcOU `
    -AccountPassword (ConvertTo-SecureString (New-RandomPassword) -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true
  $created++
}
Add-ADGroupMember "Backup Operators" -Members "svc_backup"

# Leaver: disabled, kept for audit history.
if (-not (Get-ADUser -Filter "SamAccountName -eq 'brian.jacobs'")) {
  New-ADUser -Name "Brian Jacobs" -DisplayName "Brian Jacobs" -GivenName "Brian" -Surname "Jacobs" `
    -SamAccountName "brian.jacobs" -UserPrincipalName "brian.jacobs@$dns" -Department "Sales" `
    -Title "Sales Representative" -Company $company -Description "Left the company 31 August 2026" -Path $leftOU `
    -AccountPassword (ConvertTo-SecureString (New-RandomPassword) -AsPlainText -Force) -Enabled $false
  $created++
}

# Move WS01 out of the default Computers container so policy can target it.
$ws = Get-ADComputer "WS01"
if ($ws.DistinguishedName -notlike "*$wsOU") { Move-ADObject $ws.DistinguishedName -TargetPath $wsOU }

"Accounts created this run: $created"
"Staff per department:"
foreach ($d in $depts) { "  {0,-11} {1}" -f $d, (Get-ADGroupMember "GG_$d").Count }
"Domain Admins: " + ((Get-ADGroupMember "Domain Admins").SamAccountName -join ", ")
"Kerberoastable (user accounts with an SPN): " + ((Get-ADUser -Filter 'ServicePrincipalName -like "*" -and SamAccountName -ne "krbtgt"').SamAccountName -join ", ")
"AS-REP roastable (no pre-auth): " + ((Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true').SamAccountName -join ", ")
"Disabled: " + ((Get-ADUser -Filter 'Enabled -eq $false' -SearchBase $leftOU).SamAccountName -join ", ")
"WS01 is in: " + (Get-ADComputer "WS01").DistinguishedName
