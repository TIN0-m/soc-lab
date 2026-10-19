#!/usr/bin/env bash
# 03b-logging-users.sh
# 1. Fictional company users, groups and planted weaknesses in Active Directory (DC01)
# 2. Domain-wide logging GPO: advanced audit policy, PowerShell logging, command lines, log sizes (DC01)
# 3. Sysmon on DC01 and WS01
# 4. Proof on both machines that the logging is live
# Safe to re-run.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC1091
source "$HERE/lib.sh"
CREDS_FILE="${CREDS_FILE:?set CREDS_FILE to the private credentials env file}"

# Lab-only passwords for the planted weaknesses. Generated once into the private env file.
if ! grep -q '^SPRAY_PASSWORD=' "$CREDS_FILE"; then
python -I - "$CREDS_FILE" <<'EOF'
import secrets, sys
season = secrets.choice(["Summer", "Winter", "Spring", "Autumn"])
weak = {
  # In every common password-spray list: season + year + symbol.
  "SPRAY_PASSWORD": f"{season}2026!",
  # Crackable from a standard wordlist with simple rules.
  "SVC_SQL_PASSWORD": secrets.choice(["Password123!", "Welcome123!", "Qwerty123!"]),
  "ASREP_PASSWORD": secrets.choice(["Football1!", "Sunshine1!", "Princess1!"]),
}
alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!#%+?"
while True:
  staff = "".join(secrets.choice(alphabet) for _ in range(20))
  if staff[0].isalnum() and any(c.isdigit() for c in staff) and any(c in "!#%+?" for c in staff) and any(c.isupper() for c in staff) and any(c.islower() for c in staff):
    break
with open(sys.argv[1], "a", newline="\n") as f:
  f.write("# Planted weak passwords for exercises (lab only)\n")
  for k, v in weak.items(): f.write(f"{k}='{v}'\n")
  f.write("# Everyday user lerato.mokoena (Finance Manager)\n")
  f.write(f"STAFF_PASSWORD='{staff}'\n")
print("exercise passwords added to the private env file")
EOF
fi
# shellcheck disable=SC1090
source "$CREDS_FILE"

run_ps DC01 users "$HERE/scripts/dc-users.ps1" \
  "SprayPassword=$SPRAY_PASSWORD" "SvcSqlPassword=$SVC_SQL_PASSWORD" \
  "AsrepPassword=$ASREP_PASSWORD" "StaffPassword=$STAFF_PASSWORD"

run_ps DC01 logging-gpo "$HERE/scripts/dc-gpo-logging.ps1"

run_ps DC01 sysmon "$HERE/scripts/sysmon.ps1"
run_ps WS01 sysmon "$HERE/scripts/sysmon.ps1"

run_ps DC01 verify-logging "$HERE/scripts/verify-logging.ps1"
run_ps WS01 verify-logging "$HERE/scripts/verify-logging.ps1"

echo "Logging and users complete."
