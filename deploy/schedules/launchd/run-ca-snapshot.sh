#!/bin/zsh
# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
# Called by the launchd job. Copy to ~/audit/bin/run-ca-snapshot.sh and chmod +x.
set -euo pipefail
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
OUTROOT="$HOME/audit/evidence"
CYCLE="$HOME/src/tenantkeep-posture/deploy/schedules/ca-snapshot-cycle.ps1"   # or the module's deploy/schedules folder
TEAMS_WEBHOOK="${TEAMS_WEBHOOK:-}"

pwsh -NoProfile -NonInteractive -Command "
  Import-Module Tenantkeep.Posture
  # Reuses the token cache from the last interactive sign-in. If it has expired, this throws and the .err log says so.
  Connect-MgGraph -Scopes Policy.Read.All, Directory.Read.All, Group.Read.All -NoWelcome -ContextScope CurrentUser
  \$p = @{ OutRoot = '$OUTROOT'; KeepRuns = 30; FailOnRiskRelevantChange = \$true }
  if ('$TEAMS_WEBHOOK') { \$p.TeamsWebhookUrl = '$TEAMS_WEBHOOK' }
  & '$CYCLE' @p
"
