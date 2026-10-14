#!/bin/zsh
# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
# Called by the launchd job. Copy to ~/audit/bin/run-ca-snapshot.sh and chmod +x.
set -euo pipefail
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
OUTROOT="$HOME/audit/evidence"
CYCLE="$HOME/src/tenantkeep-posture/deploy/schedules/ca-snapshot-cycle.ps1"   # or the module's deploy/schedules folder
TEAMS_WEBHOOK="${TEAMS_WEBHOOK:-}"
EMAIL_TO="${EMAIL_TO:-}"        # comma-separated; sends through Graph as EMAIL_FROM, so the interactive sign-in must include Mail.Send
EMAIL_FROM="${EMAIL_FROM:-}"

pwsh -NoProfile -NonInteractive -Command "
  Import-Module Tenantkeep.Posture
  # Reuses the token cache from the last interactive sign-in. If it has expired, this throws and the .err log says so.
  \$scopes = @('Policy.Read.All', 'Directory.Read.All', 'Group.Read.All')
  if ('$EMAIL_TO') { \$scopes += 'Mail.Send' }   # delegated: sends only as the signed-in admin's own mailbox
  Connect-MgGraph -Scopes \$scopes -NoWelcome -ContextScope CurrentUser
  \$p = @{ OutRoot = '$OUTROOT'; KeepRuns = 30; FailOnRiskRelevantChange = \$true }
  if ('$TEAMS_WEBHOOK') { \$p.TeamsWebhookUrl = '$TEAMS_WEBHOOK' }
  if ('$EMAIL_TO' -and '$EMAIL_FROM') { \$p.EmailTo = '$EMAIL_TO' -split ','; \$p.EmailFrom = '$EMAIL_FROM' }
  & '$CYCLE' @p
"
