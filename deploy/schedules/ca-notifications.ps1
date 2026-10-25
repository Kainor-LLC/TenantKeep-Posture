#Requires -Version 7.4
# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
<#
.SYNOPSIS
    Notification functions for the scheduling layer: Teams card and email. Dot-sourced by ca-snapshot-cycle.ps1.
.DESCRIPTION
    These are the only outbound sends in the product and they live outside the module on purpose: the module is
    read-only against the tenant, and sending mail through Graph needs Mail.Send, a write permission the customer
    opts into. Everything here goes to the customer's own services (their Teams, their mailbox, their SMTP relay).
#>

function Get-CaChangeNotificationContent {
    <#
    .SYNOPSIS
        Subject and HTML body for a change notification, from a Compare-PostureCaSnapshot result.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [object] $Comparison,
        [Parameter(Mandatory)] [string] $BeforeName,
        [Parameter(Mandatory)] [string] $AfterName,
        [string] $TenantLabel
    )

    $ErrorActionPreference = 'Stop'
    $h = { param($t) [System.Net.WebUtility]::HtmlEncode([string]$t) }
    $count = [int]$Comparison.RiskRelevantCount
    $label = if ($TenantLabel) { " ($TenantLabel)" } else { '' }
    $subject = if ($count -gt 0) { "Conditional Access: $count risk-relevant change(s)$label" } else { "Conditional Access: no risk-relevant changes$label" }

    $rows = foreach ($r in @($Comparison.Diff.risk)) {
        "<tr><td style=`"padding:4px 8px;color:#cf222e;font-weight:600`">$(& $h $r.rule)</td><td style=`"padding:4px 8px`">$(& $h $r.subject)</td><td style=`"padding:4px 8px`">$(& $h $r.detail)</td></tr>"
    }
    $c = $Comparison.Counts
    $body = @"
<html><body style="font-family:Helvetica,Arial,sans-serif;font-size:14px;color:#1b1f23">
<h2 style="color:#1F3A5F">$(& $h $subject)</h2>
<p>Between <strong>$(& $h $BeforeName)</strong> and <strong>$(& $h $AfterName)</strong>. Policies added $($c.added), removed $($c.removed), renamed $($c.renamed), state changed $($c.stateChanged), modified $($c.modified); locations $($c.locations), strengths $($c.strengths), groups drifted $($c.scope).</p>
$(if ($count -gt 0) { "<table style=`"border-collapse:collapse;border:1px solid #d9dee3`"><thead><tr><th style=`"text-align:left;padding:4px 8px`">Rule</th><th style=`"text-align:left;padding:4px 8px`">Subject</th><th style=`"text-align:left;padding:4px 8px`">Detail</th></tr></thead><tbody>$($rows -join '')</tbody></table>" } else { '<p>No risk-relevant changes.</p>' })
<p>The full change report is attached (ca-changes.html) and in the snapshot folder.</p>
<p style="color:#5c6670;font-size:12px">Sent by the TenantKeep Posture schedule in your environment. Nothing was sent anywhere else.</p>
</body></html>
"@
    return @{ Subject = $subject; Body = $body }
}

function Send-CaTeamsCard {
    <#
    .SYNOPSIS
        Posts the risk-relevant changes to a Teams Workflows webhook as an Adaptive Card.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] [string] $WebhookUrl,
        [Parameter(Mandatory)] [object] $Comparison,
        [Parameter(Mandatory)] [string] $BeforeName,
        [Parameter(Mandatory)] [string] $AfterName
    )

    $ErrorActionPreference = 'Stop'
    $facts = @($Comparison.Diff.risk | Select-Object -First 15 | ForEach-Object { @{ title = $_.rule; value = "$($_.subject): $($_.detail)" } })
    $card = @{
        type        = 'message'
        attachments = @(@{
                contentType = 'application/vnd.microsoft.card.adaptive'
                content     = @{
                    '$schema' = 'http://adaptivecards.io/schemas/adaptive-card.json'
                    type      = 'AdaptiveCard'
                    version   = '1.4'
                    body      = @(
                        @{ type = 'TextBlock'; size = 'Large'; weight = 'Bolder'; text = "Conditional Access: $($Comparison.RiskRelevantCount) risk-relevant change(s)" }
                        @{ type = 'TextBlock'; wrap = $true; text = "Between $BeforeName and $AfterName. Report: ca-changes.html in the snapshot folder." }
                        @{ type = 'FactSet'; facts = $facts }
                    )
                }
            })
    }
    if ($PSCmdlet.ShouldProcess($WebhookUrl, 'Post Teams card')) {
        # (verify) Workflows webhook accepts this shape; the older Office 365 connector webhooks are retired.
        $null = Invoke-RestMethod -Method Post -Uri $WebhookUrl -ContentType 'application/json' -Body ($card | ConvertTo-Json -Depth 12)
    }
}

function Send-CaChangeEmail {
    <#
    .SYNOPSIS
        Emails the change notification with ca-changes.html attached, through Graph sendMail or an SMTP relay.
    .DESCRIPTION
        Graph: POST /users/{From}/sendMail as the signed-in identity. Needs Mail.Send, which the customer grants
        knowingly; scope it to the sender mailbox with an Exchange application access policy. saveToSentItems is
        false so the sender mailbox does not fill up.
        Smtp: System.Net.Mail over STARTTLS with the given credential. No Graph permission involved.
        -PassThru returns the built message without sending (used by tests and for a dry run).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [string[]] $To,
        [Parameter(Mandatory)] [string] $From,
        [Parameter(Mandatory)] [string] $Subject,
        [Parameter(Mandatory)] [string] $HtmlBody,
        [string[]] $AttachmentPath = @(),
        [ValidateSet('Graph', 'Smtp')] [string] $Method = 'Graph',
        [string] $SmtpServer,
        [int] $SmtpPort = 587,
        [pscredential] $SmtpCredential,
        [bool] $SmtpUseTls = $true,
        [switch] $PassThru
    )

    $ErrorActionPreference = 'Stop'
    $attachments = foreach ($p in $AttachmentPath) {
        if (-not (Test-Path -LiteralPath $p)) { throw "Attachment not found: $p" }
        @{ name = (Split-Path $p -Leaf); contentType = $(if ($p -like '*.html') { 'text/html' } else { 'application/octet-stream' }); bytes = [System.IO.File]::ReadAllBytes($p) }
    }
    $message = @{ To = @($To); From = $From; Subject = $Subject; HtmlBody = $HtmlBody; Attachments = @($attachments); Method = $Method }
    if ($PassThru) { return $message }

    switch ($Method) {
        'Graph' {
            $ctx = Get-MgContext
            if (-not $ctx) { throw 'No Graph session; connect before sending mail.' }
            if (@($ctx.Scopes) -notcontains 'Mail.Send' -and @($ctx.Scopes) -notcontains 'Mail.Send.Shared') {
                throw "Email through Graph needs the Mail.Send permission on the identity (current scopes: $(@($ctx.Scopes) -join ', ')). Grant it with admin consent, restrict it to the sender mailbox with an Exchange application access policy, or use -EmailMethod Smtp."
            }
            $payload = @{
                message         = @{
                    subject      = $Subject
                    body         = @{ contentType = 'HTML'; content = $HtmlBody }
                    toRecipients = @($To | ForEach-Object { @{ emailAddress = @{ address = $_ } } })
                    attachments  = @($attachments | ForEach-Object { @{ '@odata.type' = '#microsoft.graph.fileAttachment'; name = $_.name; contentType = $_.contentType; contentBytes = [Convert]::ToBase64String($_.bytes) } })
                }
                saveToSentItems = $false
            }
            if ($PSCmdlet.ShouldProcess("$From -> $($To -join ', ')", 'Send mail through Graph')) {
                # The one Graph write in the product, outside the module, opt-in by granting Mail.Send.
                $null = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/users/$([uri]::EscapeDataString($From))/sendMail" -Body ($payload | ConvertTo-Json -Depth 10 -Compress) -ContentType 'application/json'
            }
        }
        'Smtp' {
            if (-not $SmtpServer) { throw '-SmtpServer is required for -EmailMethod Smtp.' }
            $mail = [System.Net.Mail.MailMessage]::new()
            $mail.From = [System.Net.Mail.MailAddress]::new($From)
            foreach ($t in $To) { $mail.To.Add($t) }
            $mail.Subject = $Subject
            $mail.Body = $HtmlBody
            $mail.IsBodyHtml = $true
            foreach ($a in $attachments) {
                $stream = [System.IO.MemoryStream]::new($a.bytes)
                $mail.Attachments.Add([System.Net.Mail.Attachment]::new($stream, $a.name, $a.contentType))
            }
            $client = [System.Net.Mail.SmtpClient]::new($SmtpServer, $SmtpPort)
            $client.EnableSsl = $SmtpUseTls
            if ($SmtpCredential) { $client.Credentials = $SmtpCredential.GetNetworkCredential() }
            try {
                if ($PSCmdlet.ShouldProcess("$SmtpServer`:$SmtpPort", "Send mail from $From to $($To -join ', ')")) { $client.Send($mail) }
            }
            finally { $mail.Dispose(); $client.Dispose() }
        }
    }
}
