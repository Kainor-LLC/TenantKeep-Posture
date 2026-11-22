# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Read-PosturePriceFile {
    <#
    .SYNOPSIS
        Reads a licence price file that the person running the report supplies, and returns a price for one user for
        each licence the advisor knows, with what the file says about itself. For choosing between combinations that
        already cover the goals; nothing it returns is ever written into a report.
    .DESCRIPTION
        The module ships no prices and fetches none. A Microsoft partner's price sheet is confidential, so the file
        stays wherever its owner keeps it and is read from there, a row at a time.

        The file is a CSV with these columns (others are ignored):
          ProductName     Microsoft's name for the licence
          PartNumber      optional: the SKU part number (SPE_E5), for a licence whose name in the sheet differs
          Term            P1M, P1Y or P3Y
          BillingCycle    Monthly, Annual or Triennial
          Erp             the price a customer pays for one user, as a number
          EffectiveDate   yyyy-MM-dd; a row dated later than today is not used yet
          Market, Currency  optional; rows of another market or currency than the file's own record are skipped
        A partner's own price (a ListPrice column) may be in the file; it is never read.

        Beside the file, <name>.meta.json may say when the sheet was last checked and what it assumes:
          { "checkedUtc": "2026-11-22T09:17:00Z", "market": "US", "currency": "USD",
            "assume": { "term": "P1Y", "billingCycle": "Monthly" } }
        Without it the term is P1Y billed Monthly and the age of the prices is unknown.

        Only rows of the assumed term and billing cycle are used, so every price compared is in the same unit. A
        licence is matched by PartNumber, else by name: the catalogue name, that name without a trailing "(was ...)",
        or the old name inside it. When two rows give one licence different prices on the same date the licence gets
        no price at all.
    .OUTPUTS
        price: SKU part number to [decimal]. basis: what the file is and assumes, with no price in it.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [int] $StaleAfterDays = 35,
        [datetime] $Now = [datetime]::UtcNow
    )

    $ErrorActionPreference = 'Stop'
    $full = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { throw "Price file not found: $full" }

    # What the file says about itself.
    $basis = [ordered]@{ file = (Split-Path -Leaf $full); checkedUtc = $null; ageDays = $null; stale = $true; staleAfterDays = $StaleAfterDays; term = 'P1Y'; billingCycle = 'Monthly'; market = $null; currency = $null; rowsRead = 0; rowsUsed = 0; licencesPriced = 0; ambiguous = @() }
    $metaPath = Join-Path (Split-Path -Parent $full) (([System.IO.Path]::GetFileNameWithoutExtension($full)) + '.meta.json')
    if (Test-Path -LiteralPath $metaPath -PathType Leaf) {
        $meta = $null
        try { $meta = Get-Content -Raw -LiteralPath $metaPath | ConvertFrom-Json -AsHashtable -Depth 6 } catch { Write-Warning "The price file's record $(Split-Path -Leaf $metaPath) could not be read; its age and assumptions are unknown." }
        if ($meta) {
            if ($meta.Contains('assume') -and $meta['assume']) {
                if ($meta['assume'].Contains('term') -and $meta['assume']['term']) { $basis['term'] = [string]$meta['assume']['term'] }
                if ($meta['assume'].Contains('billingCycle') -and $meta['assume']['billingCycle']) { $basis['billingCycle'] = [string]$meta['assume']['billingCycle'] }
            }
            foreach ($k in 'market', 'currency') { if ($meta.Contains($k) -and $meta[$k]) { $basis[$k] = [string]$meta[$k] } }
            $checked = [datetimeoffset]::MinValue
            # The JSON reader hands back a date for date text; text that it left alone is parsed here.
            $stamp = $(if ($meta.Contains('checkedUtc')) { $meta['checkedUtc'] } else { $null })
            $known = $false
            if ($stamp -is [datetime]) { $checked = [datetimeoffset]::new($stamp.ToUniversalTime()); $known = $true }
            elseif ($stamp) { $known = [datetimeoffset]::TryParse([string]$stamp, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$checked) }
            if ($known) {
                $basis['checkedUtc'] = $checked.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ', [cultureinfo]::InvariantCulture)
                $basis['ageDays'] = [int][math]::Floor(($Now.ToUniversalTime() - $checked.UtcDateTime).TotalDays)
                $basis['stale'] = ($basis['ageDays'] -gt $StaleAfterDays)
            }
        }
    }

    # The licences the advisor knows, by part number and by every name a sheet might use for them.
    $data = Get-PostureLicensingData
    $byPart = @{}; $byName = @{}
    foreach ($b in $data.bundles) {
        $sku = [string]$b.sku
        $byPart[$sku.ToLowerInvariant()] = $sku
        $name = ([string]$b.name).Trim()
        $names = [System.Collections.Generic.List[string]]::new()
        $names.Add($name)
        if ($name -match '^(?<plain>.+?)\s*\((?:was|formerly)\s+(?<old>[^)]+)\)\s*$') { $names.Add($Matches['plain'].Trim()); $names.Add($Matches['old'].Trim()) }
        foreach ($n in $names) { $key = $n.ToLowerInvariant(); if (-not $byName.ContainsKey($key)) { $byName[$key] = $sku } }
    }

    $today = $Now.ToUniversalTime().ToString('yyyy-MM-dd', [cultureinfo]::InvariantCulture)
    $best = @{}          # sku -> @{ date; price; clash }
    $columns = $null
    Import-Csv -LiteralPath $full | ForEach-Object {
        $row = $_
        if ($null -eq $columns) {
            $columns = @($row.PSObject.Properties | ForEach-Object { $_.Name })
            $missing = @('ProductName', 'Term', 'BillingCycle', 'Erp', 'EffectiveDate' | Where-Object { $_ -notin $columns })
            if ($missing.Count) { throw "The price file $(Split-Path -Leaf $full) has no column named $($missing -join ', '). It has: $($columns -join ', ')." }
        }
        $basis['rowsRead']++
        if ([string]$row.Term -ne $basis['term'] -or [string]$row.BillingCycle -ne $basis['billingCycle']) { return }
        if ($basis['market'] -and 'Market' -in $columns -and [string]$row.Market -and [string]$row.Market -ne $basis['market']) { return }
        if ($basis['currency'] -and 'Currency' -in $columns -and [string]$row.Currency -and [string]$row.Currency -ne $basis['currency']) { return }
        $sku = $null
        if ('PartNumber' -in $columns -and [string]$row.PartNumber) { $part = ([string]$row.PartNumber).Trim().ToLowerInvariant(); if ($byPart.ContainsKey($part)) { $sku = $byPart[$part] } }
        if (-not $sku) { $key = ([string]$row.ProductName).Trim().ToLowerInvariant(); if ($byName.ContainsKey($key)) { $sku = $byName[$key] } }
        if (-not $sku) { return }
        $amount = [decimal]0
        if (-not [decimal]::TryParse(([string]$row.Erp).Trim(), [System.Globalization.NumberStyles]::Number, [cultureinfo]::InvariantCulture, [ref]$amount) -or $amount -lt 0) { return }
        $date = ([string]$row.EffectiveDate).Trim()
        if ($date -and $date -gt $today) { return }
        $basis['rowsUsed']++
        if (-not $best.ContainsKey($sku) -or $date -gt $best[$sku]['date']) { $best[$sku] = @{ date = $date; price = $amount; clash = $false } }
        elseif ($date -eq $best[$sku]['date'] -and $amount -ne $best[$sku]['price']) { $best[$sku]['clash'] = $true }
    }

    $price = @{}
    $ambiguous = [System.Collections.Generic.List[string]]::new()
    foreach ($sku in $best.get_Keys()) {
        if ($best[$sku]['clash']) { $ambiguous.Add([string]@($data.bundles | Where-Object { [string]$_.sku -eq $sku })[0].name) }
        else { $price[$sku] = [decimal]$best[$sku]['price'] }
    }
    $basis['licencesPriced'] = $price.get_Count()
    $basis['ambiguous'] = @($ambiguous | Sort-Object)
    return [ordered]@{ price = $price; basis = $basis }
}
