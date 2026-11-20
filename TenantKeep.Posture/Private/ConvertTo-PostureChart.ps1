# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
# Charts for the report, drawn here as inline SVG so the same picture prints, renders in the PDF and opens with
# scripts blocked. Colours are CSS variables (templates/report.css: --c1 to --c5 categorical, validated with the
# dataviz script for both themes; --ok, --warn, --err, --na for status), so dark mode is the stylesheet's job.
# Every chart comes with a legend that names what the colours mean and a table twin, so no value is colour-only,
# and every mark carries a <title> for the hover text. Tones: c1 to c5, ok, warn, err, na.

function Format-PostureChartNumber {
    <#
    .SYNOPSIS
        A count as people read it: 1,284, 12.9K, 1.2M.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([double] $Value)
    $a = [Math]::Abs($Value)
    if ($a -ge 1000000) { return ('{0:0.#}M' -f ($Value / 1000000)) }
    if ($a -ge 10000) { return ('{0:0.#}K' -f ($Value / 1000)) }
    return ('{0:N0}' -f $Value)
}

function ConvertTo-PostureChartTable {
    <#
    .SYNOPSIS
        The table twin of a chart, folded under "Show as a table".
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [string[]] $Header, [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Row)
    $h = { param($t) [System.Net.WebUtility]::HtmlEncode([string]$t) }
    $head = (@($Header | ForEach-Object { '<th>' + (& $h $_) + '</th>' }) -join '')
    $body = (@($Row | ForEach-Object { '<tr>' + (@($_ | ForEach-Object { '<td>' + (& $h $_) + '</td>' }) -join '') + '</tr>' }) -join '')
    return '<details class="chart-table"><summary>Show as a table</summary><table><thead><tr>' + $head + '</tr></thead><tbody>' + $body + '</tbody></table></details>'
}

function ConvertTo-PostureChartLegend {
    <#
    .SYNOPSIS
        A legend: a swatch and a name per item, in the order the chart draws them.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Item)
    $h = { param($t) [System.Net.WebUtility]::HtmlEncode([string]$t) }
    if ($Item.Count -lt 2) { return '' }
    return '<ul class="legend">' + (@($Item | ForEach-Object { '<li><i class="sw t-' + (& $h $_.tone) + '"></i>' + (& $h $_.label) + '</li>' }) -join '') + '</ul>'
}

function ConvertTo-PostureChartCard {
    <#
    .SYNOPSIS
        The frame every chart sits in: a title, the one-line takeaway built from the numbers, the chart, and a View all
        link into the checks behind it.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string] $Title,
        [string] $Takeaway,
        [Parameter(Mandatory)] [string] $Body,
        [string] $ViewAllDomain,
        [string] $ViewAllLabel = 'View the checks',
        [string] $Class = ''
    )
    $h = { param($t) [System.Net.WebUtility]::HtmlEncode([string]$t) }
    $link = $(if ($ViewAllDomain) { '<a class="view-all" href="#checks" data-filter-domain="' + (& $h $ViewAllDomain) + '">' + (& $h $ViewAllLabel) + '</a>' } else { '' })
    return '<figure class="chart-card ' + (& $h $Class) + '"><figcaption><h4>' + (& $h $Title) + '</h4>' + $(if ($Takeaway) { '<p class="takeaway">' + (& $h $Takeaway) + '</p>' }) + '</figcaption>' + $Body + $link + '</figure>'
}

function ConvertTo-PostureDonutChart {
    <#
    .SYNOPSIS
        A donut with the total in the centre, a legend and a table. Segments: label, value, tone. Parts at zero draw
        nothing but stay in the legend and the table.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [object[]] $Segment,
        [string] $CenterLabel = 'total',
        [string] $Name = 'chart'
    )
    $h = { param($t) [System.Net.WebUtility]::HtmlEncode([string]$t) }
    $total = [double](@($Segment | ForEach-Object { [double]$_.value }) | Measure-Object -Sum).Sum
    $r = 52; $c = 2 * [Math]::PI * $r; $gap = 2
    $arcs = [System.Text.StringBuilder]::new()
    $offset = 0.0
    if ($total -gt 0) {
        foreach ($s in $Segment) {
            $v = [double]$s.value; if ($v -le 0) { continue }
            $len = $c * $v / $total
            $draw = [Math]::Max(0.5, $len - $(if (@($Segment | Where-Object { [double]$_.value -gt 0 }).Count -gt 1) { $gap } else { 0 }))
            $pct = [Math]::Round(100 * $v / $total)
            $null = $arcs.Append(('<circle class="t-{0}" cx="64" cy="64" r="{1}" fill="none" stroke-width="14" stroke-dasharray="{2:0.##} {3:0.##}" stroke-dashoffset="{4:0.##}" transform="rotate(-90 64 64)"><title>{5}: {6} ({7}%)</title></circle>' -f (& $h $s.tone), $r, $draw, ($c - $draw), (-$offset), (& $h $s.label), (Format-PostureChartNumber $v), $pct))
            $offset += $len
        }
    }
    else { $null = $arcs.Append(('<circle class="t-na" cx="64" cy="64" r="{0}" fill="none" stroke-width="14"/>' -f $r)) }
    $aria = (& $h ("$Name. " + (@($Segment | ForEach-Object { "$($_.label) $([double]$_.value)" }) -join ', ') + ". Total $total."))
    $svg = '<svg class="donut" viewBox="0 0 128 128" role="img" aria-label="' + $aria + '">' + $arcs.ToString() + '<text x="64" y="62" text-anchor="middle" class="center-value">' + (Format-PostureChartNumber $total) + '</text><text x="64" y="80" text-anchor="middle" class="center-label">' + (& $h $CenterLabel) + '</text></svg>'
    $legend = '<ul class="legend legend-values">' + (@($Segment | ForEach-Object { '<li><i class="sw t-' + (& $h $_.tone) + '"></i>' + (& $h $_.label) + ' <strong>' + (Format-PostureChartNumber ([double]$_.value)) + '</strong></li>' }) -join '') + '</ul>'
    $table = ConvertTo-PostureChartTable -Header @('Part', 'Count', 'Share') -Row @($Segment | ForEach-Object { , @($_.label, [double]$_.value, $(if ($total -gt 0) { '{0:0}%' -f (100 * [double]$_.value / $total) } else { '' })) })
    return '<div class="donut-wrap">' + $svg + $legend + '</div>' + $table
}

function ConvertTo-PostureSankeyChart {
    <#
    .SYNOPSIS
        A flow diagram in two or three stages: how a whole splits, then how each part splits again (users, then
        phishable or not, then method). Column: an array per stage of nodes (id, label, tone). Flow: from, to, value.
        Node height is its value; bands carry the source node's tone, faded. Labels sit beside the nodes with the
        count; the table lists every flow.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [object[]] $Column,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Flow,
        [string] $Name = 'flow',
        [int] $Width = 920,
        [int] $Height = 260
    )
    $h = { param($t) [System.Net.WebUtility]::HtmlEncode([string]$t) }
    $flows = @($Flow | Where-Object { [double]$_.value -gt 0 })
    $node = @{}
    foreach ($col in $Column) { foreach ($n in $col) { $node[[string]$n.id] = @{ id = [string]$n.id; label = [string]$n.label; tone = [string]$n.tone; inV = 0.0; outV = 0.0; y = 0.0; h = 0.0; x = 0.0; inY = 0.0; outY = 0.0 } } }
    foreach ($f in $flows) { $node[[string]$f.from].outV += [double]$f.value; $node[[string]$f.to].inV += [double]$f.value }
    $valueOf = { param($n) [Math]::Max($n.inV, $n.outV) }
    $pad = 12; $nodeW = 10; $top = 8; $usable = $Height - 2 * $top
    $scale = [double]::MaxValue
    foreach ($col in $Column) {
        $live = @($col | Where-Object { (& $valueOf $node[[string]$_.id]) -gt 0 })
        $sum = [double](@($live | ForEach-Object { & $valueOf $node[[string]$_.id] }) | Measure-Object -Sum).Sum
        if ($sum -gt 0) { $scale = [Math]::Min($scale, ($usable - $pad * [Math]::Max(0, $live.Count - 1)) / $sum) }
    }
    if ($scale -eq [double]::MaxValue) { $scale = 0 }
    $labelW = 190
    $stages = $Column.Count
    $span = $Width - 2 * $labelW - $nodeW
    for ($i = 0; $i -lt $stages; $i++) {
        $x = $labelW + $(if ($stages -gt 1) { $span * $i / ($stages - 1) } else { 0 })
        $y = [double]$top
        foreach ($n in $Column[$i]) {
            $nd = $node[[string]$n.id]; $v = & $valueOf $nd
            if ($v -le 0) { continue }
            $nd.x = $x; $nd.y = $y; $nd.h = [Math]::Max(2, $v * $scale); $nd.inY = $y; $nd.outY = $y
            $y += $nd.h + $pad
        }
    }
    $sb = [System.Text.StringBuilder]::new()
    foreach ($f in $flows) {
        $a = $node[[string]$f.from]; $b = $node[[string]$f.to]; $t = [double]$f.value * $scale
        $x0 = $a.x + $nodeW; $x1 = $b.x; $xm = ($x0 + $x1) / 2; $y0 = $a.outY; $y1 = $b.inY
        $null = $sb.Append(('<path class="band t-{0}" d="M{1:0.#},{2:0.#} C{3:0.#},{2:0.#} {3:0.#},{4:0.#} {5:0.#},{4:0.#} L{5:0.#},{6:0.#} C{3:0.#},{6:0.#} {3:0.#},{7:0.#} {1:0.#},{7:0.#} Z"><title>{8} to {9}: {10}</title></path>' -f (& $h $a.tone), $x0, $y0, $xm, $y1, $x1, ($y1 + $t), ($y0 + $t), (& $h $a.label), (& $h $b.label), (Format-PostureChartNumber ([double]$f.value))))
        $a.outY += $t; $b.inY += $t
    }
    for ($i = 0; $i -lt $stages; $i++) {
        foreach ($n in $Column[$i]) {
            $nd = $node[[string]$n.id]; $v = & $valueOf $nd
            if ($v -le 0) { continue }
            $null = $sb.Append(('<rect class="node t-{0}" x="{1:0.#}" y="{2:0.#}" width="{3}" height="{4:0.#}" rx="2"><title>{5}: {6}</title></rect>' -f (& $h $nd.tone), $nd.x, $nd.y, $nodeW, $nd.h, (& $h $nd.label), (Format-PostureChartNumber $v)))
            $last = ($i -eq $stages - 1)
            $tx = $(if ($last) { $nd.x + $nodeW + 8 } else { $nd.x - 8 })
            $anchor = $(if ($last) { 'start' } else { 'end' })
            $null = $sb.Append(('<text x="{0:0.#}" y="{1:0.#}" text-anchor="{2}" class="node-label">{3} <tspan class="node-value">{4}</tspan></text>' -f $tx, ($nd.y + $nd.h / 2 + 4), $anchor, (& $h $nd.label), (Format-PostureChartNumber $v)))
        }
    }
    $aria = (& $h ("$Name. " + (@($flows | ForEach-Object { "$($node[[string]$_.from].label) to $($node[[string]$_.to].label) $([double]$_.value)" }) -join '; ') + '.'))
    $svg = '<svg class="sankey" viewBox="0 0 ' + $Width + ' ' + $Height + '" role="img" aria-label="' + $aria + '">' + $sb.ToString() + '</svg>'
    $table = ConvertTo-PostureChartTable -Header @('From', 'To', 'Count') -Row @($flows | ForEach-Object { , @($node[[string]$_.from].label, $node[[string]$_.to].label, [double]$_.value) })
    return '<div class="sankey-wrap">' + $svg + '</div>' + $table
}

function ConvertTo-PostureRingChart {
    <#
    .SYNOPSIS
        Defence in depth as layered rings, outermost layer first, with the layers listed beside them. Layer: label,
        passed, total, status (pass, partial, fail, na). Each ring's arc is the share of its checks that pass; the
        list repeats the status in words and n of m, so the rings are never the only way to read it.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [object[]] $Layer,
        [string] $Name = 'layers'
    )
    $h = { param($t) [System.Net.WebUtility]::HtmlEncode([string]$t) }
    $toneOf = @{ pass = 'ok'; partial = 'warn'; fail = 'err'; na = 'na' }
    $wordOf = @{ pass = 'Holds'; partial = 'Partly'; fail = 'Missing'; na = 'Not applicable' }
    $iconOf = @{ pass = [string][char]0x2713; partial = '!'; fail = [string][char]0x2715; na = [string][char]0x2013 }
    $sb = [System.Text.StringBuilder]::new()
    $outer = 76; $step = 13; $i = 0
    foreach ($l in $Layer) {
        $r = $outer - $i * $step; $c = 2 * [Math]::PI * $r
        $share = $(if ([int]$l.total -gt 0) { [double]$l.passed / [double]$l.total } else { 0 })
        $null = $sb.Append(('<circle class="track" cx="84" cy="84" r="{0}" fill="none" stroke-width="9"/>' -f $r))
        if ($share -gt 0) { $null = $sb.Append(('<circle class="t-{0}" cx="84" cy="84" r="{1}" fill="none" stroke-width="9" stroke-linecap="round" stroke-dasharray="{2:0.##} {3:0.##}" transform="rotate(-90 84 84)"><title>{4}: {5} of {6}</title></circle>' -f $toneOf[[string]$l.status], $r, ($c * $share), $c, (& $h $l.label), $l.passed, $l.total)) }
        $i++
    }
    $aria = (& $h ("$Name. " + (@($Layer | ForEach-Object { "$($_.label): $($wordOf[[string]$_.status]), $($_.passed) of $($_.total)" }) -join '; ') + '.'))
    $svg = '<svg class="rings" viewBox="0 0 168 168" role="img" aria-label="' + $aria + '">' + $sb.ToString() + '</svg>'
    $list = '<ol class="layer-list">' + (@($Layer | ForEach-Object { '<li><span class="status-dot t-' + $toneOf[[string]$_.status] + '" aria-hidden="true">' + $iconOf[[string]$_.status] + '</span><span class="layer-name">' + (& $h $_.label) + '</span><span class="layer-state">' + (& $h $wordOf[[string]$_.status]) + $(if ([int]$_.total -gt 0) { ', ' + $_.passed + ' of ' + $_.total }) + '</span></li>' }) -join '') + '</ol>'
    return '<div class="rings-wrap">' + $svg + $list + '</div>'
}

function ConvertTo-PostureBarChart {
    <#
    .SYNOPSIS
        A segmented bar: one whole split into parts, each block labelled with its count where it fits, a legend of
        names, and the table. Thin (no text) for rows of a list, tall for a bar standing alone.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [object[]] $Segment,
        [switch] $Thin,
        [switch] $NoTable,
        [string] $Name = 'bar'
    )
    $h = { param($t) [System.Net.WebUtility]::HtmlEncode([string]$t) }
    $total = [double](@($Segment | ForEach-Object { [double]$_.value }) | Measure-Object -Sum).Sum
    $blocks = @($Segment | Where-Object { [double]$_.value -gt 0 } | ForEach-Object {
            $pct = $(if ($total -gt 0) { 100 * [double]$_.value / $total } else { 0 })
            $text = $(if (-not $Thin -and $pct -ge 8) { Format-PostureChartNumber ([double]$_.value) } else { '' })
            '<span class="seg t-' + (& $h $_.tone) + '" style="flex-grow:' + ('{0:0.###}' -f $pct) + '" title="' + (& $h "$($_.label): $([double]$_.value)") + '">' + $text + '</span>'
        }) -join ''
    $aria = (& $h ("$Name. " + (@($Segment | ForEach-Object { "$($_.label) $([double]$_.value)" }) -join ', ') + '.'))
    $bar = '<div class="segbar' + $(if ($Thin) { ' thin' }) + '" role="img" aria-label="' + $aria + '">' + $blocks + '</div>'
    if ($Thin) { return $bar }
    $legend = ConvertTo-PostureChartLegend -Item $Segment
    $table = $(if ($NoTable) { '' } else { ConvertTo-PostureChartTable -Header @('Part', 'Count') -Row @($Segment | ForEach-Object { , @($_.label, [double]$_.value) }) })
    return $bar + $legend + $table
}
