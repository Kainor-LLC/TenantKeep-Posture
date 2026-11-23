# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function ConvertTo-PosturePlanHtml {
    <#
    .SYNOPSIS
        The remediation plan as a flow chart, and the same plan in words under it.
    .DESCRIPTION
        Takes Get-PosturePlan's result. The chart is one inline SVG: a column per stage, a box per project, an
        arrow from a project to each one in the next column that waits on it (solid: needs it first; dashed: better
        after it). A box links to the project's entry in the list below, which names what it waits on and why, and
        the checks to fix. Colours come from the report's stylesheet, so the chart follows light and dark and
        prints. Returns an empty string when there is nothing to plan.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([System.Collections.IDictionary] $Plan)

    $ErrorActionPreference = 'Stop'
    if (-not $Plan -or @($Plan.columns).Count -eq 0) { return '' }
    $h = { param([object] $Text) [System.Net.WebUtility]::HtmlEncode([string]$Text) }
    $sizeLabel = @{ S = 'Small'; M = 'Medium'; L = 'Large' }
    $plural = { param([int] $n, [string] $one, [string] $many) if ($n -eq 1) { "$n $one" } else { "$n $many" } }
    # Two lines at most, broken between words.
    $wrap = {
        param([string] $text, [int] $max)
        $lines = [System.Collections.Generic.List[string]]::new(); $line = ''
        foreach ($word in ($text -split ' ')) {
            if ($line -and ($line.Length + 1 + $word.Length) -gt $max) { $lines.Add($line); $line = $word } else { $line = $(if ($line) { "$line $word" } else { $word }) }
        }
        if ($line) { $lines.Add($line) }
        if ($lines.Count -gt 2) { $lines = [System.Collections.Generic.List[string]]@($lines[0], ($lines[1].TrimEnd('.', ',') + [string][char]0x2026)) }
        , $lines.ToArray()
    }
    $subLine = {
        param($p)
        if ($p.state -eq 'done') { return 'In place' + $(if ($p.notJudged -gt 0) { ', ' + (& $plural $p.notJudged 'check' 'checks') + ' not judged' }) }
        $lead = $(if ($p.improvementsOnly) { 'Improvement' } elseif ($p.risk) { "$($p.risk) risk" } else { '' })
        $work = $(if ($p.improvementsOnly) { "$($p.toFix) to do" } else { "$($p.toFix) to fix" })
        (@($lead, $work, $sizeLabel[[string]$p.size]) | Where-Object { $_ }) -join ([string][char]0x00B7).PadLeft(2).PadRight(3)
    }

    # Geometry. A narrower column for what is already in place; every later column the same width. The first column
    # of work is stacked from the top. Every other column puts a project level with the projects it is joined to, so
    # an arrow runs across and not up the page: the wanted height is the average of its neighbours', and a box that
    # would overlap the one above is moved down.
    $top = 58; $boxH = 84; $pitch = 98; $gap = 58
    $columns = @($Plan.columns)
    $place = @{}
    $heads = [System.Text.StringBuilder]::new()
    $x = 4
    $columnX = @{}
    foreach ($col in $columns) {
        $w = $(if ($col.key -eq 'inPlace') { 224 } else { 256 })
        $n = @($col.projects).Count
        $hint = switch ($col.key) {
            'inPlace' { 'What the plan builds on' }
            'start' { if ($n -eq 1) { 'Nothing has to come first' } else { "These $n can run side by side" } }
            default { 'Each waits on a project to its left' }
        }
        $null = $heads.Append('<text class="plan-h" x="' + $x + '" y="22">' + (& $h $col.title) + '</text><text class="plan-hs" x="' + $x + '" y="41">' + (& $h $hint) + '</text>')
        $columnX[$col.key] = @{ x = $x; w = $w }
        $x += $w + $gap
    }
    $width = $x - $gap + 4
    $joined = { param([string] $id, [string] $end, [string] $other) @($Plan.edges | Where-Object { [string]$_[$end] -eq $id } | ForEach-Object { $place[[string]$_[$other]] } | Where-Object { $_ } | ForEach-Object { $_.y }) }
    $stack = {
        param($col, [string] $end, [string] $other)
        $at = $columnX[$col.key]
        $wanted = @(for ($i = 0; $i -lt @($col.projects).Count; $i++) {
                $ys = @(& $joined ([string]$col.projects[$i].id) $end $other)
                [pscustomobject]@{ project = $col.projects[$i]; order = $i; y = $(if ($ys.Count -gt 0) { [double]($ys | Measure-Object -Average).Average } else { [double]($top + $i * $pitch) }) }
            })
        $next = $top
        foreach ($entry in @($wanted | Sort-Object y, order)) {
            $y = [Math]::Max($next, [int][Math]::Round($entry.y))
            $place[[string]$entry.project.id] = @{ x = $at.x; y = $y; w = $at.w; col = $col.key }
            $next = $y + $pitch
        }
    }
    foreach ($col in $columns) { if ($col.key -ne 'inPlace') { & $stack $col 'to' 'from' } }
    foreach ($col in $columns) { if ($col.key -eq 'inPlace') { & $stack $col 'from' 'to' } }
    $height = $top + $pitch
    foreach ($spot in $place.get_Values()) { $height = [Math]::Max($height, $spot.y + $boxH + 14) }

    $edgeSvg = @($Plan.edges | ForEach-Object {
            $a = $place[[string]$_.from]; $b = $place[[string]$_.to]
            if (-not $a -or -not $b) { return }
            $x1 = $a.x + $a.w; $y1 = $a.y + $boxH / 2; $x2 = $b.x - 7; $y2 = $b.y + $boxH / 2; $mid = ($x1 + $x2) / 2
            '<path class="plan-edge ' + (& $h $_.kind) + '" d="M' + $x1 + ',' + $y1 + ' C' + $mid + ',' + $y1 + ' ' + $mid + ',' + $y2 + ' ' + $x2 + ',' + $y2 + '" marker-end="url(#plan-arrow)"/>'
        }) -join ''

    $nodeSvg = @(foreach ($col in $columns) {
            foreach ($p in $col.projects) {
                $at = $place[[string]$p.id]
                $done = $p.state -eq 'done'
                $stage = $(if ($done) { 'done' } elseif ($col.key -eq 'start') { 'start' } else { 'wait' })
                $riskClass = $(if ($p.improvementsOnly) { ' r-improve' } elseif ($p.risk) { ' r-' + ([string]$p.risk).ToLowerInvariant() } else { '' })
                $class = 'plan-node ' + $stage + $riskClass + $(if (@($p.checkFirst).Count -gt 0) { ' flag' })
                $title = (& $wrap ($(if ($done) { [string][char]0x2713 + ' ' } else { '' }) + [string]$p.name) $(if ($col.key -eq 'inPlace') { 26 } else { 30 }))
                $text = ''
                for ($i = 0; $i -lt $title.Count; $i++) { $text += '<text class="plan-t" x="' + ($at.x + 16) + '" y="' + ($at.y + 26 + $i * 17) + '">' + (& $h $title[$i]) + '</text>' }
                $text += '<text class="plan-s" x="' + ($at.x + 16) + '" y="' + ($at.y + $boxH - 14) + '">' + (& $h (& $subLine $p)) + '</text>'
                # An arrow joins neighbouring columns only. What a project also waits on further left is counted on the
                # box and named in the list below.
                if (-not $done) {
                    $drawn = @($Plan.edges | Where-Object { [string]$_.to -eq [string]$p.id }).Count
                    $further = @($p.waitsOn | Where-Object { $_.state -in 'needed', 'done' }).Count - $drawn
                    if ($further -gt 0) { $text += '<text class="plan-s plan-more" text-anchor="end" x="' + ($at.x + $at.w - 12) + '" y="' + ($at.y + $boxH - 14) + '">+' + $further + ' earlier</text>' }
                }
                $bar = $(if ($done) { '' } else { '<rect class="plan-bar" x="' + $at.x + '" y="' + $at.y + '" width="5" height="' + $boxH + '" rx="2"/>' })
                $box = '<rect class="plan-box" x="' + $at.x + '" y="' + $at.y + '" width="' + $at.w + '" height="' + $boxH + '" rx="10"/>' + $bar + $text + '<title>' + (& $h $p.what) + '</title>'
                if ($done) { '<g class="' + $class + '">' + $box + '</g>' } else { '<a class="' + $class + '" href="#plan-' + (& $h $p.id) + '">' + $box + '</a>' }
            }
        }) -join ''

    $label = 'Projects in the order they can start. An arrow runs from a project to each one in the next column that waits on it.'
    $open = '<svg class="plan-chart" viewBox="0 0 ' + $width + ' ' + $height + '" width="' + $width + '" height="' + $height + '" style="min-width:' + $width + 'px" role="img" aria-label="' + (& $h $label) + '">'
    $marker = '<defs><marker id="plan-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z"/></marker></defs>'
    $svg = $open + $marker + $heads.ToString() + $edgeSvg + $nodeSvg + '</svg>'
    $legend = '<p class="plan-legend"><span><i></i>Needs it first</span><span><i class="dashed"></i>Better after it</span><span class="tech">Select a project for its checks. The colour on its left edge is its highest risk. "+1 earlier" means it also waits on a project further left, named in the list below.</span></p>'
    $toggle = '<button type="button" class="btn plan-risk" data-plan-risk aria-pressed="false">Highest Risk Only</button>'

    # The same plan in words: for print, for a screen reader, and for the detail the boxes have no room for.
    $checkLinks = { param($p) (@($p.checks | ForEach-Object { '<a href="#checks" data-check="' + (& $h $_.id) + '" title="' + (& $h $_.title) + '"><code>' + (& $h $_.id) + '</code></a>' }) -join ' ') }
    $entry = {
        param($p)
        $stateWord = @{ done = 'in place'; needed = 'in this plan'; unknown = 'could not be judged in this run, so check it first' }
        $waits = @($p.waitsOn | ForEach-Object { '<li>' + $(if ($_.kind -eq 'needs') { 'Needs ' } else { 'Better after ' }) + '<strong>' + (& $h $_.name) + '</strong> (' + (& $h $stateWord[[string]$_.state]) + '). ' + (& $h $_.why) + '</li>' }) -join ''
        '<li id="plan-' + (& $h $p.id) + '" class="plan-item' + $(if ($p.improvementsOnly) { '' } elseif ($p.risk) { ' r-' + ([string]$p.risk).ToLowerInvariant() }) + '"><p><strong>' + (& $h $p.name) + '</strong> ' +
        $(if ($p.improvementsOnly) { '<span class="chip improve">Improvement</span>' } elseif ($p.risk) { '<span class="sev ' + (& $h $p.risk) + '">' + (& $h $p.risk) + '</span>' }) +
        ' <span class="tech">' + (& $h ($(if ($p.improvementsOnly) { "$($p.toFix) to do" } else { "$($p.toFix) to fix" }) + ', ' + ([string]$sizeLabel[[string]$p.size]).ToLowerInvariant())) + '</span></p><p>' + (& $h $p.what) + '</p>' +
        $(if ($waits) { '<ul class="plan-waits">' + $waits + '</ul>' }) + '<p class="plan-checks">' + (& $checkLinks $p) + '</p></li>'
    }
    $words = [System.Text.StringBuilder]::new()
    foreach ($col in $columns) {
        if ($col.key -eq 'inPlace') { continue }
        $n = @($col.projects).Count
        $lead = switch ($col.key) {
            'start' { if ($n -eq 1) { 'Nothing has to come first.' } else { "None of these $n waits on another, so they can run side by side." } }
            default { 'Each waits on a project from an earlier stage.' }
        }
        $null = $words.Append('<h4>' + (& $h $col.title) + '</h4><p class="hint">' + (& $h $lead) + '</p><ol class="plan-list">' + (@($col.projects | ForEach-Object { & $entry $_ }) -join '') + '</ol>')
    }
    if (@($Plan.whenever).Count -gt 0) {
        $null = $words.Append('<h4>Also Ready to Start</h4><p class="hint">These wait on nothing and nothing waits on them, so they fit in wherever there is time. Highest risk first.</p><ol class="plan-list">' + (@($Plan.whenever | ForEach-Object { & $entry $_ }) -join '') + '</ol>')
    }
    $counts = $Plan.counts
    $summary = (& $plural $counts.needed 'project has' 'projects have') + ' something to fix and ' + $counts.done + ' ' + $(if ($counts.done -eq 1) { 'has' } else { 'have' }) + ' nothing to fix.'
    if (@($Plan.notJudged).Count -gt 0) { $summary += ' Not judged in this run: ' + (@($Plan.notJudged | ForEach-Object { $_.name }) -join ', ') + '.' }

    '<div class="plan"><div class="plan-tools">' + $toggle + '</div><div class="plan-scroll">' + $svg + '</div>' + $legend +
    '<p class="tech">' + (& $h $summary) + ' The order is a recommendation: what each project waits on, and why, is listed below.</p>' +
    '<div class="plan-words">' + $words.ToString() + '</div></div>'
}
