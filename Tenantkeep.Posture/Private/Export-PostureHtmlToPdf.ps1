# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Find-PostureHeadlessBrowser {
    <#
    .SYNOPSIS
        Locates Microsoft Edge or Google Chrome (or Chromium) for headless PDF printing. Returns $null when none is found.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $ErrorActionPreference = 'Stop'
    $candidates = if ($IsMacOS) {
        @(
            '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge'
            '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
            '/Applications/Chromium.app/Contents/MacOS/Chromium'
            "$HOME/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"
            "$HOME/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
        )
    }
    elseif ($IsWindows) {
        @(
            "$env:ProgramFiles(x86)\Microsoft\Edge\Application\msedge.exe"
            "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe"
            "$env:ProgramFiles\Google\Chrome\Application\chrome.exe"
            "$env:ProgramFiles(x86)\Google\Chrome\Application\chrome.exe"
            "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe"
        )
    }
    else {
        @()
    }
    foreach ($c in $candidates) { if ($c -and (Test-Path -LiteralPath $c -PathType Leaf)) { return $c } }
    foreach ($name in 'microsoft-edge', 'microsoft-edge-stable', 'google-chrome', 'google-chrome-stable', 'chromium', 'chromium-browser', 'msedge', 'chrome') {
        $cmd = Get-Command -Name $name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($cmd) { return $cmd.Source }
    }
    return $null
}

function Export-PostureHtmlToPdf {
    <#
    .SYNOPSIS
        Prints a self-contained HTML file to PDF through a headless Edge or Chrome (spec 6: no wkhtmltopdf).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string] $HtmlPath,
        [Parameter(Mandatory)] [string] $PdfPath,
        [string] $Browser,
        [int] $TimeoutSeconds = 120
    )

    $ErrorActionPreference = 'Stop'
    if (-not $Browser) { $Browser = Find-PostureHeadlessBrowser }
    if (-not $Browser) {
        throw "No headless browser found. Install Microsoft Edge or Google Chrome, or open $HtmlPath in a browser and print to PDF."
    }
    $html = (Resolve-Path -LiteralPath $HtmlPath).Path
    $fileUri = [uri]::new($html).AbsoluteUri

    # A throwaway profile: the user's own profile is locked while their browser is open, and nothing from this run
    # should land in it. Crash reporting is off so the run writes nowhere else either.
    $scratch = Join-Path ([System.IO.Path]::GetTempPath()) "tenantkeep-pdf-$([guid]::NewGuid().ToString('n'))"
    New-Item -ItemType Directory -Path $scratch -Force | Out-Null
    $stderrPath = Join-Path $scratch 'browser-stderr.txt'
    $arguments = @(
        '--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check', '--disable-extensions'
        '--disable-crash-reporter', '--disable-breakpad', "--user-data-dir=$scratch"
        '--no-pdf-header-footer', "--print-to-pdf=$PdfPath", $fileUri
    )
    Write-Verbose "$Browser $($arguments -join ' ')"
    try {
        $proc = Start-Process -FilePath $Browser -ArgumentList $arguments -Wait -PassThru -NoNewWindow -RedirectStandardError $stderrPath
        if ($proc.ExitCode -ne 0) {
            $tail = if (Test-Path -LiteralPath $stderrPath) { @(Get-Content -LiteralPath $stderrPath -Tail 5) -join ' | ' } else { '' }
            throw "Headless browser exited with code $($proc.ExitCode) while printing $html. $tail"
        }
        if (-not (Test-Path -LiteralPath $PdfPath)) { throw "Headless browser finished but $PdfPath was not written." }
        return (Resolve-Path -LiteralPath $PdfPath).Path
    }
    finally {
        Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
    }
}
