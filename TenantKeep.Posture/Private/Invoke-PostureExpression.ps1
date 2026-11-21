# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Invoke-PostureExpression {
    <#
    .SYNOPSIS
        Evaluates a check's pass expression against facts and thresholds. A small parser of its own; never Invoke-Expression.
    .DESCRIPTION
        Grammar: or-expr := and-expr ('||' and-expr)*; and-expr := not-expr ('&&' not-expr)*; not-expr := '!' not-expr | cmp;
        cmp := value (('==' | '!=' | '>=' | '<=' | '>' | '<') value)?; value := number | 'string' | true | false | null |
        identifier ('.' identifier)* | '(' or-expr ')'. Identifiers resolve through the context: facts.x, thresholds.y.
        Comparisons are numeric when both sides are numbers, string (ordinal, case-insensitive) otherwise.

        Missing data never reads as pass or fail. A reference to a fact or threshold that is not there throws, and so
        does a fact that is there with no value (null): the engine turns both into "not evaluated: data missing",
        naming the fact. Only the literal null may be compared with it (facts.x == null).

        '&&' and '||' decide from the left: when the left side settles the answer the right side is not read, so
        "facts.staleDevices == 0 || facts.cleanupRuleEnabled" passes on a tenant with no stale devices even when the
        cleanup rule could not be read, and is not evaluated when there are stale devices and the rule is unknown.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)] [string] $Expression,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Context
    )

    $ErrorActionPreference = 'Stop'

    # Tokenize
    $tokens = [System.Collections.Generic.List[object]]::new()
    $pattern = '\s*(?:(?<num>-?\d+(?:\.\d+)?)|(?<str>''(?:[^'']|'''')*'')|(?<op>\|\||&&|==|!=|>=|<=|>|<|!|\(|\))|(?<id>[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*))'
    $pos = 0
    while ($pos -lt $Expression.Length) {
        $m = [regex]::Match($Expression.Substring($pos), "^$pattern")
        if (-not $m.Success -or $m.Length -eq 0) {
            if ($Expression.Substring($pos).Trim().Length -eq 0) { break }
            throw "Cannot parse expression at position $pos`: '$($Expression.Substring($pos))'"
        }
        if ($m.Groups['num'].Success) { $tokens.Add(@{ type = 'num'; value = [double]$m.Groups['num'].Value }) }
        elseif ($m.Groups['str'].Success) { $v = $m.Groups['str'].Value; $tokens.Add(@{ type = 'str'; value = $v.Substring(1, $v.Length - 2).Replace("''", "'") }) }
        elseif ($m.Groups['op'].Success) { $tokens.Add(@{ type = 'op'; value = $m.Groups['op'].Value }) }
        else {
            $id = $m.Groups['id'].Value
            switch ($id) {
                'true' { $tokens.Add(@{ type = 'bool'; value = $true }) }
                'false' { $tokens.Add(@{ type = 'bool'; value = $false }) }
                'null' { $tokens.Add(@{ type = 'null'; value = $null }) }
                default { $tokens.Add(@{ type = 'id'; value = $id }) }
            }
        }
        $pos += $m.Length
    }

    # skip counts the sides of && and || that are parsed but not read, because the other side already decided.
    $state = @{ i = 0; skip = 0 }
    $peek = { if ($state.i -lt $tokens.Count) { $tokens[$state.i] } else { $null } }
    $next = { if ($state.i -ge $tokens.Count) { return $null }; $t = $tokens[$state.i]; $state.i++; $t }
    $isOp = { param($t, [string] $v) $t -and $t.type -eq 'op' -and $t.value -eq $v }

    # A reference that resolves to null is carried as a marker with its path, so whatever reads it can say which
    # fact has no value. A tuple, because no fact is ever one.
    $noValue = { param($x) $x -is [System.Tuple[string, string]] -and $x.Item1 -eq 'PostureNoValue' }
    $read = { param($x) if (& $noValue $x) { throw "$($x.Item2) has no value in the evidence." }; $x }

    $resolve = {
        param([string] $Path)
        if ($state.skip -gt 0) { return $false }
        $current = $Context
        foreach ($seg in $Path.Split('.')) {
            if ($current -is [System.Collections.IDictionary]) {
                if (-not $current.Contains($seg)) { throw "Unknown reference '$Path' in expression." }
                $current = $current[$seg]
            }
            elseif ($null -ne $current -and ($current.PSObject.Properties.Name -contains $seg)) { $current = $current.$seg }
            else { throw "Unknown reference '$Path' in expression." }
        }
        if ($null -eq $current) { return [System.Tuple[string, string]]::new('PostureNoValue', $Path) }
        return $current
    }

    $parseOr = $null; $parseAnd = $null; $parseNot = $null; $parseCmp = $null; $parseValue = $null
    $parseValue = {
        $t = & $next
        if ($null -eq $t) { throw 'Unexpected end of expression.' }
        switch ($t.type) {
            'num' { return $t.value }
            'str' { return $t.value }
            'bool' { return $t.value }
            'null' { return $null }
            'id' { return (& $resolve $t.value) }
            'op' {
                if ($t.value -eq '(') {
                    $v = & $parseOr
                    $close = & $next
                    if (-not (& $isOp $close ')')) { throw "Expected ')' in expression." }
                    return $v
                }
                throw "Unexpected '$($t.value)' in expression."
            }
        }
    }
    $compare = {
        param($l, [string] $op, $r)
        # The literal null against a fact with no value is the one comparison that may see it.
        if ($null -eq $l -or $null -eq $r) {
            $bothNull = ($null -eq $l -or (& $noValue $l)) -and ($null -eq $r -or (& $noValue $r))
            if ($op -eq '==') { return $bothNull }
            if ($op -eq '!=') { return -not $bothNull }
            return $false
        }
        $l = & $read $l; $r = & $read $r
        $ln = 0.0; $rn = 0.0
        $leftNumeric = $l -is [double] -or $l -is [int] -or $l -is [long] -or $l -is [decimal] -or [double]::TryParse([string]$l, [ref]$ln)
        $rightNumeric = $r -is [double] -or $r -is [int] -or $r -is [long] -or $r -is [decimal] -or [double]::TryParse([string]$r, [ref]$rn)
        $numeric = $leftNumeric -and $rightNumeric
        if ($numeric -and $l -isnot [bool] -and $r -isnot [bool]) {
            $a = [double]$l; $b = [double]$r
            switch ($op) { '==' { $a -eq $b } '!=' { $a -ne $b } '>=' { $a -ge $b } '<=' { $a -le $b } '>' { $a -gt $b } '<' { $a -lt $b } }
        }
        else {
            $a = [string]$l; $b = [string]$r
            switch ($op) {
                '==' { [string]::Equals($a, $b, 'OrdinalIgnoreCase') } '!=' { -not [string]::Equals($a, $b, 'OrdinalIgnoreCase') }
                '>=' { [string]::Compare($a, $b, $true) -ge 0 } '<=' { [string]::Compare($a, $b, $true) -le 0 }
                '>' { [string]::Compare($a, $b, $true) -gt 0 } '<' { [string]::Compare($a, $b, $true) -lt 0 }
            }
        }
    }
    $parseCmp = {
        $left = & $parseValue
        $t = & $peek
        if ($t -and $t.type -eq 'op' -and $t.value -in @('==', '!=', '>=', '<=', '>', '<')) {
            $null = & $next
            $right = & $parseValue
            if ($state.skip -gt 0) { return $false }
            return [bool](& $compare $left $t.value $right)
        }
        return $left
    }
    $parseNot = {
        $t = & $peek
        if (& $isOp $t '!') {
            $null = & $next
            $inner = & $parseNot
            if ($state.skip -gt 0) { return $false }
            return -not [bool](& $read $inner)
        }
        return & $parseCmp
    }
    # A side that is not read is still parsed, so the expression's shape is checked and the tokens are consumed.
    $skipSide = { param([scriptblock] $Side) $state.skip++; try { $null = & $Side } finally { $state.skip-- } }
    $parseAnd = {
        $v = & $parseNot
        while (& $isOp (& $peek) '&&') {
            $null = & $next
            if ($state.skip -gt 0) { $null = & $parseNot; continue }
            if (-not [bool](& $read $v)) { & $skipSide $parseNot; $v = $false }
            else { $v = [bool](& $read (& $parseNot)) }
        }
        return $v
    }
    $parseOr = {
        $v = & $parseAnd
        while (& $isOp (& $peek) '||') {
            $null = & $next
            if ($state.skip -gt 0) { $null = & $parseAnd; continue }
            if ([bool](& $read $v)) { & $skipSide $parseAnd; $v = $true }
            else { $v = [bool](& $read (& $parseAnd)) }
        }
        return $v
    }

    $result = & $parseOr
    if ($state.i -lt $tokens.Count) { throw "Unexpected token '$($tokens[$state.i].value)' after end of expression." }
    return [bool](& $read $result)
}
