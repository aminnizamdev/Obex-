Param(
    [string]$OutFile = "Superscript_obex_alphav1.txt"
)

$ErrorActionPreference = 'Stop'
$root = Get-Location

if (Test-Path -LiteralPath $OutFile) {
    Remove-Item -LiteralPath $OutFile -Force
}

Get-ChildItem -Recurse -File |
    Where-Object {
        $_.FullName -notlike (Join-Path $root.Path 'target\*') -and
        $_.FullName -ne (Join-Path $root.Path $OutFile)
    } |
    ForEach-Object {
        $rel = $_.FullName.Substring($root.Path.Length + 1)
        $pathFmt = $rel -replace '\\','>'
        $content = Get-Content -LiteralPath $_.FullName -Raw -ErrorAction SilentlyContinue
        if ($null -eq $content) { $content = '' }
        $entry = $pathFmt + ' ' + $content + [System.Environment]::NewLine + [System.Environment]::NewLine
        [System.IO.File]::AppendAllText($OutFile, $entry)
    }


