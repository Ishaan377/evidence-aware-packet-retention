# Builds the guide with XeLaTeX. The installer is switched off so nothing is ever downloaded.
param([int]$Runs = 2, [string]$Main = 'guide')
Set-Location -LiteralPath $PSScriptRoot
foreach ($i in 1..$Runs) {
    & xelatex --disable-installer -interaction=nonstopmode -halt-on-error "$Main.tex" 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) { break }
}
Select-String -LiteralPath "$Main.log" -Pattern '^!|^l\.\d+|not found|Undefined control' | Select-Object -First 12 | ForEach-Object { $_.Line }
if (Test-Path -LiteralPath "$Main.pdf") { & pdfinfo "$Main.pdf" 2>$null | Select-String 'Pages' }
