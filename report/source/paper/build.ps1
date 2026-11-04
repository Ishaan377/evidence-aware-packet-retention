# Builds the IEEE paper with pdfLaTeX. The installer is switched off so nothing is ever downloaded.
param([int]$Runs = 3)
Set-Location -LiteralPath $PSScriptRoot
foreach ($i in 1..$Runs) {
    & pdflatex --disable-installer -interaction=nonstopmode -halt-on-error paper.tex 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) { break }
}
Select-String -LiteralPath 'paper.log' -Pattern '^!|^l\.\d+|not found|Undefined control|undefined on input|Overfull .hbox \((\d{2,}|[3-9])\.' | Select-Object -First 14 | ForEach-Object { $_.Line }
if (Test-Path -LiteralPath 'paper.pdf') { & pdfinfo paper.pdf 2>$null | Select-String 'Pages' }
