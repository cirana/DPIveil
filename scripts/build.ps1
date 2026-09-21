$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

python -m pip install -r requirements.txt
python -m pip install -r requirements-build.txt
python -m unittest discover -s tests
python -m PyInstaller --clean --noconfirm DPIveil.spec

$WinDivertDir = python -c "import pathlib, pydivert.windivert_dll as w; print(pathlib.Path(w.__file__).resolve().parent)"
if (-not $WinDivertDir) {
    throw "Could not locate PyDivert WinDivert binaries."
}

$Required = @("WinDivert64.dll", "WinDivert64.sys")
foreach ($Name in $Required) {
    $Source = Join-Path $WinDivertDir $Name
    if (-not (Test-Path $Source)) {
        throw "Missing required PyDivert file: $Source"
    }
    Copy-Item $Source (Join-Path "$Root\dist" $Name) -Force
}

$Exe = Join-Path "$Root\dist" "DPIveil.exe"
if (-not (Test-Path $Exe)) {
    throw "DPIveil.exe was not produced."
}

# The distributable runtime is intentionally only these three files.
$Allowed = @("DPIveil.exe", "WinDivert64.dll", "WinDivert64.sys")
Get-ChildItem "$Root\dist" -File |
    Where-Object { $_.Name -notin $Allowed } |
    Remove-Item -Force

Write-Host ""
Write-Host "Build complete:"
Get-ChildItem "$Root\dist" -File | ForEach-Object {
    $Hash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
    Write-Host ("  {0}  SHA256={1}" -f $_.Name, $Hash)
}
