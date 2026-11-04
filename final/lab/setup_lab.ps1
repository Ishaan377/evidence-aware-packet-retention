# Create the isolated Suricata lab used by the forensic test. Needs WSL 2 and internet access.
#   powershell -ExecutionPolicy Bypass -File final\lab\setup_lab.ps1
# Remove it at any time with: wsl --unregister ebr-lab
param([string]$Name = 'ebr-lab')
$ErrorActionPreference = 'Stop'
$home_folder = Join-Path $env:LOCALAPPDATA $Name
$image = 'https://cloud-images.ubuntu.com/wsl/releases/24.04/current/ubuntu-noble-wsl-amd64-24.04lts.rootfs.tar.gz'

if ((wsl.exe -l -q) -replace "`0", '' -contains $Name) {
    Write-Output "$Name already exists; leaving it in place."
} else {
    New-Item -ItemType Directory -Force $home_folder | Out-Null
    $rootfs = Join-Path $home_folder 'rootfs.tar.gz'
    curl.exe -sS -L --fail -o $rootfs $image
    wsl.exe --import $Name (Join-Path $home_folder 'vm') $rootfs --version 2
    Remove-Item $rootfs
}
# The lab only reads capture files, so the live-capture service the package enables is switched off.
$install = 'export DEBIAN_FRONTEND=noninteractive; apt-get update -qq; apt-get install -y -qq suricata suricata-update python3 python3-yaml > /tmp/apt.log 2>&1; systemctl disable --now suricata 2>/dev/null; mkdir -p /opt/ebr/bin; suricata -V'
wsl.exe -d $Name -u root --exec /bin/bash -c $install
$setup = (Get-Content (Join-Path $PSScriptRoot 'setup_lab.sh') -Raw) -replace "`r`n", "`n"
# The explicit exit stops bash before the carriage return PowerShell adds to piped text.
"$setup`nexit 0`n" | wsl.exe -d $Name -u root --exec /bin/bash -s
Write-Output "Lab $Name is ready."
