# FolderVault — one-time toolchain setup
# Rust (rustup) is already installed. This adds the MSVC C++ toolset that
# `x86_64-pc-windows-msvc` needs for linking (link.exe + Windows SDK).
#
# Run from an elevated PowerShell (right-click → Run as administrator):
#   powershell -ExecutionPolicy Bypass -File .\setup-toolchain.ps1

$ErrorActionPreference = 'Stop'

$vsInstaller = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\setup.exe'
$vsPath      = 'C:\Program Files\Microsoft Visual Studio\18\Enterprise'

if ((Test-Path $vsInstaller) -and (Test-Path $vsPath)) {
    # Preferred: add the C++ components to the existing VS 18 Enterprise.
    Write-Host "Adding MSVC toolset + Windows SDK to VS 18 Enterprise..." -ForegroundColor Cyan
    & $vsInstaller modify `
        --installPath $vsPath `
        --add Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
        --add Microsoft.VisualStudio.Component.Windows11SDK.26100 `
        --passive --norestart
}
else {
    # Fallback: standalone Build Tools (~2 GB, no full IDE).
    Write-Host "VS not found — installing standalone Build Tools via winget..." -ForegroundColor Cyan
    winget install Microsoft.VisualStudio.2022.BuildTools --override `
        "--wait --passive --add Microsoft.VisualStudio.Component.VC.Tools.x86.x64 --add Microsoft.VisualStudio.Component.Windows11SDK.26100"
}

Write-Host ""
Write-Host "When the installer finishes, open a NEW terminal and verify with:" -ForegroundColor Green
Write-Host "  cargo build --release   (from the foldervault directory)"
