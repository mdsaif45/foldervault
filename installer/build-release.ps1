# FolderVault release builder.
# Produces four artifacts under dist/, all delivering the same behavior after
# first run (they self-register the Explorer menu + .fvlt association):
#
#   1. FolderVault-<ver>-installer.exe   Inno Setup installer (per-user, no admin)
#   2. FolderVault-<ver>-portable.zip     exe + dll + README, run-from-anywhere
#   3. FolderVault-<ver>-selfcontained.zip portable + MSIX for the Win11 menu
#   4. fvlt-<ver>-cli.zip                 the CLI tool alone
#
# Optional signing: pass -Sign to sign the exe/dll/msix with a cert. Without a
# real cert it generates a throwaway dev cert (installs to CurrentUser\My) so
# the MSIX is installable locally; production should pass -CertPath/-CertPass.
#
# Usage:
#   pwsh installer\build-release.ps1                 # unsigned
#   pwsh installer\build-release.ps1 -Sign           # dev-cert signed
#   pwsh installer\build-release.ps1 -Sign -CertPath cert.pfx -CertPass ****

param(
    [switch]$Sign,
    [string]$CertPath,
    [string]$CertPass
)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$cargo = Join-Path $env:USERPROFILE '.cargo\bin\cargo.exe'

# ---------- MSIX helper (defined before use) ----------
function New-Msix {
    param($Ver, $PayloadDir, $Stage)
    $makeappx = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin\*\x64\makeappx.exe' -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | Select-Object -First 1
    if (-not $makeappx) { Write-Warning "makeappx.exe not found -> MSIX skipped"; return $null }
    $msixStage = Join-Path $Stage 'msix'
    Copy-Item (Join-Path $root 'installer\msix') $msixStage -Recurse
    # manifest validation requires the declared Executable/DLL to exist in the
    # pack dir. Copy the real files in so the package validates; at runtime the
    # sparse package's ExternalLocation content is what actually runs.
    Copy-Item (Join-Path $PayloadDir 'FolderVault.exe') $msixStage
    Copy-Item (Join-Path $PayloadDir 'vault_shellext.dll') $msixStage
    # only the <Identity ... Version="..."> attr, not MinVersion/MaxVersionTested
    $manifestPath = Join-Path $msixStage 'AppxManifest.xml'
    $xml = Get-Content $manifestPath -Raw
    $xml = [regex]::Replace($xml, '(?s)(<Identity\b.*?Version=")[0-9.]+(")', "`${1}$Ver.0`${2}")
    Set-Content $manifestPath $xml -NoNewline
    $out = Join-Path $Stage "FolderVault-$Ver.msix"
    $log = & $makeappx.FullName pack /o /d $msixStage /p $out 2>&1
    if (Test-Path $out) {
        return $out
    } else {
        Write-Warning "makeappx failed:"
        $log | Select-String 'error' | ForEach-Object { Write-Warning "  $_" }
        return $null
    }
}

# version from workspace Cargo.toml
$ver = (Select-String -Path (Join-Path $root 'Cargo.toml') -Pattern '^version\s*=\s*"([^"]+)"').Matches[0].Groups[1].Value
Write-Host "== FolderVault $ver release ==" -ForegroundColor Cyan

$dist = Join-Path $root 'dist'
$stage = Join-Path $dist '_stage'
Remove-Item -Recurse -Force $dist -ErrorAction SilentlyContinue
New-Item -ItemType Directory $dist, $stage | Out-Null

# ---- 1. build everything (size-tuned release profile) ----
Write-Host "building release binaries..." -ForegroundColor Yellow
& $cargo build --release 2>&1 | Select-Object -Last 1
$rel = Join-Path $root 'target\release'
$exe = Join-Path $rel 'FolderVault.exe'
$dll = Join-Path $rel 'vault_shellext.dll'
$cli = Join-Path $rel 'fvlt.exe'
foreach ($f in $exe, $dll, $cli) {
    if (-not (Test-Path $f)) { throw "missing build output: $f" }
}
"  FolderVault.exe    $([math]::Round((Get-Item $exe).Length/1KB)) KB"
"  vault_shellext.dll $([math]::Round((Get-Item $dll).Length/1KB)) KB"
"  fvlt.exe           $([math]::Round((Get-Item $cli).Length/1KB)) KB"

function New-Zip($srcDir, $zipName) {
    $zip = Join-Path $dist $zipName
    Compress-Archive -Path (Join-Path $srcDir '*') -DestinationPath $zip -Force
    Write-Host "  -> $zipName ($([math]::Round((Get-Item $zip).Length/1KB)) KB)" -ForegroundColor Green
}

# ---- optional signing ----
$signTool = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe' -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | Select-Object -First 1
$cert = $null
if ($Sign) {
    if ($CertPath) {
        $cert = @{ Pfx = $CertPath; Pass = $CertPass }
    } else {
        Write-Host "no -CertPath: generating a throwaway dev cert" -ForegroundColor Yellow
        $c = New-SelfSignedCertificate -Type Custom -Subject 'CN=FolderVault Dev' `
            -KeyUsage DigitalSignature -CertStoreLocation 'Cert:\CurrentUser\My' `
            -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3', '2.5.29.19={text}')
        $pfx = Join-Path $stage 'devcert.pfx'
        $pw = ConvertTo-SecureString -String 'devpass' -Force -AsPlainText
        Export-PfxCertificate -Cert $c -FilePath $pfx -Password $pw | Out-Null
        $cert = @{ Pfx = $pfx; Pass = 'devpass' }
        Write-Host "  dev cert thumbprint $($c.Thumbprint) (install to Trusted People to use the MSIX)" -ForegroundColor DarkGray
    }
    if (-not $signTool) { Write-Warning "signtool.exe not found; skipping signing" }
}
function Sign-File($path) {
    if ($Sign -and $signTool -and $cert) {
        & $signTool.FullName sign /fd SHA256 /f $cert.Pfx /p $cert.Pass /t http://timestamp.digicert.com $path 2>&1 | Out-Null
        Write-Host "  signed $(Split-Path $path -Leaf)" -ForegroundColor DarkGray
    }
}
Sign-File $exe; Sign-File $dll; Sign-File $cli

$readme = Join-Path $root 'installer\PACKAGE-README.txt'

# ---- 2. portable.zip: exe + dll + readme ----
Write-Host "packaging portable..." -ForegroundColor Yellow
$p = Join-Path $stage 'portable'; New-Item -ItemType Directory $p | Out-Null
Copy-Item $exe, $dll, $readme $p
New-Zip $p "FolderVault-$ver-portable.zip"

# ---- 3. cli.zip ----
Write-Host "packaging cli-tool..." -ForegroundColor Yellow
$cdir = Join-Path $stage 'cli'; New-Item -ItemType Directory $cdir | Out-Null
Copy-Item $cli $cdir
Copy-Item (Join-Path $root 'docs\SPEC.md') (Join-Path $cdir 'FORMAT.md')
New-Zip $cdir "fvlt-$ver-cli.zip"

# ---- 4. self-contained.zip: portable + MSIX (Win11 top-level menu) ----
Write-Host "packaging self-contained (with MSIX)..." -ForegroundColor Yellow
$sc = Join-Path $stage 'selfcontained'; New-Item -ItemType Directory $sc | Out-Null
Copy-Item $exe, $dll, $readme $sc
$msix = New-Msix -Ver $ver -PayloadDir $sc -Stage $stage
if ($msix) {
    Copy-Item $msix $sc
    Sign-File (Join-Path $sc (Split-Path $msix -Leaf))
}
New-Zip $sc "FolderVault-$ver-selfcontained.zip"

# ---- 5. installer.exe (Inno Setup) ----
$iscc = (Get-Command iscc.exe -ErrorAction SilentlyContinue).Source
if (-not $iscc) {
    $iscc = @(
        "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe",
        'C:\Program Files (x86)\Inno Setup 6\ISCC.exe',
        'C:\Program Files\Inno Setup 6\ISCC.exe'
    ) | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if ($iscc) {
    Write-Host "building installer.exe (Inno Setup)..." -ForegroundColor Yellow
    & $iscc "/DAppVersion=$ver" "/DRel=$rel" "/DRoot=$root" (Join-Path $root 'installer\foldervault.iss') 2>&1 | Select-Object -Last 2
    $built = Join-Path $dist "FolderVault-$ver-installer.exe"
    if (Test-Path $built) { Sign-File $built; Write-Host "  -> FolderVault-$ver-installer.exe" -ForegroundColor Green }
} else {
    Write-Warning "Inno Setup (iscc.exe) not on PATH -> skipping installer.exe."
    Write-Warning "Install with: winget install JRSoftware.InnoSetup, then re-run."
}

Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue
Write-Host "`nartifacts in $dist :" -ForegroundColor Cyan
Get-ChildItem $dist | Format-Table Name, @{n='KB';e={[math]::Round($_.Length/1KB)}} -AutoSize
