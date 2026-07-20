# Generates the MSIX package logo PNGs (installer/msix/Assets/) from app.ico.
# These are only the package tile/store images; the real icons are the .ico
# resources embedded in the exe.
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing

$root   = Split-Path $PSScriptRoot -Parent
$icoPath = Join-Path $root 'assets\app.ico'
$out    = Join-Path $PSScriptRoot 'msix\Assets'
New-Item -ItemType Directory $out -Force | Out-Null

$sizes = @{
    'Square44x44Logo.png'   = 44
    'Square150x150Logo.png' = 150
    'StoreLogo.png'         = 50
}
foreach ($name in $sizes.Keys) {
    $sz = $sizes[$name]
    $ico = New-Object System.Drawing.Icon($icoPath, ([Math]::Min($sz,256)), ([Math]::Min($sz,256)))
    $src = $ico.ToBitmap()
    $bmp = New-Object System.Drawing.Bitmap($sz, $sz, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.InterpolationMode = 'HighQualityBicubic'
    $g.DrawImage($src, (New-Object System.Drawing.Rectangle 0,0,$sz,$sz))
    $g.Dispose()
    $bmp.Save((Join-Path $out $name), [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose(); $src.Dispose(); $ico.Dispose()
    Write-Host "wrote $name (${sz}x${sz})"
}
