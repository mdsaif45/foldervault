# Generates assets/app.ico (padlock) and assets/locked-folder.ico
# (Win11-style folder + padlock overlay) as multi-size PNG-compressed ICOs.
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing

# resolve assets/ relative to this script so it works from any checkout
$assets = Join-Path (Split-Path $PSScriptRoot -Parent) 'assets'
$sizes = 16, 20, 24, 32, 48, 64, 256

function New-RoundRectPath([float]$x, [float]$y, [float]$w, [float]$h, [float]$r) {
    $p = New-Object System.Drawing.Drawing2D.GraphicsPath
    $d = 2 * $r
    $p.AddArc($x, $y, $d, $d, 180, 90)
    $p.AddArc($x + $w - $d, $y, $d, $d, 270, 90)
    $p.AddArc($x + $w - $d, $y + $h - $d, $d, $d, 0, 90)
    $p.AddArc($x, $y + $h - $d, $d, $d, 90, 90)
    $p.CloseFigure()
    return $p
}

function Draw-Padlock([System.Drawing.Graphics]$g, [float]$cx, [float]$cy, [float]$scale, `
        [System.Drawing.Color]$body, [System.Drawing.Color]$shackle, [System.Drawing.Color]$hole) {
    # geometry in a 100x110 local box centered horizontally on cx, body top at cy
    $bw = 100 * $scale; $bh = 72 * $scale; $br = 14 * $scale
    $bx = $cx - $bw / 2; $by = $cy
    $pw = 16 * $scale                       # shackle stroke width
    $srx = 30 * $scale                      # shackle radius x
    $sTop = $cy - 38 * $scale
    $pen = New-Object System.Drawing.Pen($shackle, $pw)
    $pen.StartCap = 'Flat'; $pen.EndCap = 'Flat'
    $g.DrawArc($pen, $cx - $srx, $sTop, $srx * 2, $srx * 2 + 10 * $scale, 180, 180)
    $g.DrawLine($pen, $cx - $srx, $sTop + $srx, $cx - $srx, $cy + 2 * $scale)
    $g.DrawLine($pen, $cx + $srx, $sTop + $srx, $cx + $srx, $cy + 2 * $scale)
    $pen.Dispose()
    $bp = New-RoundRectPath $bx $by $bw $bh $br
    $bBrush = New-Object System.Drawing.SolidBrush($body)
    $g.FillPath($bBrush, $bp); $bBrush.Dispose(); $bp.Dispose()
    $khR = 11 * $scale
    $khBrush = New-Object System.Drawing.SolidBrush($hole)
    $g.FillEllipse($khBrush, $cx - $khR, $by + 20 * $scale, $khR * 2, $khR * 2)
    $g.FillRectangle($khBrush, $cx - 4.5 * $scale, $by + 32 * $scale, 9 * $scale, 22 * $scale)
    $khBrush.Dispose()
}

function Render([int]$size, [scriptblock]$draw256) {
    $bmp = New-Object System.Drawing.Bitmap($size, $size, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'
    $g.PixelOffsetMode = 'HighQuality'
    $s = $size / 256.0
    $g.ScaleTransform($s, $s)
    & $draw256 $g
    $g.Dispose()
    $ms = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    return , $ms.ToArray()
}

function Write-Ico([string]$path, [scriptblock]$draw256) {
    $images = @()
    foreach ($sz in $sizes) {
        [byte[]]$png = Render $sz $draw256
        $images += , @($sz, $png)
    }
    $fs = [System.IO.File]::Create($path)
    $bw = New-Object System.IO.BinaryWriter($fs)
    $bw.Write([uint16]0); $bw.Write([uint16]1); $bw.Write([uint16]$images.Count)
    $offset = 6 + 16 * $images.Count
    foreach ($img in $images) {
        $sz = $img[0]; $data = $img[1]
        $bw.Write([byte]($(if ($sz -ge 256) { 0 } else { $sz })))
        $bw.Write([byte]($(if ($sz -ge 256) { 0 } else { $sz })))
        $bw.Write([byte]0); $bw.Write([byte]0)
        $bw.Write([uint16]1); $bw.Write([uint16]32)
        $bw.Write([uint32]$data.Length); $bw.Write([uint32]$offset)
        $offset += $data.Length
    }
    foreach ($img in $images) { $bw.Write($img[1]) }
    $bw.Dispose(); $fs.Dispose()
    Write-Host "wrote $path ($([math]::Round((Get-Item $path).Length/1KB,1)) KB)"
}

$folderFace  = [System.Drawing.Color]::FromArgb(255, 0xFF, 0xC9, 0x4D)
$folderTab   = [System.Drawing.Color]::FromArgb(255, 0xE8, 0xA9, 0x33)
$folderShade = [System.Drawing.Color]::FromArgb(255, 0xF5, 0xB8, 0x3D)
$lockBody    = [System.Drawing.Color]::FromArgb(255, 0x2F, 0x2F, 0x3A)
$lockShackle = [System.Drawing.Color]::FromArgb(255, 0x55, 0x55, 0x63)
$gold        = [System.Drawing.Color]::FromArgb(255, 0xE1, 0xB9, 0x4A)
$goldDark    = [System.Drawing.Color]::FromArgb(255, 0x8A, 0x6A, 0x1C)

# ---- locked-folder.ico: folder with padlock, bottom-right ----
Write-Ico "$assets\locked-folder.ico" {
    param($g)
    $tab = New-RoundRectPath 20 52 96 40 12
    $b = New-Object System.Drawing.SolidBrush($folderTab); $g.FillPath($b, $tab); $b.Dispose(); $tab.Dispose()
    $back = New-RoundRectPath 20 68 216 136 16
    $b = New-Object System.Drawing.SolidBrush($folderShade); $g.FillPath($b, $back); $b.Dispose(); $back.Dispose()
    $front = New-RoundRectPath 20 88 216 116 16
    $b = New-Object System.Drawing.SolidBrush($folderFace); $g.FillPath($b, $front); $b.Dispose(); $front.Dispose()
    Draw-Padlock $g 178 148 0.62 $lockBody $lockBody $gold
}

# ---- app.ico: standalone gold padlock ----
Write-Ico "$assets\app.ico" {
    param($g)
    Draw-Padlock $g 128 118 1.55 $gold $goldDark $lockBody
}
