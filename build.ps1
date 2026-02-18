$ErrorActionPreference = "Stop"

Write-Host "=== StealthLink Build ===" -ForegroundColor Cyan

$buildDir = "build"
if (Test-Path $buildDir) {
    Remove-Item -Path $buildDir -Recurse -Force
}
New-Item -ItemType Directory -Path $buildDir | Out-Null

Push-Location "protocol"

Write-Host "[1/5] Server (Linux/AMD64)..." -ForegroundColor Green
$env:GOOS = "linux"
$env:GOARCH = "amd64"
$env:CGO_ENABLED = "0"
go build -ldflags="-s -w" -trimpath -o "..\$buildDir\server-linux-amd64" ./cmd/server
if ($LASTEXITCODE -ne 0) { Write-Error "Build failed"; exit 1 }

Write-Host "[2/5] Server (Windows/AMD64)..." -ForegroundColor Green
$env:GOOS = "windows"
$env:GOARCH = "amd64"
go build -ldflags="-s -w" -trimpath -o "..\$buildDir\server-windows-amd64.exe" ./cmd/server
if ($LASTEXITCODE -ne 0) { Write-Error "Build failed"; exit 1 }

Write-Host "[3/5] Client (Windows/AMD64)..." -ForegroundColor Green
$env:GOOS = "windows"
$env:GOARCH = "amd64"
go build -ldflags="-s -w" -trimpath -o "..\$buildDir\client-windows-amd64.exe" ./cmd/client
if ($LASTEXITCODE -ne 0) { Write-Error "Build failed"; exit 1 }

Write-Host "[4/5] Client (Linux/AMD64)..." -ForegroundColor Green
$env:GOOS = "linux"
$env:GOARCH = "amd64"
go build -ldflags="-s -w" -trimpath -o "..\$buildDir\client-linux-amd64" ./cmd/client
if ($LASTEXITCODE -ne 0) { Write-Error "Build failed"; exit 1 }

Write-Host "[5/5] Client (Android/ARM64)..." -ForegroundColor Green
$env:GOOS = "android"
$env:GOARCH = "arm64"
go build -ldflags="-s -w" -trimpath -o "..\$buildDir\client-android-arm64" ./cmd/client
if ($LASTEXITCODE -ne 0) { Write-Error "Build failed"; exit 1 }

Pop-Location

Write-Host ""
Write-Host "=== Build Complete ===" -ForegroundColor Cyan
Write-Host "Artifacts in '$buildDir':" -ForegroundColor Yellow
Get-ChildItem $buildDir | ForEach-Object {
    $size = [math]::Round($_.Length / 1MB, 1)
    Write-Host "  $($_.Name) ($size MB)"
}
Write-Host ""
Write-Host "Usage:" -ForegroundColor Yellow
Write-Host "  Server: ./server-linux-amd64 -config config.json"
Write-Host "  Client: ./client-windows-amd64 -server host:443 -psk YOUR_KEY -sni host"
Write-Host "  Client: ./client-windows-amd64 -sub 'stealthlink://...'"
