$OUT_DIR = "..\Server\web\downloads"
$SRC = ".\main.go"

# Ensure directories exist
if (!(Test-Path "$OUT_DIR\windows")) { New-Item -ItemType Directory -Force -Path "$OUT_DIR\windows" }
if (!(Test-Path "$OUT_DIR\linux")) { New-Item -ItemType Directory -Force -Path "$OUT_DIR\linux" }

Write-Host "--- Building Windows Agent ---" -ForegroundColor Cyan
$env:GOOS="windows"
$env:GOARCH="amd64"
go build -ldflags="-s -w" -o "$OUT_DIR\windows\agent-windows.exe" $SRC

Write-Host "--- Building Linux Agent ---" -ForegroundColor Cyan
$env:GOOS="linux"
$env:GOARCH="amd64"
go build -ldflags="-s -w" -o "$OUT_DIR\linux\agent-linux" $SRC

# Reset environment variables for your current session
$env:GOOS=""
$env:GOARCH=""

Write-Host "Done! Binaries are in $OUT_DIR" -ForegroundColor Green