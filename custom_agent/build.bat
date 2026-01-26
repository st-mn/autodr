@echo off
REM Wazuh Custom Agent Build Script for Windows

set VERSION=1.0.0
set APP_NAME=wazuh-agent
set BUILD_DIR=build

echo Building Wazuh Custom Agent v%VERSION%

REM Create build directory
if not exist %BUILD_DIR% mkdir %BUILD_DIR%

REM Build for Windows (amd64)
echo Building for Windows (amd64)...
set GOOS=windows
set GOARCH=amd64
go build -ldflags="-w -s" -o %BUILD_DIR%\%APP_NAME%-windows-amd64.exe main.go

REM Build for Linux (amd64)
echo Building for Linux (amd64)...
set GOOS=linux
set GOARCH=amd64
go build -ldflags="-w -s" -o %BUILD_DIR%\%APP_NAME%-linux-amd64 main.go

REM Build for Linux (arm64)
echo Building for Linux (arm64)...
set GOOS=linux
set GOARCH=arm64
go build -ldflags="-w -s" -o %BUILD_DIR%\%APP_NAME%-linux-arm64 main.go

echo.
echo Build complete! Binaries are in the %BUILD_DIR% directory
dir %BUILD_DIR%

echo.
echo To run the agent:
echo   Windows: .\%BUILD_DIR%\%APP_NAME%-windows-amd64.exe config.json
echo   Linux: ./%BUILD_DIR%/%APP_NAME%-linux-amd64 config.json
