#!/bin/bash

# Windows
GOOS=windows GOARCH=amd64 go build -o build/x-ray_cve_check_windows_amd64.exe x-ray_cve_check.go
GOOS=windows GOARCH=386   go build -o build/x-ray_cve_check_windows_386.exe x-ray_cve_check.go
GOOS=windows GOARCH=arm64 go build -o build/x-ray_cve_check_windows_arm64.exe x-ray_cve_check.go

# Linux
GOOS=linux GOARCH=amd64 go build -o build/x-ray_cve_check_linux_amd64 x-ray_cve_check.go
GOOS=linux GOARCH=arm64 go build -o build/x-ray_cve_check_linux_arm64 x-ray_cve_check.go

# macOS
GOOS=darwin GOARCH=amd64 go build -o build/x-ray_cve_check_macos_amd64 x-ray_cve_check.go
GOOS=darwin GOARCH=arm64 go build -o build/x-ray_cve_check_macos_arm64 x-ray_cve_check.go

echo "✅ All builds complete in ./build/"
