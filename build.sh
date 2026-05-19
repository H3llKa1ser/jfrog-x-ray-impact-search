#!/bin/bash

# Linux
go build -o x-ray_cve_check x-ray_cve_check.go

# Windows
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o x-ray_cve_check.exe x-ray_cve_check.go

# macOS
GOOS=darwin GOARCH=arm64 go build -o x-ray_cve_check x-ray_cve_check.go
