#!/bin/sh
set -ex
go get github.com/ericchiang/letsencrypt
go build -o double-click-tls
GOOS=darwin GOARCH=amd64 go build -o double-click-tls.app
GOOS=windows GOARCH=amd64 go build -o double-click-tls.exe
