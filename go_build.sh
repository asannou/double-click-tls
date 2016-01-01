#!/bin/sh
set -ex
go get github.com/ericchiang/letsencrypt
go build -o double-click-tls
GOOS=darwin GOARCH=amd64 go build -o double-click-tls-darwin-amd64
GOOS=windows GOARCH=amd64 go build -o double-click-tls-amd64.exe
GOOS=windows GOARCH=386 go build -o double-click-tls-386.exe
