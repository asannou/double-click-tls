#!/bin/sh
PACKAGE=github.com/asannou/double-click-tls
docker run -i --rm -v $(pwd)/bin:/go/bin golang:1.4-cross /bin/sh << EOD
set -ex
go get $PACKAGE
GOOS=darwin GOARCH=amd64 go get $PACKAGE
GOOS=windows GOARCH=amd64 go get $PACKAGE
GOOS=windows GOARCH=386 go get $PACKAGE
EOD
