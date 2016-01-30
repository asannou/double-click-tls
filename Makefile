GO := docker run -i --rm -v `pwd`:/go/src/double-click-tls -w /go/src/double-click-tls golang:1.4-cross

build: double-click-tls.go
	$(GO) sh -c "go get && go get github.com/mitchellh/gox && gox -os='linux darwin windows' -arch='amd64 386' -output='bin/{{.Dir}}_{{.OS}}_{{.Arch}}'"
