# Double Click TLS

## Build

### Linux

```
$ docker run -it --rm -v $(pwd)/bin:/go/bin golang:1.4-cross go get github.com/asannou/double-click-tls
$ ls bin/
double-click-tls
```

### OS X

```
$ docker run -it --rm -v $(pwd)/bin:/go/bin golang:1.4-cross sh -c "GOOS=darwin GOARCH=amd64 go get github.com/asannou/double-click-tls"
$ ls bin/darwin_amd64/
double-click-tls
```

### Windows

```
$ docker run -it --rm -v $(pwd)/bin:/go/bin golang:1.4-cross sh -c "GOOS=windows GOARCH=amd64 go get github.com/asannou/double-click-tls"
$ ls bin/windows_amd64/
double-click-tls.exe
```
