#!/bin/sh
docker run -it --rm -e GOOS=$GOOS -e GOARCH=$GOARCH -v $(pwd):/pwd -w /pwd golang:1.4-cross ./go_build.sh
