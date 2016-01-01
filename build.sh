#!/bin/sh
docker run -it --rm -v $(pwd):/pwd -w /pwd golang:1.4-cross ./go_build.sh
