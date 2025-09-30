#!/bin/sh -e
export GOOS=linux
export GOARCH=amd64
export CGO_ENABLED=0            # set 0 to avoid cgo and produce static bin when possible
VERSION="0.2.0"
go build -trimpath -o hokuto \
  -ldflags="-s -w -X main.version=${VERSION}" \
  ./...
